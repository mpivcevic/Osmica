-- 015 — Separate "the owner" from "any signed-in session".
--
-- Every hardening migration so far narrowed `anon` and left `authenticated`
-- alone, because `authenticated` could only be reached with the owner's email
-- and password. Anonymous sign-ins — required by Stage C so waiters get an
-- auth.uid() — remove that assumption: the role is now obtainable by anyone
-- holding the publishable key, which is public by design.
--
-- So the role can no longer stand in for "the owner". Two mechanisms are needed,
-- because they cover different things:
--
--   * ROW access -> RLS policies, which distinguish an owner session from an
--     anonymous one via the is_anonymous JWT claim.
--   * COLUMN access -> grants, because RLS filters rows and cannot hide a
--     column. phone, pin_hash and invite_token therefore leave the role's
--     table-level SELECT entirely.
--
-- ORDER OF OPERATIONS: this must be applied BEFORE anonymous sign-ins are
-- enabled on production, and before v4.37 is treated as live there.
--
-- REQUIRES A CLIENT CHANGE. Revoking phone and invite_token from the role
-- breaks the owner's two WAITER_COLS_ADMIN reads (osmica.html:1332, :2145).
-- owner_list_waiters() below replaces them. Do not apply this to a database
-- serving a client older than v4.38.

BEGIN;

-- ── Helpers ────────────────────────────────────────────────────────────────
--
-- All three are SECURITY DEFINER so that a policy which consults them does not
-- re-enter the RLS being evaluated. A policy on `cafes` that selected from
-- `cafes` directly would recurse; a DEFINER function reads underneath RLS and
-- terminates. This is the standard shape and the reason these exist at all.

-- COALESCE to false: a session with no JWT (role `anon`) has no claim, and the
-- absence of the claim must not read as "anonymous user", which is a different
-- thing entirely.
CREATE OR REPLACE FUNCTION public.is_anon_session()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT COALESCE((auth.jwt() ->> 'is_anonymous')::boolean, false);
$$;

CREATE OR REPLACE FUNCTION public.owns_cafe(p_cafe_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.cafes c
    WHERE c.id = p_cafe_id
      AND c.owner_id = auth.uid()
      AND NOT COALESCE((auth.jwt() ->> 'is_anonymous')::boolean, false)
  );
$$;

-- The waiter behind the current anonymous session, via 014's binding. NULL for
-- an owner, for anon, and for an anonymous session that has not linked yet —
-- all of which correctly fail every policy that uses it.
CREATE OR REPLACE FUNCTION public.current_waiter_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT w.id FROM public.waiters w WHERE w.auth_user_id = auth.uid();
$$;

CREATE OR REPLACE FUNCTION public.current_waiter_cafe()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT w.cafe_id FROM public.waiters w WHERE w.auth_user_id = auth.uid();
$$;

GRANT EXECUTE ON FUNCTION public.is_anon_session()     TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.owns_cafe(uuid)       TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.current_waiter_id()   TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.current_waiter_cafe() TO anon, authenticated;


-- ── Columns: phone, pin_hash and invite_token leave the role ────────────────
--
-- Mirrors what 006 did for anon. The owner gets them back through
-- owner_list_waiters() below, which checks ownership rather than trusting a
-- role name.
REVOKE SELECT ON public.waiters FROM authenticated;
GRANT SELECT (
  id,
  cafe_id,
  name,
  color,
  pattern,
  vacations,
  joined_at,
  created_at,
  auth_user_id
) ON public.waiters TO authenticated;


CREATE OR REPLACE FUNCTION public.owner_list_waiters(p_cafe_id uuid)
RETURNS TABLE (
  id           uuid,
  cafe_id      uuid,
  name         text,
  color        text,
  pattern      jsonb,
  vacations    jsonb,
  joined_at    timestamptz,
  created_at   timestamptz,
  phone        text,
  -- text, not uuid. dev/013 aligned dev to production by changing this column
  -- uuid -> text, and 014 writes gen_random_uuid()::text into it. Declaring uuid
  -- here compiles fine and fails only when the function is first called, with a
  -- structure mismatch.
  invite_token text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
BEGIN
  -- owns_cafe() already excludes anonymous sessions and non-owners. Raising
  -- rather than returning zero rows keeps a caller from reading an empty result
  -- as "this cafe has no staff".
  IF NOT public.owns_cafe(p_cafe_id) THEN
    RAISE EXCEPTION 'not_owner';
  END IF;

  RETURN QUERY
  SELECT w.id, w.cafe_id, w.name, w.color, w.pattern, w.vacations,
         w.joined_at, w.created_at, w.phone, w.invite_token
  FROM public.waiters w
  WHERE w.cafe_id = p_cafe_id
  ORDER BY w.created_at;
END;
$$;

GRANT EXECUTE ON FUNCTION public.owner_list_waiters(uuid) TO authenticated;
REVOKE EXECUTE ON FUNCTION public.owner_list_waiters(uuid) FROM anon, PUBLIC;


-- ── Rows: RLS on all four tables ───────────────────────────────────────────
--
-- Policies are permissive and therefore OR'd. Read them as: anon and waiters
-- may look but not touch, except where a waiter is explicitly allowed to act;
-- the owner may do anything within their own cafe and nothing outside it.
--
-- Cafe isolation for reads is deliberately NOT introduced here. anon can
-- already enumerate cafes today, and changing that is Stage D's job together
-- with the client work it implies. 015 closes the privilege escalation that
-- anonymous sign-ins opened, and no more — a smaller change is a testable one.

ALTER TABLE public.cafes          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.waiters        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.shift_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.date_schedules ENABLE ROW LEVEL SECURITY;

-- Idempotent: this file may be re-applied after a correction.
DROP POLICY IF EXISTS cafes_read            ON public.cafes;
DROP POLICY IF EXISTS cafes_owner_all       ON public.cafes;
DROP POLICY IF EXISTS waiters_read          ON public.waiters;
DROP POLICY IF EXISTS waiters_owner_all     ON public.waiters;
DROP POLICY IF EXISTS sr_read               ON public.shift_requests;
DROP POLICY IF EXISTS sr_owner_all          ON public.shift_requests;
DROP POLICY IF EXISTS sr_waiter_insert      ON public.shift_requests;
DROP POLICY IF EXISTS sr_waiter_update      ON public.shift_requests;
DROP POLICY IF EXISTS ds_read               ON public.date_schedules;
DROP POLICY IF EXISTS ds_owner_all          ON public.date_schedules;

-- cafes
CREATE POLICY cafes_read ON public.cafes
  FOR SELECT TO anon, authenticated USING (true);

CREATE POLICY cafes_owner_all ON public.cafes
  FOR ALL TO authenticated
  USING (owner_id = auth.uid() AND NOT public.is_anon_session())
  WITH CHECK (owner_id = auth.uid() AND NOT public.is_anon_session());

-- waiters. Reads are wide, but the column grants above decide what "wide"
-- exposes: safe columns only, for anon and waiters alike.
CREATE POLICY waiters_read ON public.waiters
  FOR SELECT TO anon, authenticated USING (true);

CREATE POLICY waiters_owner_all ON public.waiters
  FOR ALL TO authenticated
  USING (public.owns_cafe(cafe_id))
  WITH CHECK (public.owns_cafe(cafe_id));

-- shift_requests
CREATE POLICY sr_read ON public.shift_requests
  FOR SELECT TO anon, authenticated USING (true);

CREATE POLICY sr_owner_all ON public.shift_requests
  FOR ALL TO authenticated
  USING (public.owns_cafe(cafe_id))
  WITH CHECK (public.owns_cafe(cafe_id));

-- A waiter may raise a request only for themselves, only in their own cafe.
-- waiter_id is checked against 014's binding rather than against anything the
-- client sends, so it cannot be spoofed by editing the request body.
CREATE POLICY sr_waiter_insert ON public.shift_requests
  FOR INSERT TO authenticated
  WITH CHECK (
    public.is_anon_session()
    AND waiter_id = public.current_waiter_id()
    AND cafe_id   = public.current_waiter_cafe()
  );

-- Covering someone else's shift is by definition a write to another waiter's
-- row, so this cannot be narrowed to "own rows". It is bounded by cafe instead.
-- RLS cannot restrict WHICH columns an UPDATE touches, so a waiter can still
-- write note or status on any request in their cafe. Closing that needs either
-- a SECURITY DEFINER cover_request() RPC or a column-level UPDATE grant, and
-- belongs with the client change that would accompany it — see Stage D.
CREATE POLICY sr_waiter_update ON public.shift_requests
  FOR UPDATE TO authenticated
  USING      (public.is_anon_session() AND cafe_id = public.current_waiter_cafe())
  WITH CHECK (public.is_anon_session() AND cafe_id = public.current_waiter_cafe());

-- date_schedules — the roster. Waiters read it; only the owner writes it.
CREATE POLICY ds_read ON public.date_schedules
  FOR SELECT TO anon, authenticated USING (true);

CREATE POLICY ds_owner_all ON public.date_schedules
  FOR ALL TO authenticated
  USING (public.owns_cafe(cafe_id))
  WITH CHECK (public.owns_cafe(cafe_id));

COMMIT;


-- ── VERIFY ──────────────────────────────────────────────────────────────────
--
-- 1. RLS is on for all four:
--
--      select relname, relrowsecurity from pg_class
--      where relnamespace = 'public'::regnamespace and relkind = 'r'
--      order by relname;
--      -- expect: relrowsecurity = true on cafes, date_schedules,
--      --         shift_requests, waiters
--
-- 2. The sensitive columns are gone from the role:
--
--      select column_name from information_schema.column_privileges
--      where table_name = 'waiters' and grantee = 'authenticated'
--        and privilege_type = 'SELECT' order by column_name;
--      -- expect: no phone, no pin_hash, no invite_token
--
-- 3. Table-level privileges still read DELETE/INSERT/SELECT/UPDATE for
--    authenticated. That is expected and is no longer the whole story — the
--    policies above decide which ROWS those apply to. Do not "fix" it by
--    revoking, or the owner loses the admin panel.
--
-- 4. The owner's replacement read works, and only for its owner:
--
--      select * from public.owner_list_waiters('<your cafe id>');
--      -- as the owner: rows, including phone and invite_token
--      -- as anyone else: ERROR not_owner
--
-- 5. THE REAL TEST needs a browser and belongs with v4.38. On dev, with
--    anonymous sign-ins enabled:
--      a. owner signs in -> admin panel lists staff, phone numbers visible,
--         invite links still generatable
--      b. waiter completes an invite -> lands on the waiter screen
--      c. waiter raises a swap request -> succeeds
--      d. waiter offers to cover another request -> succeeds
--      e. waiter attempts to read another cafe's phone numbers -> nothing
