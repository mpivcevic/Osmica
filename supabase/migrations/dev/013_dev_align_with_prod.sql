-- dev/013 — Bring osmica-dev's schema into line with production.
--
-- Named 013 rather than 012 as earlier notes had it: 012 is the token-keyed
-- set_waiter_pin, applied 17 Aug.
--
-- WHY THIS MATTERS. Dev exists to catch bugs before production sees them. Every
-- property where dev differs is a bug it cannot catch — or worse, one it invents.
-- The sharp example is `status`: the app writes 'cover_rejected' at
-- osmica.html:2515 when a waiter declines to cover a shift. Production accepts
-- it. Dev's CHECK constraint lists only four values and would reject it on a
-- constraint violation — a failure that exists *only* in the test environment,
-- which is the most expensive kind of bug there is.
--
-- WHAT IS DELIBERATELY NOT ALIGNED, and stays that way:
--
--   * Migration 003 (revoking anonymous INSERT/UPDATE/DELETE) is NOT applied.
--     Dev keeps anonymous writes so single-phone testing is unimpeded. This is
--     the one intentional difference, and it is the one that cannot mislead you:
--     dev being more permissive never hides a production failure.
--   * The dev_open_* RLS policies stay. They are named to be unmistakable and
--     Stage D replaces them wholesale.
--
-- ORDER IS LOAD-BEARING. waiters.invite_token changes uuid -> text, and
-- claim_invite / mark_invite_joined take a uuid parameter and compare directly
-- against that column. Change the column first and both functions break on a
-- type mismatch, so they are dropped up front and recreated afterwards with
-- production's text signatures.

BEGIN;

-- ── 1. Drop the functions that depend on invite_token's type ────────────────
-- Their parameter type changes, so CREATE OR REPLACE cannot be used. Dropping
-- also drops their grants, which are re-issued at the end.

DROP FUNCTION IF EXISTS public.claim_invite(uuid);
DROP FUNCTION IF EXISTS public.mark_invite_joined(uuid);

-- Production dropped this in migration 008: it took a waiter id and
-- authenticated nothing. Dev has been carrying it ever since.
DROP FUNCTION IF EXISTS public.set_waiter_pin(uuid, text);


-- ── 2. Column alignment ─────────────────────────────────────────────────────

-- invite_token: uuid -> text, matching production's type and default. The
-- default must be dropped before the type change, because a uuid default cannot
-- survive a cast to text.
ALTER TABLE public.waiters ALTER COLUMN invite_token DROP DEFAULT;
ALTER TABLE public.waiters
  ALTER COLUMN invite_token TYPE text USING invite_token::text;
ALTER TABLE public.waiters
  ALTER COLUMN invite_token SET DEFAULT gen_random_uuid()::text;

-- Production has UNIQUE on invite_token; dev never did. Without it, two waiters
-- could share a token and claim_invite's LIMIT 1 would silently pick one.
ALTER TABLE public.waiters DROP CONSTRAINT IF EXISTS waiters_invite_token_key;
ALTER TABLE public.waiters ADD  CONSTRAINT waiters_invite_token_key UNIQUE (invite_token);

-- Production leaves these nullable. Dev's NOT NULL would reject a write that
-- production accepts.
ALTER TABLE public.waiters ALTER COLUMN pattern   DROP NOT NULL;
ALTER TABLE public.waiters ALTER COLUMN vacations DROP NOT NULL;

-- approved_by: uuid -> text, matching production.
ALTER TABLE public.shift_requests
  ALTER COLUMN approved_by TYPE text USING approved_by::text;

-- THE IMPORTANT ONE. Add 'cover_rejected' — the fifth status the app actually
-- writes. The constraint is auto-named by the inline CHECK in 010_dev_schema.
ALTER TABLE public.shift_requests DROP CONSTRAINT IF EXISTS shift_requests_status_check;
ALTER TABLE public.shift_requests ADD  CONSTRAINT shift_requests_status_check
  CHECK (status IN ('open','pending_approval','approved','rejected','cover_rejected'));

-- Production's date_schedules carries created_at (verified by probing a live
-- row on 17 Aug). Dev's does not.
ALTER TABLE public.date_schedules
  ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();


-- ── 3. set_updated_at trigger ───────────────────────────────────────────────
-- Production has this; dev does not, so dev's shift_requests.updated_at never
-- moves off NULL.
--
-- Copied verbatim from production via pg_get_functiondef on 17 Aug, not
-- reconstructed.
--
-- Deliberately carries NO `SET search_path`, matching production. That looks
-- inconsistent with every other function in this project, and is correct here: a
-- plain trigger function runs as the invoking user, not as its owner, so a
-- hostile search_path lets an attacker hijack only themselves. The pin earns its
-- place on SECURITY DEFINER functions and nowhere else.

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS set_updated_at ON public.shift_requests;
CREATE TRIGGER set_updated_at
  BEFORE UPDATE ON public.shift_requests
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


-- ── 4. Invite functions, recreated with production's text signatures ────────

CREATE FUNCTION public.claim_invite(p_token text)
RETURNS TABLE (id uuid, cafe_id uuid, name text, color text,
               joined_at timestamptz, cafe_name text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
  SELECT w.id, w.cafe_id, w.name, w.color, w.joined_at, c.name AS cafe_name
  FROM public.waiters w
  JOIN public.cafes   c ON c.id = w.cafe_id
  WHERE w.invite_token = p_token
  LIMIT 1;
$$;

CREATE FUNCTION public.mark_invite_joined(p_token text)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
  UPDATE public.waiters
  SET joined_at = now()
  WHERE invite_token = p_token
    AND joined_at IS NULL;
$$;

-- Now identical to production's 007 — the ::text cast that dev/012 needed is
-- gone, because the column is text. This is the last piece of dev-only SQL.
CREATE OR REPLACE FUNCTION public.set_waiter_pin_by_token(p_token text, p_pin text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_waiter_id uuid;
  v_cafe_id   uuid;
  v_taken     int;
BEGIN
  IF p_pin IS NULL OR p_pin !~ '^[0-9]{4}$' THEN
    RETURN 'invalid_pin';
  END IF;

  SELECT w.id, w.cafe_id INTO v_waiter_id, v_cafe_id
  FROM public.waiters w
  WHERE w.invite_token = p_token
    AND w.joined_at IS NULL
  LIMIT 1;

  IF v_waiter_id IS NULL THEN
    RETURN 'invalid_token';
  END IF;

  SELECT COUNT(*) INTO v_taken
  FROM public.waiters
  WHERE cafe_id = v_cafe_id
    AND id <> v_waiter_id
    AND pin_hash IS NOT NULL
    AND crypt(p_pin, pin_hash) = pin_hash;

  IF v_taken > 0 THEN
    RETURN 'taken';
  END IF;

  UPDATE public.waiters
  SET pin_hash  = crypt(p_pin, gen_salt('bf')),
      joined_at = now()
  WHERE id = v_waiter_id;

  RETURN 'ok';
END;
$$;


-- ── 5. Column grants — production's 005 + 006 shape ─────────────────────────
-- So the *readable API shape* matches production and a query that 401s in
-- production also 401s here. Writes are untouched: dev keeps anonymous
-- INSERT/UPDATE/DELETE.
--
-- Safe against the client as written: no call site does select('*') on waiters.
-- All six use WAITER_COLS or WAITER_COLS_ADMIN (osmica.html:1332, 2082, 3512),
-- and the id-filtered update and delete need only `id`, which is granted.

REVOKE SELECT ON public.waiters FROM anon, PUBLIC;

GRANT SELECT (
  id,
  cafe_id,
  name,
  color,
  pattern,
  vacations,
  joined_at,
  created_at
) ON public.waiters TO anon;

GRANT SELECT ON public.waiters TO authenticated;


-- ── 6. Re-issue execute grants ──────────────────────────────────────────────

GRANT EXECUTE ON FUNCTION public.claim_invite(text)                    TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mark_invite_joined(text)              TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.set_waiter_pin_by_token(text, text)   TO anon, authenticated;

COMMIT;


-- ── VERIFY ──────────────────────────────────────────────────────────────────
--
-- 1. The one that motivated this file — must now succeed where it used to
--    violate a constraint:
--
--      begin;
--      update public.shift_requests set status = 'cover_rejected'
--      where id = (select id from public.shift_requests limit 1);
--      rollback;
--
-- 2. Types match production:
--
--      select column_name, data_type, is_nullable
--      from information_schema.columns
--      where table_name in ('waiters','shift_requests','date_schedules')
--        and column_name in ('invite_token','approved_by','pattern','vacations','created_at')
--      order by table_name, column_name;
--
--    expect: invite_token text, approved_by text, pattern/vacations YES nullable,
--            date_schedules.created_at present.
--
-- 3. The invite path still works end to end. Reset Eva and walk the UI:
--
--      update public.waiters
--      set joined_at = null, pin_hash = null, invite_token = gen_random_uuid()::text
--      where name like 'Eva%';
--
--      select 'https://<tunnel>/osmica.html?invite=' || invite_token
--      from public.waiters where name like 'Eva%';
--
-- 4. With the publishable key and NO session, dev now answers like production:
--
--      ?select=name,color    -> 200
--      ?select=phone         -> 401
--      ?select=invite_token  -> 401
--      ?select=*             -> 401
--
--    Note this makes invite tokens unreadable over REST on dev too. Fetch them
--    from the SQL editor, as above.
--
-- 5. set_waiter_pin is gone (it was dropped from production in 008):
--
--      POST /rest/v1/rpc/set_waiter_pin -> 404
