-- 010 — Schema for the osmica-dev project. RUN THIS AGAINST DEV ONLY.
--
-- Mirrors production's shape, reconstructed from the live column list and from
-- every read/write the client performs. Production's own OpenAPI endpoint is
-- locked down, so if anything here drifts from prod, prod is the authority.
--
-- The dev project was created with "Automatically expose new tables" OFF and
-- "Enable automatic RLS" ON, so tables come up locked and everything below has
-- to open them deliberately. That is the point: access is a decision you can
-- read in the migration, not a default nobody chose.
--
-- Safe to re-run.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

-- ── Tables ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.cafes (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  owner_id    uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.waiters (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cafe_id       uuid NOT NULL REFERENCES public.cafes(id) ON DELETE CASCADE,
  name          text NOT NULL,
  pin_hash      text,
  phone         text,
  color         text,
  pattern       jsonb NOT NULL DEFAULT '{"m":[0,0,0,0,0,0,0],"s":[0,0,0,0,0,0,0],"a":[0,0,0,0,0,0,0]}'::jsonb,
  vacations     jsonb NOT NULL DEFAULT '[]'::jsonb,
  invite_token  uuid NOT NULL DEFAULT gen_random_uuid(),
  joined_at     timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.shift_requests (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cafe_id      uuid NOT NULL REFERENCES public.cafes(id) ON DELETE CASCADE,
  waiter_id    uuid NOT NULL REFERENCES public.waiters(id) ON DELETE CASCADE,
  date         date NOT NULL,
  shift        text NOT NULL CHECK (shift IN ('jutro','međusmjena','popodne','oboje')),
  note         text,
  status       text NOT NULL DEFAULT 'open'
                 CHECK (status IN ('open','pending_approval','approved','rejected')),
  covered_by   uuid REFERENCES public.waiters(id) ON DELETE SET NULL,
  -- No FK: the approver is the owner, who lives in auth.users, not waiters.
  approved_by  uuid,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz
);

CREATE TABLE IF NOT EXISTS public.date_schedules (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cafe_id    uuid NOT NULL REFERENCES public.cafes(id) ON DELETE CASCADE,
  waiter_id  uuid NOT NULL REFERENCES public.waiters(id) ON DELETE CASCADE,
  date       date NOT NULL,
  shifts     jsonb NOT NULL DEFAULT '[]'::jsonb,
  -- The client upserts with onConflict: 'cafe_id,waiter_id,date', which needs
  -- exactly this constraint to exist or every schedule generation fails.
  UNIQUE (cafe_id, waiter_id, date)
);

-- ── PIN functions (mirroring production) ──────────────────

CREATE OR REPLACE FUNCTION public.set_waiter_pin(p_waiter_id uuid, p_pin text)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = public, extensions, pg_temp
AS $$
  UPDATE public.waiters
  SET pin_hash = extensions.crypt(p_pin, extensions.gen_salt('bf'))
  WHERE id = p_waiter_id;
$$;

CREATE OR REPLACE FUNCTION public.verify_waiter_pin(p_waiter_id uuid, p_pin text)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = public, extensions, pg_temp
AS $$
  SELECT COALESCE(
    (SELECT pin_hash = extensions.crypt(p_pin, pin_hash)
     FROM public.waiters WHERE id = p_waiter_id),
    false);
$$;

CREATE OR REPLACE FUNCTION public.login_waiter_by_pin(p_cafe_id uuid, p_pin text)
RETURNS TABLE (id uuid, name text, cafe_id uuid, color text)
LANGUAGE sql SECURITY DEFINER SET search_path = public, extensions, pg_temp
AS $$
  SELECT w.id, w.name, w.cafe_id, w.color
  FROM public.waiters w
  WHERE w.cafe_id = p_cafe_id
    AND w.pin_hash IS NOT NULL
    AND w.pin_hash = extensions.crypt(p_pin, w.pin_hash)
  LIMIT 1;
$$;

-- ── Invite functions (same as production migration 001) ───

CREATE OR REPLACE FUNCTION public.claim_invite(p_token uuid)
RETURNS TABLE (id uuid, cafe_id uuid, name text, color text,
               joined_at timestamptz, cafe_name text)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
AS $$
  SELECT w.id, w.cafe_id, w.name, w.color, w.joined_at, c.name AS cafe_name
  FROM public.waiters w
  JOIN public.cafes   c ON c.id = w.cafe_id
  WHERE w.invite_token = p_token
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.mark_invite_joined(p_token uuid)
RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp
AS $$
  UPDATE public.waiters SET joined_at = now()
  WHERE invite_token = p_token AND joined_at IS NULL;
$$;

-- ── Access ────────────────────────────────────────────────
-- "Automatically expose new tables" is off, so nothing is reachable until
-- granted here. Deliberate and visible, rather than a default nobody chose.

GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE
  ON public.cafes, public.waiters, public.shift_requests, public.date_schedules
  TO anon, authenticated;

GRANT EXECUTE ON FUNCTION public.set_waiter_pin(uuid, text)      TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.verify_waiter_pin(uuid, text)   TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.login_waiter_by_pin(uuid, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_invite(uuid)              TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mark_invite_joined(uuid)        TO anon, authenticated;

-- ── Deliberately permissive dev policies ──────────────────
-- Automatic RLS switched RLS on for every table above, which would otherwise
-- deny everything. These open it back up so single-phone testing is
-- unimpeded. They are named dev_open_* precisely so they are impossible to
-- mistake for real policies, and Stage D replaces them wholesale.
--
-- NEVER apply this section to production.

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['cafes','waiters','shift_requests','date_schedules']
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS dev_open_%s ON public.%I', t, t);
    EXECUTE format(
      'CREATE POLICY dev_open_%s ON public.%I FOR ALL TO anon, authenticated USING (true) WITH CHECK (true)',
      t, t);
  END LOOP;
END $$;

COMMIT;

-- Verify: this should return 4 rows, each with a dev_open_* policy.
--   select tablename, policyname from pg_policies where schemaname = 'public';
