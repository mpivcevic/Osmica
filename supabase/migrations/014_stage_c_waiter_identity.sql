-- 014 — Stage C1: give waiters a place to hold a real identity.
--
-- PURELY ADDITIVE. Adds one nullable column and one function. Changes nothing
-- that exists, and the client does not call it until v4.37. Safe to run on
-- production and dev immediately, in either order.
--
-- BEFORE THIS IS USEFUL, a dashboard setting must be changed on BOTH projects:
--
--   Authentication -> Providers -> Anonymous sign-ins -> enable
--
-- Without it, signInAnonymously() returns an error and the client's linking step
-- quietly does nothing. That failure is deliberately non-fatal (the PIN login
-- path still works), so it will not announce itself — check the column, not the
-- app's behaviour.
--
-- WHY auth.uid() RATHER THAN A PARAMETER: the function reads the caller's
-- identity from their JWT instead of accepting a user id as an argument. An
-- argument could be forged by anyone; auth.uid() is signed by Supabase and
-- cannot be. This is the same lesson as migration 007 — the caller must not be
-- allowed to assert who they are.

BEGIN;

-- Nullable on purpose: every existing waiter has no identity yet, and C2 fills
-- them in one at a time as each person re-invites. UNIQUE because one Supabase
-- user maps to exactly one waiter — see "one device per waiter" in
-- osmica_stage_c_plan.md, which is a decision, not an accident.
--
-- ON DELETE SET NULL rather than CASCADE: deleting an auth user must not delete
-- the employee record. It should unlink them so the owner can re-invite.
ALTER TABLE public.waiters
  ADD COLUMN IF NOT EXISTS auth_user_id uuid UNIQUE
  REFERENCES auth.users(id) ON DELETE SET NULL;


CREATE OR REPLACE FUNCTION public.link_waiter_to_auth(p_token text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
-- No crypt() here, but `extensions` costs nothing and removes the chance that
-- someone later adds one and rediscovers the happy-path-only failure. See the
-- traps list in supabase/migrations/README.md.
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_uid       uuid := auth.uid();
  v_waiter_id uuid;
BEGIN
  -- The caller must actually be signed in. An anonymous Supabase user still has
  -- a uid; someone calling with only the publishable key does not.
  IF v_uid IS NULL THEN
    RETURN 'no_session';
  END IF;

  -- Already linked, on this or another device: succeed silently rather than
  -- error, so a retried or double-fired call is harmless.
  SELECT id INTO v_waiter_id
  FROM public.waiters
  WHERE auth_user_id = v_uid;

  IF v_waiter_id IS NOT NULL THEN
    RETURN 'already_linked';
  END IF;

  -- Keyed on the invite token, exactly as 007. `auth_user_id IS NULL` rather
  -- than `joined_at IS NULL`, because by this point set_waiter_pin_by_token has
  -- already set joined_at — the client links immediately after setting the PIN.
  SELECT id INTO v_waiter_id
  FROM public.waiters
  WHERE invite_token = p_token
    AND auth_user_id IS NULL
  LIMIT 1;

  IF v_waiter_id IS NULL THEN
    -- Covers "no such token" and "that waiter is already claimed" without
    -- distinguishing them, so the answer confirms nothing to a stranger.
    RETURN 'invalid_token';
  END IF;

  -- Bind, and burn the token in the same statement.
  --
  -- Rotating it here is what finally answers "can a forwarded invite be reused?"
  -- with no. Until now the token stayed valid forever and remained a permanent
  -- handle on the account; from here it is dead the moment the real waiter
  -- links. The cost is that a waiter who clears browser data needs the owner to
  -- reissue — see decision 2 in osmica_stage_c_plan.md.
  UPDATE public.waiters
  SET auth_user_id = v_uid,
      invite_token = gen_random_uuid()::text,
      joined_at    = COALESCE(joined_at, now())
  WHERE id = v_waiter_id;

  RETURN 'ok';
END;
$$;

-- Supabase gives anonymous sign-ins the `authenticated` role, with an
-- `is_anonymous` claim set true. So this grant covers waiters; it also covers
-- owners, which is harmless because the token is what authorises, not the role.
GRANT EXECUTE ON FUNCTION public.link_waiter_to_auth(text) TO authenticated;

-- Deliberately NOT granted to anon. A caller with no session has no auth.uid()
-- and could only ever get 'no_session', so exposing it would add surface for
-- nothing.
REVOKE EXECUTE ON FUNCTION public.link_waiter_to_auth(text) FROM anon, PUBLIC;

COMMIT;


-- ── VERIFY ──────────────────────────────────────────────────────────────────
--
-- 1. The column exists and every waiter is unlinked so far:
--
--      select name, auth_user_id from public.waiters order by name;
--      -- expect: six rows, auth_user_id all null
--
-- 2. With the publishable key and NO session, the function is unreachable:
--
--      POST /rest/v1/rpc/link_waiter_to_auth {"p_token":"x"}   -> 401 or 404
--
--    If this returns 'no_session' instead, the anon revoke did not take.
--
-- 3. Nothing else changed — the existing invite path still behaves:
--
--      select set_waiter_pin_by_token('not-a-uuid','1234');   -- invalid_token
--
-- 4. THE REAL TEST belongs to C2 and needs a browser: complete an invite on
--    dev, then confirm the binding landed —
--
--      select name, auth_user_id is not null as linked from public.waiters
--      where name like 'Eva%';
--
--    and then close and reopen the app as that waiter. They must land on the
--    waiter screen. If they land in the owner's admin panel, the is_anonymous
--    guard in init() is missing or wrong — stop and fix that before anything
--    else, because it hands every waiter the owner's view.
