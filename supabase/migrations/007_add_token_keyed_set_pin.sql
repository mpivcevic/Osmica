-- 007 — Close the unauthenticated waiter takeover.
--
-- THE HOLE (confirmed live against production, 17 Aug 2026):
--
--   set_waiter_pin(p_waiter_id uuid, p_pin text) is SECURITY DEFINER, granted to
--   anon, and authenticates NOTHING. It takes a waiter id and sets that waiter's
--   PIN. `waiters.id` is anon-readable. So:
--
--     1. GET  /waiters?select=id,name              -> pick a target
--     2. POST /rpc/set_waiter_pin {id, "1234"}     -> their PIN is now 1234
--     3. POST /rpc/login_waiter_by_pin {cafe, "1234"} -> logged in as them
--
--   Three requests, no guessing, any waiter. This is worse than the PIN brute
--   force that 004/009 address, and rotating credentials (010) does NOT fix it:
--   set_waiter_pin overwrites whatever pin_hash holds, NULL included.
--
-- THE FIX:
--
--   Key PIN setup on the invite token, exactly as 001 did for claim_invite and
--   mark_invite_joined. The token is the only thing a legitimate first-time
--   waiter holds that a passer-by does not.
--
--   Also enforce server-side what the client already assumes: PIN setup is only
--   valid while joined_at IS NULL. osmica.html:1787 sends a waiter to the
--   'setup' step only when !waiter.joined_at, and to 'recover' (which demands
--   the existing PIN via verify_waiter_pin) otherwise. The server never checked.
--   Now it does, which makes the invite genuinely single-use for PIN setup.
--
--   mark_invite_joined is folded in. It was a second anonymous round trip
--   (osmica.html:1872) that left a window where the PIN was set but the invite
--   was still open. One statement, no window.
--
-- THIS FILE IS PURELY ADDITIVE AND SAFE TO RUN NOW. It creates a new function
-- under a new name and changes nothing that exists. The insecure
-- set_waiter_pin keeps working until 008 drops it — which must not run until
-- v4.35 is deployed. Same ordering discipline as 001 -> 4.29 -> 002.

BEGIN;

CREATE OR REPLACE FUNCTION public.set_waiter_pin_by_token(p_token text, p_pin text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
-- SECURITY DEFINER runs as the owner; an attacker-controlled search_path is the
-- classic way to hijack one.
--
-- `extensions` MUST be listed: crypt() and gen_salt() come from pgcrypto, which
-- Supabase installs into the `extensions` schema. The original functions carried
-- no search_path at all, which is the only reason crypt() ever resolved for them.
-- Pinning it to `public, pg_temp` alone makes every crypt() call fail — and it
-- fails on the happy path only, so a token/PIN-validation smoke test still
-- passes. An unlisted schema here is ignored, so this is safe either way.
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_waiter_id uuid;
  v_cafe_id   uuid;
  v_taken     int;
BEGIN
  -- A 4-digit PIN is the whole credential. Reject anything that is not exactly
  -- four digits rather than trusting the keypad, which is client-side and
  -- therefore not a control.
  IF p_pin IS NULL OR p_pin !~ '^[0-9]{4}$' THEN
    RETURN 'invalid_pin';
  END IF;

  -- The token is the credential. joined_at IS NULL makes it single-use for PIN
  -- setup: once the waiter has joined, the only way back in is the recover path,
  -- which requires knowing the current PIN.
  SELECT id, cafe_id INTO v_waiter_id, v_cafe_id
  FROM public.waiters
  WHERE invite_token = p_token
    AND joined_at IS NULL
  LIMIT 1;

  IF v_waiter_id IS NULL THEN
    -- Deliberately does not distinguish "no such token" from "already joined".
    -- Telling them apart would confirm that a token is real.
    RETURN 'invalid_token';
  END IF;

  -- Unchanged from the original: PINs must be unique per café, because
  -- login_waiter_by_pin resolves café + PIN to exactly one waiter.
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

-- Anonymous callers are the point: a waiter opening an invite link has no
-- session yet.
GRANT EXECUTE ON FUNCTION public.set_waiter_pin_by_token(text, text) TO anon, authenticated;

COMMIT;

-- Verify with the publishable key and NO session:
--   select set_waiter_pin_by_token(gen_random_uuid()::text, '1234'); -> invalid_token
--   select set_waiter_pin_by_token('<real unused token>', '12');     -> invalid_pin
--   select set_waiter_pin_by_token('<real USED token>',   '1234');   -> invalid_token
--
-- Residual, accepted: a holder of a valid UNUSED token can still probe which
-- PINs are taken in that café, four digits at a time, via the 'taken' return.
-- That is a much narrower audience than "anyone with the page open", and it
-- disappears with the rest of this machinery at Stage C.
