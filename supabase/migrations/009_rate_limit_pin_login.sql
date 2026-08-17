-- 009 — Rate-limit BOTH PIN oracles. Supersedes 004; do not run 004.
--
-- A 4-digit PIN is 10,000 possibilities and there are two ways to test a guess:
--
--   login_waiter_by_pin(cafe_id, pin)   osmica.html:1542  café + PIN -> any waiter
--   verify_waiter_pin(waiter_id, pin)   osmica.html:1586, :1892  waiter + PIN -> bool
--
-- 004 throttled only the first. `waiters.id` is anon-readable, so the second is
-- the same 10,000-guess space against a named person. Both are covered here.
--
-- Three fixes to 004's design, all found while writing this:
--
--   1. 004 never decayed the counter. Fails only reset on a successful login, so
--      a café accumulating one fumbled PIN a week would eventually lock itself
--      out forever. Counters now decay after 15 quiet minutes.
--   2. 004 used a flat 10-fails/15-minutes lockout. That is 15 minutes of a real
--      café unable to work because someone mistyped at 6am. Escalating instead:
--      10 fails -> 1 min, 20 -> 5 min, 30+ -> 15 min. A brute force still needs
--      ~1000 windows (250+ hours) to walk 10,000; a tired waiter waits a minute.
--   3. PostgreSQL grants EXECUTE to PUBLIC on new functions by default, so 004's
--      helpers would have been callable by anon — including the one that
--      increments the counter, i.e. a free café-wide lockout button. Explicitly
--      revoked below.
--
-- ACCEPTED TRADE-OFF: the lockout is café-wide, because on a failed
-- login_waiter_by_pin there is by definition no waiter to attribute the failure
-- to. So an attacker can deliberately lock the café's keypad. That is a nuisance
-- where the alternative is account takeover, and Stage C deletes this whole
-- mechanism — table included — when waiters get real identities.
--
-- Safe to run at any point after 007. Does not depend on 008.

BEGIN;

CREATE TABLE IF NOT EXISTS public.pin_attempts (
  cafe_id      uuid PRIMARY KEY REFERENCES public.cafes(id) ON DELETE CASCADE,
  fails        int         NOT NULL DEFAULT 0,
  last_fail_at timestamptz,
  locked_until timestamptz
);

-- 004 shipped without last_fail_at; add it if that version was ever applied.
ALTER TABLE public.pin_attempts ADD COLUMN IF NOT EXISTS last_fail_at timestamptz;

-- No client ever touches this directly; only the SECURITY DEFINER functions
-- below, which run as the table owner and so bypass RLS.
ALTER TABLE public.pin_attempts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.pin_attempts FROM anon, authenticated, PUBLIC;


CREATE OR REPLACE FUNCTION public.register_pin_failure(p_cafe_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_fails int;
BEGIN
  -- Guard the FK: an attacker posts arbitrary café ids, and an unguarded INSERT
  -- would either raise (leaking that the café is unknown) or, without the FK,
  -- let them grow this table without bound.
  IF p_cafe_id IS NULL
     OR NOT EXISTS (SELECT 1 FROM public.cafes WHERE id = p_cafe_id) THEN
    RETURN;
  END IF;

  INSERT INTO public.pin_attempts (cafe_id, fails, last_fail_at)
  VALUES (p_cafe_id, 1, now())
  ON CONFLICT (cafe_id) DO UPDATE
    SET fails = CASE
          -- Decay: 15 quiet minutes and the slate is clean.
          WHEN public.pin_attempts.last_fail_at IS NULL
            OR public.pin_attempts.last_fail_at < now() - interval '15 minutes'
          THEN 1
          ELSE public.pin_attempts.fails + 1
        END,
        last_fail_at = now()
  RETURNING fails INTO v_fails;

  UPDATE public.pin_attempts
  SET locked_until = CASE
        WHEN v_fails >= 30 THEN now() + interval '15 minutes'
        WHEN v_fails >= 20 THEN now() + interval '5 minutes'
        WHEN v_fails >= 10 THEN now() + interval '1 minute'
        ELSE locked_until
      END
  WHERE cafe_id = p_cafe_id;
END;
$$;


CREATE OR REPLACE FUNCTION public.clear_pin_failures(p_cafe_id uuid)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
  UPDATE public.pin_attempts
  SET fails = 0, last_fail_at = NULL, locked_until = NULL
  WHERE cafe_id = p_cafe_id;
$$;


CREATE OR REPLACE FUNCTION public.is_pin_locked(p_cafe_id uuid)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
  SELECT COALESCE(
    (SELECT locked_until > now() FROM public.pin_attempts WHERE cafe_id = p_cafe_id),
    false
  );
$$;

-- Default EXECUTE is granted to PUBLIC. The two mutating helpers must not be
-- callable by anyone but the functions below — register_pin_failure especially,
-- since a direct caller could lock a café out at will.
REVOKE EXECUTE ON FUNCTION public.register_pin_failure(uuid) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.clear_pin_failures(uuid)   FROM PUBLIC, anon, authenticated;

-- is_pin_locked is read-only and safe to expose: it lets the keypad eventually
-- say "too many attempts" instead of "wrong PIN". See the note at the bottom.
GRANT EXECUTE ON FUNCTION public.is_pin_locked(uuid) TO anon, authenticated;


-- ---------------------------------------------------------------------------
-- The two oracles, rewritten.
-- ---------------------------------------------------------------------------

-- DROP rather than REPLACE: the return type changes. `phone` is removed, because
-- 006 made it owner-only at the table grant and this SECURITY DEFINER function
-- was handing it back to anon anyway. The client never reads it — osmica.html:1549
-- builds the session from id, name, cafe_id and color only.
DROP FUNCTION IF EXISTS public.login_waiter_by_pin(uuid, text);

CREATE FUNCTION public.login_waiter_by_pin(p_cafe_id uuid, p_pin text)
RETURNS TABLE(id uuid, cafe_id uuid, name text, color text, pattern jsonb)
LANGUAGE plpgsql
SECURITY DEFINER
-- The original had no search_path. A SECURITY DEFINER function runs as its
-- owner, so an attacker-controlled search_path is the classic hijack.
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_id uuid;
BEGIN
  IF public.is_pin_locked(p_cafe_id) THEN
    RETURN;  -- empty, indistinguishable from a wrong PIN
  END IF;

  SELECT w.id INTO v_id
  FROM public.waiters w
  WHERE w.cafe_id = p_cafe_id
    AND w.pin_hash IS NOT NULL
    AND crypt(p_pin, w.pin_hash) = w.pin_hash
  LIMIT 1;

  IF v_id IS NULL THEN
    PERFORM public.register_pin_failure(p_cafe_id);
    RETURN;
  END IF;

  PERFORM public.clear_pin_failures(p_cafe_id);

  RETURN QUERY
  SELECT w.id, w.cafe_id, w.name, w.color, w.pattern
  FROM public.waiters w
  WHERE w.id = v_id;
END;
$$;

GRANT EXECUTE ON FUNCTION public.login_waiter_by_pin(uuid, text) TO anon, authenticated;


-- Return type is unchanged, so REPLACE is fine here.
CREATE OR REPLACE FUNCTION public.verify_waiter_pin(p_waiter_id uuid, p_pin text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions, pg_temp
AS $$
DECLARE
  v_cafe_id uuid;
  v_hash    text;
  v_ok      boolean;
BEGIN
  SELECT w.cafe_id, w.pin_hash INTO v_cafe_id, v_hash
  FROM public.waiters w
  WHERE w.id = p_waiter_id;

  IF v_cafe_id IS NULL THEN
    RETURN false;  -- unknown waiter: nothing to attribute a failure to
  END IF;

  IF public.is_pin_locked(v_cafe_id) THEN
    RETURN false;
  END IF;

  v_ok := v_hash IS NOT NULL AND crypt(p_pin, v_hash) = v_hash;

  IF v_ok THEN
    PERFORM public.clear_pin_failures(v_cafe_id);
  ELSE
    PERFORM public.register_pin_failure(v_cafe_id);
  END IF;

  RETURN v_ok;
END;
$$;

GRANT EXECUTE ON FUNCTION public.verify_waiter_pin(uuid, text) TO anon, authenticated;

COMMIT;


-- VERIFY, with the publishable key and no session. Use a WRONG PIN throughout so
-- you are not typing a real credential into a shell, and run it against the DEV
-- café first if you would rather not lock production's keypad for a minute.
--
--   1. Ten wrong guesses, then check the lock engaged:
--      for i in $(seq 1 10); do
--        curl -s -X POST "$URL/rest/v1/rpc/login_waiter_by_pin" \
--          -H "apikey: $KEY" -H "Authorization: Bearer $KEY" \
--          -H "Content-Type: application/json" \
--          -d '{"p_cafe_id":"<cafe>","p_pin":"0000"}'; echo
--      done
--      -> all return []
--
--   2. select is_pin_locked('<cafe>')  -> true
--
--   3. A CORRECT PIN must also return [] while locked. If it logs in, the guard
--      is in the wrong place.
--
--   4. Wait 60s, log in correctly -> one row, and no `phone` column.
--
--   5. select is_pin_locked('<cafe>')  -> false   (cleared on success)
--
-- To unlock immediately during testing:
--   DELETE FROM public.pin_attempts WHERE cafe_id = '<cafe>';
--
--
-- KNOWN UX GAP, deliberately not fixed here: a locked-out waiter sees "Pogrešan
-- PIN. Pokušaj ponovo." because the client cannot tell an empty result from a
-- wrong PIN. is_pin_locked is granted to anon precisely so the keypad can call
-- it after a failure and say "too many attempts, try again in a minute". That is
-- a client change and belongs in its own build — see TOMORROW.md.
