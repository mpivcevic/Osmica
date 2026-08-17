-- 004 — Rate-limit PIN login.
--
-- A 4-digit PIN is 10,000 possibilities. login_waiter_by_pin(cafe_id, pin)
-- resolves café + PIN straight to a waiter, so an attacker does not even need
-- to know whose PIN they are guessing — any hit logs them in as somebody.
-- Unlimited attempts make that a seconds-long attack.
--
-- This is a stopgap. Stage C deletes login_waiter_by_pin entirely, at which
-- point the whole table below can be dropped.

BEGIN;

CREATE TABLE IF NOT EXISTS public.pin_attempts (
  cafe_id      uuid PRIMARY KEY REFERENCES public.cafes(id) ON DELETE CASCADE,
  fails        int         NOT NULL DEFAULT 0,
  locked_until timestamptz
);

-- No client should ever read or write this directly; only the SECURITY DEFINER
-- function below touches it.
ALTER TABLE public.pin_attempts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.pin_attempts FROM anon, authenticated;

CREATE OR REPLACE FUNCTION public.register_pin_failure(p_cafe_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
  INSERT INTO public.pin_attempts (cafe_id, fails)
  VALUES (p_cafe_id, 1)
  ON CONFLICT (cafe_id) DO UPDATE
    SET fails = public.pin_attempts.fails + 1,
        -- Ten wrong PINs locks the café's keypad for 15 minutes. Generous for
        -- a tired waiter at 6am, ruinous for a brute force.
        locked_until = CASE
          WHEN public.pin_attempts.fails + 1 >= 10 THEN now() + interval '15 minutes'
          ELSE public.pin_attempts.locked_until
        END;
END;
$$;

CREATE OR REPLACE FUNCTION public.is_pin_locked(p_cafe_id uuid)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT COALESCE(
    (SELECT locked_until > now() FROM public.pin_attempts WHERE cafe_id = p_cafe_id),
    false
  );
$$;

GRANT EXECUTE ON FUNCTION public.is_pin_locked(uuid) TO anon, authenticated;

COMMIT;

-- MANUAL STEP — login_waiter_by_pin must now, in this order:
--   1. RETURN NULL immediately if is_pin_locked(p_cafe_id)
--   2. on a wrong PIN, call register_pin_failure(p_cafe_id)
--   3. on a correct PIN, reset: UPDATE pin_attempts
--        SET fails = 0, locked_until = NULL WHERE cafe_id = p_cafe_id
--
-- The existing body was never captured, so it is not rewritten here. Paste the
-- current definition (Dashboard -> Database -> Functions) and the edit takes
-- about five minutes.
