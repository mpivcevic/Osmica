-- dev/012 — The dev twin of production's 007.
--
-- Needed because v4.35 calls set_waiter_pin_by_token, and localhost + every
-- tunnel URL hit osmica-dev. Without this, dev's invite flow errors out with
-- "function does not exist" while production works fine.
--
-- ONE DIFFERENCE from production's 007, and it is the whole reason this file
-- exists rather than a copy-paste:
--
--   production  waiters.invite_token  text  (default gen_random_uuid()::text)
--   dev         waiters.invite_token  uuid
--
-- So the lookup casts: `w.invite_token::text = p_token`. The client sends a
-- string either way, and the cast is on the column rather than the parameter so
-- an invalid uuid in p_token cannot raise — it simply matches nothing.
--
-- Not fixing the type drift here. That belongs in the still-unwritten
-- 012_dev_align_with_prod.sql, along with the other nine differences, and
-- changing a column type under a live seed is not something to bundle into an
-- unrelated migration.
--
-- Dev deliberately keeps anonymous writes (003 is never applied here), so this
-- function is the only hardening dev gets. That is intentional: dev tests the
-- app, not the security model.

BEGIN;

CREATE OR REPLACE FUNCTION public.set_waiter_pin_by_token(p_token text, p_pin text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
-- `extensions` carries pgcrypto — see line 16 of 010_dev_schema.sql. Omitting it
-- makes crypt() fail on the happy path only, which a token-validation smoke test
-- will not catch.
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
  WHERE w.invite_token::text = p_token   -- ← the dev-only cast
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

GRANT EXECUTE ON FUNCTION public.set_waiter_pin_by_token(text, text) TO anon, authenticated;

COMMIT;

-- Verify. Eva Evec is the standing never-joined subject in the dev seed, so she
-- is the one row where the happy path can be exercised repeatedly.
--
--   select set_waiter_pin_by_token(gen_random_uuid()::text, '1234');  -- invalid_token
--   select set_waiter_pin_by_token('not-a-uuid', '1234');             -- invalid_token, no error
--   select set_waiter_pin_by_token('anything', '12');                 -- invalid_pin
--
-- The happy path, which is the one that proves crypt() resolves — rolled back so
-- Eva stays available as a fresh subject:
--
--   begin;
--   select set_waiter_pin_by_token(
--     (select invite_token::text from public.waiters where name like 'Eva%'), '1234');  -- ok
--   rollback;
--
-- To put Eva back after a real end-to-end test through the UI:
--   update public.waiters
--   set joined_at = null, pin_hash = null, invite_token = gen_random_uuid()
--   where name like 'Eva%';
