-- 008 — Remove the insecure set_waiter_pin.
--
-- ⚠️  DO NOT RUN THIS UNTIL v4.35 IS DEPLOYED AND VERIFIED LIVE.
--
--     v4.35 switches osmica.html:1856 from set_waiter_pin(waiter_id, pin) to
--     set_waiter_pin_by_token(token, pin). Running this against 4.34 or earlier
--     breaks PIN setup for every new waiter — including all five of them right
--     after 010 rotates their tokens.
--
--     Check the version in the page footer says v4.35, then complete one real
--     invite -> PIN setup on production before running this.
--
-- Once 007 is in and the client no longer calls it, the old function is pure
-- attack surface: anon EXECUTE on a no-auth PIN setter for any waiter id.
--
-- mark_invite_joined stays. 007 folds its behaviour into PIN setup, but the
-- function is harmless on its own (token-keyed, idempotent, write-once) and
-- Stage C may still want it. Nothing calls it after v4.35.

BEGIN;

REVOKE EXECUTE ON FUNCTION public.set_waiter_pin(uuid, text) FROM anon, authenticated, PUBLIC;
DROP FUNCTION IF EXISTS public.set_waiter_pin(uuid, text);

COMMIT;

-- Verify with the publishable key and NO session — this must now fail rather
-- than return true:
--   POST /rest/v1/rpc/set_waiter_pin
--        {"p_waiter_id":"00000000-0000-0000-0000-000000000000","p_pin":"0000"}
--   -> 404 (function does not exist)
--
-- Before 008 this returned HTTP 200 and the body `true`, which is what
-- confirmed the takeover was live.
