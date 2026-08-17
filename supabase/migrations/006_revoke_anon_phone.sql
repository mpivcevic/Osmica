-- 006 — Stop exposing waiters' phone numbers to anonymous readers.
--
-- After 005, anon could still read `phone` — five real mobile numbers of real
-- employees, readable by anyone who opens the page and finds the key. Personal
-- data under GDPR, and the last genuinely sensitive column left open.
--
-- Every use of phone in the client is owner-side: the admin staff list, the
-- WhatsApp invite, the edit-waiter form, and the schedule-notify buttons. No
-- waiter-facing screen displays another waiter's number, so anon does not need
-- the column at all.
--
-- Requires Build 4.34 to be deployed first: that build drops phone from
-- WAITER_COLS and adds it to WAITER_COLS_ADMIN, and makes loadAppData() take
-- the owner's list explicitly. Running this against an earlier build 401s the
-- waiter roster load.
--
-- Same shape as 005 — re-grant the allowed columns rather than trying to revoke
-- one, because a column-level REVOKE cannot subtract from a table-level grant.
--
-- Safe to re-run.

BEGIN;

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

-- Unchanged: the owner reads phone and invite_token for their own café.
GRANT SELECT ON public.waiters TO authenticated;

COMMIT;

-- Verify with the publishable key and NO session:
--   select=name,color   -> 200
--   select=phone        -> 401/403
--   select=name,phone   -> 401/403
--
-- Remaining anon-readable columns are name, colour, shift pattern and holidays.
-- Closing those needs per-café isolation, i.e. RLS, i.e. Stage C then Stage D.
