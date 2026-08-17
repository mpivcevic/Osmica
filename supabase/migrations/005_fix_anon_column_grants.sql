-- 005 — Actually hide pin_hash and invite_token from anonymous readers.
--
-- Migration 002 ran without error and achieved nothing. It used:
--   REVOKE SELECT (pin_hash) ON waiters FROM anon;
-- which only subtracts COLUMN-level privileges. anon holds a TABLE-level SELECT
-- grant, and a table grant confers every column including ones later "revoked"
-- individually. Postgres reports success because the statement is valid; it just
-- has nothing to remove.
--
-- The working form is the opposite shape: drop the table-wide grant, then grant
-- back exactly the columns anon may see. Anything added to the table in future
-- is then invisible to anon until explicitly granted, which is the safer default.
--
-- authenticated keeps full table SELECT: the owner legitimately reads
-- invite_token to build invite links for their own café.
--
-- Safe to re-run.

BEGIN;

-- PUBLIC is included because a grant there would leak straight through to anon,
-- and revoking from anon alone would leave the hole open with no error to show
-- for it — exactly the failure mode 002 had.
REVOKE SELECT ON public.waiters FROM anon, PUBLIC;

GRANT SELECT (
  id,
  cafe_id,
  name,
  phone,
  color,
  pattern,
  vacations,
  joined_at,
  created_at
) ON public.waiters TO anon;

-- Explicit rather than assumed: the owner's paths depend on this.
GRANT SELECT ON public.waiters TO authenticated;

COMMIT;

-- Verify with the publishable key and NO session. Expected:
--   select=name,color     -> 200
--   select=pin_hash       -> 401/403
--   select=invite_token   -> 401/403
--   select=*              -> 401/403  (because * expands to include both)
--
-- That last one is the reason the client had to stop using select('*') in
-- v4.29 before this could run. It also means claim_invite() is now the only
-- way an anonymous caller can resolve an invite — which is the intent.
