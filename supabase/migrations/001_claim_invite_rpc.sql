-- 001 — claim_invite(): the only anonymous path that may touch invite_token.
--
-- Purely additive. Run this FIRST; it breaks nothing on its own, and it must
-- exist before the client build that calls it, which in turn must ship before
-- 002 revokes anon's access to the column.
--
-- Replaces this client query, which required anon to both read and filter on
-- invite_token:
--   sb.from('waiters').select('*').eq('invite_token', token).single()
--
-- Returns only what the invite screen renders, and never the token itself.
-- Also folds in the cafes lookup that used to be a second round trip.

BEGIN;

CREATE OR REPLACE FUNCTION public.claim_invite(p_token text)
RETURNS TABLE (
  id         uuid,
  cafe_id    uuid,
  name       text,
  color      text,
  joined_at  timestamptz,
  cafe_name  text
)
LANGUAGE sql
SECURITY DEFINER
-- Pin the search_path: SECURITY DEFINER functions run as the owner, and an
-- attacker-controlled search_path is the classic way to hijack one.
SET search_path = public, pg_temp
AS $$
  SELECT w.id, w.cafe_id, w.name, w.color, w.joined_at, c.name AS cafe_name
  FROM public.waiters w
  JOIN public.cafes   c ON c.id = w.cafe_id
  WHERE w.invite_token = p_token
  LIMIT 1;
$$;

-- Anonymous callers are the entire point of this function: a waiter opening an
-- invite link has no session yet.
GRANT EXECUTE ON FUNCTION public.claim_invite(text) TO anon, authenticated;


-- Finishing an invite marks joined_at, which the client did as a bare anonymous
-- UPDATE — a write that migration 003 revokes. Keyed on the token rather than
-- the waiter id, so a passer-by cannot flip someone else's row to "joined" and
-- lock them out of PIN setup. Idempotent: only ever sets joined_at once.
CREATE OR REPLACE FUNCTION public.mark_invite_joined(p_token text)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  UPDATE public.waiters
  SET joined_at = now()
  WHERE invite_token = p_token
    AND joined_at IS NULL;
$$;

GRANT EXECUTE ON FUNCTION public.mark_invite_joined(text) TO anon, authenticated;

COMMIT;

-- Verify with the publishable key and no session:
--   select * from claim_invite('<a real token>');            -> one row, no token column
--   select * from claim_invite(gen_random_uuid()::text);   -> zero rows
