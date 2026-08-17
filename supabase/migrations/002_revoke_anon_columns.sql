-- 001 — Stop leaking credentials to anonymous readers.
--
-- Run this FIRST, and only after Build 4.29 is deployed. That build narrowed
-- every client SELECT so nothing asks for these two columns from a waiter
-- session. Running it against an older build breaks the roster load, because
-- PostgREST's select('*') expands to columns the anon role can no longer read.
--
-- Safe to re-run.

BEGIN;

-- pin_hash: bcrypt over a 4-digit PIN is a 10,000-key space. No client code
-- reads this column; it existed in responses only because of select('*').
REVOKE SELECT (pin_hash) ON public.waiters FROM anon;

-- invite_token: a live credential. For a waiter with joined_at IS NULL it
-- grants PIN-setup mode, i.e. account takeover. The owner still needs it to
-- build invite links, and keeps access because they are `authenticated`,
-- not `anon`.
REVOKE SELECT (invite_token) ON public.waiters FROM anon;

COMMIT;

-- Verify — both must fail with a permission error when run with the
-- publishable key and no session:
--   select pin_hash from waiters limit 1;
--   select invite_token from waiters limit 1;
-- And this must still succeed:
--   select id, name, joined_at from waiters limit 1;
