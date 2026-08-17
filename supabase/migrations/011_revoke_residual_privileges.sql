-- 011 — Remove privileges nothing uses, found by auditing the grant table.
--
-- Migration 003 revoked INSERT, UPDATE and DELETE from anon. It did not revoke
-- TRUNCATE, TRIGGER or REFERENCES, because nobody thought to look for them —
-- they arrive automatically from Supabase's default GRANT ALL on new tables and
-- never appear in the app, so they are invisible until you query the catalog.
--
-- Confirmed present on all four tables, 17 Aug 2026, for BOTH anon and
-- authenticated:
--
--   anon           cafes, date_schedules, shift_requests, waiters
--                  -> REFERENCES, TRIGGER, TRUNCATE
--   authenticated  same three, plus the full CRUD set it legitimately needs
--
-- WHY TRUNCATE MATTERS, and it is not the reason you would guess.
--
--   For anon it is currently unreachable: PostgREST exposes SELECT, INSERT,
--   UPDATE, DELETE and RPC, and has no TRUNCATE verb. So this is not a live
--   hole. It is a grant that should never have existed, sitting one dynamic-SQL
--   mistake away from mattering.
--
--   For `authenticated` it is worse, and it is a Stage D problem in advance:
--   **TRUNCATE ignores Row Level Security entirely.** RLS filters DELETE row by
--   row; TRUNCATE is a table-level operation that policies cannot constrain. So
--   once Stage D lands and each owner is confined to their own café, any signed-
--   in owner would still be able to empty every café's table in one statement —
--   including cafés belonging to other businesses. The policies would look
--   correct and would not be.
--
--   Revoking it now means Stage D's policies are the whole story when they land,
--   rather than being quietly bypassable.
--
-- TRIGGER lets a role attach triggers to a table, which is a route to running
-- code on someone else's writes. REFERENCES lets a role point a foreign key at
-- the table, which can block deletes. Neither is used by anything.
--
-- Also drops mark_invite_joined: dead since v4.35, when migration 007 folded
-- marking-joined into set_waiter_pin_by_token's single UPDATE. It is anon-
-- callable and nothing calls it. Harmless in itself — token-keyed, write-once —
-- but an unused anon-executable function is surface for no benefit.
--
-- Safe to run on production and dev alike. Nothing the client does needs any of
-- these.

BEGIN;

-- ── Privileges no role in this app has ever used ────────────────────────────

REVOKE TRUNCATE, TRIGGER, REFERENCES
  ON public.cafes, public.waiters, public.shift_requests, public.date_schedules
  FROM anon, authenticated, PUBLIC;

-- ── Dead function ───────────────────────────────────────────────────────────

DROP FUNCTION IF EXISTS public.mark_invite_joined(text);
DROP FUNCTION IF EXISTS public.mark_invite_joined(uuid);   -- dev's old signature

-- ── Trigger function should not be callable as an RPC ───────────────────────
-- set_updated_at showed as anon-executable purely because PostgreSQL grants
-- EXECUTE to PUBLIC by default. Calling it outside a trigger errors anyway, so
-- this is hygiene rather than a fix — but the audit should come back clean, so
-- that a future row that IS interesting stands out.

REVOKE EXECUTE ON FUNCTION public.set_updated_at() FROM anon, authenticated, PUBLIC;

COMMIT;

-- ── VERIFY ──────────────────────────────────────────────────────────────────
--
-- 1. anon should now hold SELECT and nothing else. waiters will show no row at
--    all here, because its SELECT is column-level (005/006) rather than
--    table-level — that is correct, not a missing grant.
--
--      select grantee, table_name, privilege_type
--      from information_schema.table_privileges
--      where table_schema = 'public' and grantee in ('anon','authenticated')
--      order by table_name, grantee, privilege_type;
--
--    expect for anon:          SELECT on cafes, date_schedules, shift_requests
--    expect for authenticated: SELECT, INSERT, UPDATE, DELETE on all four
--    expect nowhere:           TRUNCATE, TRIGGER, REFERENCES
--
-- 2. The function audit should list six functions, four anon-runnable:
--
--      select p.proname,
--             case when p.prosecdef then 'DEFINER' else 'invoker' end as security,
--             has_function_privilege('anon', p.oid, 'EXECUTE') as anon_can_run
--      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
--      where n.nspname = 'public'
--      order by anon_can_run desc, p.proname;
--
--    anon_can_run true:  claim_invite, is_pin_locked, login_waiter_by_pin,
--                        set_waiter_pin_by_token, verify_waiter_pin
--    anon_can_run false: clear_pin_failures, register_pin_failure, set_updated_at
--    gone:               mark_invite_joined
--
-- 3. The app must still work end to end. The invite flow is the one this could
--    plausibly break, so complete one invite -> PIN setup after running it.
--
-- NOTE for Stage C: claim_invite carries `search_path=public, pg_temp` with no
-- `extensions`. That is correct today — it is a pure SELECT and calls nothing
-- from pgcrypto. If Stage C ever adds a crypt() call to it, that search_path
-- must gain `extensions` or it will fail on the happy path only.
