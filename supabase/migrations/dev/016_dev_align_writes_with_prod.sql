-- dev/016 — Align dev's WRITE path with production: drop dev_open_*, revoke
-- anonymous writes.
--
-- Applies to osmica-dev (simavghwjnqytcyeunto) only. Production already has
-- both halves of this, from 003 and 015 respectively. Do not run on production.
--
-- WHY NOW, when dev/013 deliberately chose the opposite.
--
-- dev/013 lines 15-19 declined to apply 003 on purpose: "Dev keeps anonymous
-- writes so single-phone testing is unimpeded. This is the one intentional
-- difference, and it is the one that cannot mislead you: dev being more
-- permissive never hides a production failure."
--
-- That reasoning was sound for the question dev was answering at the time —
-- does the app work — and it has expired. Stage C changed the question. The
-- property that now has to hold is that an UNLINKED waiter cannot write and a
-- LINKED one can, and a more-permissive dev answers "everyone can" to both
-- halves. Dev being more permissive now hides precisely the production failure
-- Stage C exists to fix.
--
-- THE PART NOBODY DECIDED, which is the more serious of the two.
--
-- dev/010 line 154 created, on all four tables:
--
--     CREATE POLICY dev_open_<t> ON public.<t>
--       FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
--
-- 015 drops and recreates its own named policies (cafes_read, sr_waiter_insert,
-- and so on) but knows nothing about dev_open_*, having been written against
-- production where they do not exist. **Permissive policies combine with OR.**
-- So on dev every 015 policy sits underneath a blanket USING (true), and the
-- entire mechanism Stage C rests on — sr_waiter_insert, sr_waiter_update,
-- owns_cafe(), is_anon_session() — has never once been exercised. The five
-- browser checks recorded as passing in step 8 passed because dev_open_* let
-- them, not because the policies work. Production is the only place they have
-- ever been live.
--
-- Confirmed by probe, 22 Aug 2026, publishable key and no session:
--
--     POST /rest/v1/shift_requests -> 201, row created (prod: 401, 42501)
--     DELETE the same row          -> 200, row deleted (prod: 401, 42501)
--     POST {} to all four tables   -> 400 23502 not-null, i.e. permitted
--                                     (prod: 401 42501 on all four)
--
-- A 23502 rather than a 42501 is the tell: PostgREST checks privileges before
-- constraints, so reaching a not-null violation means the write was allowed and
-- failed only on its contents.
--
-- WHAT THIS COSTS. Single-phone testing on dev ends. After this migration an
-- unlinked waiter on dev is read-only, exactly as on production, so testing a
-- waiter write requires completing an invite on that browser profile first.
-- That is the cost of dev telling the truth, and it is the cost dev/013 was
-- avoiding. It is worth paying now only because step 7 is the outstanding work
-- and step 7 cannot be validated against a database that says yes to everyone.
--
-- WHAT THIS DOES NOT TOUCH. Reads stay wide open on both projects — anonymous
-- SELECT of names, colours, patterns and schedules is Stage D's problem, and
-- 015's *_read policies keep it working identically here. The owner's session
-- is unaffected: cafes_owner_all, waiters_owner_all, sr_owner_all and
-- ds_owner_all are all TO authenticated and gated on ownership, and 015 already
-- created them on dev.

BEGIN;

-- ── 1. The blanket policies ─────────────────────────────────────────────────
-- Named dev_open_* by dev/010 "precisely so they are impossible to mistake for
-- production policy". Taking that at its word. Dropped by name rather than by
-- loop so that this file states exactly what it removed; IF EXISTS so a partial
-- earlier cleanup cannot abort the migration.

DROP POLICY IF EXISTS dev_open_cafes          ON public.cafes;
DROP POLICY IF EXISTS dev_open_waiters        ON public.waiters;
DROP POLICY IF EXISTS dev_open_shift_requests ON public.shift_requests;
DROP POLICY IF EXISTS dev_open_date_schedules ON public.date_schedules;

-- ── 2. Migration 003's write revokes, replayed ──────────────────────────────
-- Undoes dev/010 line 127, which granted SELECT, INSERT, UPDATE, DELETE on all
-- four tables to anon and authenticated in one statement.
--
-- Only anon loses write here. authenticated keeps table-level CRUD on purpose:
-- the owner needs it, and 015 is what confines the role — RLS for rows, column
-- grants for columns. See trap 6, "a role is not an identity".

REVOKE INSERT, UPDATE, DELETE ON public.cafes          FROM anon;
REVOKE INSERT, UPDATE, DELETE ON public.waiters        FROM anon;
REVOKE INSERT, UPDATE, DELETE ON public.shift_requests FROM anon;
REVOKE INSERT, UPDATE, DELETE ON public.date_schedules FROM anon;

-- ── 3. Residual privileges, defensively ─────────────────────────────────────
-- 011 ran against dev on 17 Aug and should have cleared these. dev/013 ran
-- afterwards and issues no GRANT ALL, so nothing ought to have come back. This
-- is belt and braces: a REVOKE of a privilege that is already absent is a
-- no-op, and trap 5 is that these are invisible unless you go looking.

REVOKE TRUNCATE, TRIGGER, REFERENCES
  ON public.cafes, public.waiters, public.shift_requests, public.date_schedules
  FROM anon, authenticated, PUBLIC;

COMMIT;


-- ── VERIFY ──────────────────────────────────────────────────────────────────
--
-- Never trust the green Success. Every check below must be run against BOTH
-- projects, and both must answer identically — that is the whole point of the
-- migration. Dev's publishable key is in osmica.html line 1118, production's on
-- line 1114.
--
-- 1. The blanket policies are gone and only 015's remain:
--
--      select tablename, policyname, roles, cmd from pg_policies
--      where schemaname = 'public' order by tablename, policyname;
--      -- expect: no policy whose name begins dev_open_
--      -- expect: 10 policies, matching production exactly —
--      --   cafes_read, cafes_owner_all, waiters_read, waiters_owner_all,
--      --   sr_read, sr_owner_all, sr_waiter_insert, sr_waiter_update,
--      --   ds_read, ds_owner_all
--
-- 2. anon holds SELECT and nothing else. waiters shows no row at all, because
--    its SELECT is column-level from dev/013 rather than table-level — correct,
--    not a missing grant:
--
--      select grantee, table_name, privilege_type
--      from information_schema.table_privileges
--      where table_schema = 'public' and grantee in ('anon','authenticated')
--      order by table_name, grantee, privilege_type;
--      -- expect anon:          SELECT on cafes, date_schedules, shift_requests
--      -- expect authenticated: SELECT, INSERT, UPDATE, DELETE on all four
--      -- expect nowhere:       TRUNCATE, TRIGGER, REFERENCES
--
-- 3. The probe that motivated this file, re-fired. An empty body creates no row
--    either way, so this is safe to run against both projects:
--
--      U=https://simavghwjnqytcyeunto.supabase.co/rest/v1
--      K=<dev publishable key>
--      for t in cafes waiters shift_requests date_schedules; do
--        printf "%-16s %s\n" "$t" \
--          "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$U/$t" \
--             -H "apikey: $K" -H "Authorization: Bearer $K" \
--             -H "Content-Type: application/json" -d '{}')"
--      done
--      -- expect: 401 on all four, code 42501, on dev AND production
--      -- a 400 with code 23502 means the write was PERMITTED and this
--      --   migration did not land
--
-- 4. Reads must be untouched — this migration is not Stage D:
--
--      ?select=name,color -> 200     ?select=phone        -> 401
--      ?select=invite_token -> 401   ?select=*            -> 401
--
-- 5. The app, end to end on dev, in this order. 5a and 5b are regressions this
--    file could plausibly cause; 5c and 5d are the checks that were previously
--    impossible and are the reason for running it at all:
--
--    5a. Owner signs in, edits the roster, saves. Must work — if it does not,
--        an owner policy from 015 is missing on dev, not a fault of this file.
--    5b. Eva (already linked on dev) raises a swap request. Must work: she is
--        authenticated with an anonymous session, so sr_waiter_insert admits
--        her. This is the first genuine test sr_waiter_insert has ever had.
--    5c. A PIN-only waiter, never invited, tries to raise a request. Must FAIL.
--        Before this migration it succeeded, which is the bug.
--    5d. Eva tries to raise a request naming a different waiter_id in the body.
--        Must fail — sr_waiter_insert checks waiter_id against 014's binding,
--        not against what the client sends.
--
-- ── ROLLBACK ────────────────────────────────────────────────────────────────
--
-- If this makes dev unusable before real devices are available, dev/010's
-- policies can be recreated — but restore them as a deliberate, dated act,
-- never as a reflex, and re-read the top of this file first:
--
--   DO $$
--   DECLARE t text;
--   BEGIN
--     FOREACH t IN ARRAY ARRAY['cafes','waiters','shift_requests','date_schedules']
--     LOOP
--       EXECUTE format(
--         'CREATE POLICY dev_open_%s ON public.%I FOR ALL TO anon, authenticated USING (true) WITH CHECK (true)',
--         t, t);
--     END LOOP;
--   END $$;
--   GRANT INSERT, UPDATE, DELETE
--     ON public.cafes, public.waiters, public.shift_requests, public.date_schedules
--     TO anon;
--
-- Doing so returns dev to answering "yes" for everyone, and step 7 becomes
-- untestable again.
