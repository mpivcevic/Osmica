-- 003 — Close the worst hole: anonymous writes.
--
-- Probed 13 Aug 2026 with nothing but the publishable key: anonymous PATCH and
-- DELETE both returned 204, meaning accepted and executed. They affected no
-- rows only because the probe filtered on a UUID that does not exist. As it
-- stands, anyone can delete the café, the roster and every schedule.
--
-- Owners are unaffected: they hold a Supabase Auth session and act as
-- `authenticated`, not `anon`.
--
-- KNOWN REGRESSION: waiters have no session yet, so creating and updating swap
-- requests stops working until Stage C gives them an identity. shift_requests
-- currently holds 0 rows, so nothing in flight is lost. If that is not
-- acceptable, say so and the two paths get a SECURITY DEFINER bridge instead —
-- throwaway work that Stage C deletes.

BEGIN;

REVOKE INSERT, UPDATE, DELETE ON public.cafes          FROM anon;
REVOKE INSERT, UPDATE, DELETE ON public.waiters        FROM anon;
REVOKE INSERT, UPDATE, DELETE ON public.shift_requests FROM anon;
REVOKE INSERT, UPDATE, DELETE ON public.date_schedules FROM anon;

-- set_waiter_pin is SECURITY DEFINER and stays callable: a waiter setting their
-- PIN from an invite link is still anonymous at that moment. Looked up by name
-- rather than hardcoded, because the exact argument types were never verified
-- and a wrong signature would abort this whole migration.
DO $$
DECLARE fn record;
BEGIN
  FOR fn IN
    SELECT p.oid::regprocedure AS sig
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND p.proname IN ('set_waiter_pin', 'verify_waiter_pin')
  LOOP
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO anon', fn.sig);
  END LOOP;
END $$;

COMMIT;

-- Verify — this must now fail with 401/403 rather than 204:
--   curl -X DELETE -H "apikey: <publishable>" \
--     "<url>/rest/v1/waiters?id=eq.00000000-0000-0000-0000-000000000000"
