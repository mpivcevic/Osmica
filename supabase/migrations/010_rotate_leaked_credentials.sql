-- 008 — Rotate the credentials that were world-readable.
--
-- Until 005/006, `pin_hash` and `invite_token` were readable by anyone holding
-- the publishable key, which ships in the page. They were exposed for months.
-- bcrypt over a 4-digit PIN is a 10,000-key space: anyone who took a copy has
-- had every PIN in plaintext since the moment they grabbed it. Closing the read
-- (006) does not un-leak what was already taken. The values themselves must be
-- treated as public and replaced.
--
-- This rotates BOTH credentials in one move by putting every waiter back through
-- the invite flow they already have:
--
--   invite_token  -> fresh uuid            (old links die)
--   pin_hash      -> NULL                  (old PINs stop working)
--   joined_at     -> NULL                  (new link opens in PIN-setup mode)
--
-- No new UI is needed. claim_invite() keys on the token, and a row with
-- joined_at NULL is exactly what puts the setup screen into "choose a PIN" mode
-- (osmica.html:1856 -> set_waiter_pin -> mark_invite_joined).
--
-- ⚠️  DESTRUCTIVE AND IMMEDIATE. On COMMIT every waiter is logged out of the
--     keypad and cannot get back in until they open a NEW invite link. Do not
--     run this mid-shift. Have the five WhatsApp messages ready to send first —
--     the SELECT at the bottom prints them.
--
-- ⚠️  Run 007 (rate limit) BEFORE this one. Rotating into an unthrottled
--     10,000-guess endpoint means doing this twice. 004 is superseded by 007
--     and should not be run.
--
-- Owners are unaffected: they authenticate through Supabase Auth (email +
-- password), not through any of this.

BEGIN;

-- Belt and braces: never touch more than the one production café by accident.
-- If this returns more rows than you expect, ROLLBACK.
SELECT id, name FROM public.cafes;

UPDATE public.waiters
SET invite_token = gen_random_uuid()::text,
    pin_hash     = NULL,
    joined_at    = NULL;

COMMIT;

-- The new invite links. Send one to each waiter over WhatsApp.
-- Anyone holding an old link now has a dead link.
-- NOTE the explicit `osmica.html`. The bare directory URL does NOT work:
-- index.html is a <meta http-equiv="refresh" url="osmica.html"> and a meta
-- refresh drops the query string, so /osmica/?invite=… arrives at the app with
-- no token and boots to the home screen. Cost one confusing round of debugging
-- on 17 Aug. The app's own invite buttons are fine — osmica.html:1986 builds
-- them from location.pathname, which already includes osmica.html.
SELECT name,
       phone,
       'https://mpivcevic.github.io/osmica/osmica.html?invite=' || invite_token AS invite_url
FROM public.waiters
ORDER BY name;

-- Afterwards, confirm the leak is actually closed — with the publishable key and
-- no session, these must all 401:
--   ?select=pin_hash      ?select=invite_token      ?select=*
--
-- And confirm the rotation landed: no waiter should still hold a PIN.
--   SELECT count(*) FROM public.waiters WHERE pin_hash IS NOT NULL;  -- expect 0
