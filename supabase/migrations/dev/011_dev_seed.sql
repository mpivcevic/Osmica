-- 011 — Fake staff for the dev café. RUN THIS AGAINST DEV ONLY.
--
-- Run AFTER you have signed up in the app over the tunnel and completed café
-- setup — the app creates the café row itself, so there is no point seeding
-- one here and then fighting it. This only adds staff to whatever café exists.
--
-- Names are deliberately invented. Nothing in dev should resemble the real
-- team, so that a screenshot or a shared demo link can never expose a real
-- person's name, phone number or shift pattern.
--
-- Safe to re-run: it deletes and recreates only these five seeded rows.

BEGIN;

DO $$
DECLARE
  v_cafe uuid;
BEGIN
  SELECT id INTO v_cafe FROM public.cafes ORDER BY created_at LIMIT 1;

  IF v_cafe IS NULL THEN
    RAISE EXCEPTION
      'No café exists yet. Sign up in the app over the tunnel and finish café setup first, then re-run this.';
  END IF;

  DELETE FROM public.waiters
  WHERE cafe_id = v_cafe
    AND name IN ('Ana Anić','Bruno Barić','Cvita Cvitić','Duje Dujić','Eva Evec');

  INSERT INTO public.waiters (cafe_id, name, phone, color, pattern, joined_at) VALUES
    -- Works mornings Mon-Fri. Already "joined", so the login path is testable.
    (v_cafe, 'Ana Anić',     '385991110001', '#2563eb',
     '{"m":[1,1,1,1,1,0,0],"s":[0,0,0,0,0,0,0],"a":[0,0,0,0,0,0,0]}'::jsonb, now()),
    -- Afternoons Mon-Fri.
    (v_cafe, 'Bruno Barić',  '385991110002', '#7c3aed',
     '{"m":[0,0,0,0,0,0,0],"s":[0,0,0,0,0,0,0],"a":[1,1,1,1,1,0,0]}'::jsonb, now()),
    -- Mid-shifts plus weekend mornings.
    (v_cafe, 'Cvita Cvitić', '385991110003', '#db2777',
     '{"m":[0,0,0,0,0,1,1],"s":[1,1,1,1,1,0,0],"a":[0,0,0,0,0,0,0]}'::jsonb, now()),
    -- Weekend cover only.
    (v_cafe, 'Duje Dujić',   '385991110004', '#16a34a',
     '{"m":[0,0,0,0,0,1,1],"s":[0,0,0,0,0,0,0],"a":[0,0,0,0,1,1,0]}'::jsonb, now()),
    -- Deliberately left un-joined (joined_at NULL) so the invite and
    -- PIN-setup flow always has a fresh subject to test against.
    (v_cafe, 'Eva Evec',     '385991110005', '#d97706',
     '{"m":[1,0,1,0,1,0,0],"s":[0,1,0,1,0,0,0],"a":[0,0,0,0,0,0,0]}'::jsonb, NULL);

  RAISE NOTICE 'Seeded 5 waiters into café %', v_cafe;
END $$;

COMMIT;

-- Every seeded waiter except Eva has joined but has no PIN yet, so their first
-- login goes through PIN setup. To give them working PINs instead:
--
--   SELECT public.set_waiter_pin(w.id, v.pin)
--   FROM public.waiters w
--   JOIN (VALUES
--     ('Ana Anić',     '1111'),
--     ('Bruno Barić',  '2222'),
--     ('Cvita Cvitić', '3333'),
--     ('Duje Dujić',   '4444')
--   ) AS v(name, pin) ON v.name = w.name;
--
-- Give them DISTINCT PINs, not one shared value. login_waiter_by_pin() matches
-- a PIN against every waiter in the café and returns the first hit, so four
-- waiters sharing '1111' means the keypad always logs you in as whoever sorts
-- first — which looks like a bug but is really the enumeration hole showing
-- through. Stage C removes that function and this stops mattering.
