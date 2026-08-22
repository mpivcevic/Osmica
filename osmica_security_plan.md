# Osmica — Security Plan

> ⚠️ **Read this first — written 13 Aug 2026 and now partly historical.**
> This is the *plan*, not the *status*. Section 1 ("What is actually true right
> now") describes the world before any migration was applied: it says anonymous
> writes are open on all four tables and lists five waiters. None of that is
> still true. Stages A, B and C1-C2 are complete and verified on both projects.
>
> For current state, in this order:
> 1. `TaskList_2026-08-17.md` — the Stage C record, closed 22 Aug 2026
> 2. `osmica_stage_c_plan.md` — C3 and C4 scope, not yet built
> 3. `supabase/migrations/README.md` — what is applied where, and the trap list
>
> **Stage D is narrower than described below.** Migration `015` already enabled
> RLS on all four tables and wrote the owner and waiter policies. What remains is
> the four `*_read` policies, which are deliberately `TO anon, authenticated
> USING (true)`, and the residual anon SELECT grants — and closing them properly
> depends on C4 removing the PIN login path, because until then a waiter with no
> session still has to render the café and roster before authenticating.

Written 13 Aug 2026. Supersedes the deferred backlog from 10 Aug.
All findings below were re-probed live against the production project today,
read-only except two write probes whose filters matched zero rows.

---

## 1. What is actually true right now

Probed with nothing but the publishable key that ships in `osmica.html` — no
login, no session, no privileged access.

| Table | Anon read | Anon write | Notes |
|---|---|---|---|
| `cafes` | yes | yes | 1 row |
| `waiters` | yes | yes | 5 rows — includes `pin_hash`, `invite_token`, `phone` |
| `shift_requests` | yes | yes | 0 rows |
| `date_schedules` | yes | yes | 0 rows |

The write result is new. On 10 Aug writes were listed as untested. They are now
confirmed open: anonymous `PATCH` and `DELETE` both return `204`, meaning the
statement was accepted and executed — it touched no rows only because the probe
filtered on a UUID that does not exist. In practice, anyone holding the key can
rewrite or delete every row in the database.

Consequences, in order of severity:

1. **Anonymous destructive writes.** The café, all five waiters, and all
   schedules can be deleted or altered by anyone. No login required.
2. **`invite_token` is readable.** For any waiter with `joined_at` null it grants
   PIN-setup mode, i.e. direct account takeover.
3. **`pin_hash` is readable.** bcrypt over a 4-digit PIN is a 10,000-key space —
   crackable offline in minutes on a laptop.
4. **`phone` is readable.** Personal data of real employees, GDPR-relevant.
5. **PIN is the entire credential.** `zm_b_cafe_id` in localStorage is what makes
   the keypad appear and is a non-secret anyone can set from the console.
   `login_waiter_by_pin(cafe_id, pin)` then resolves café + PIN straight to a
   waiter — you don't need to know whose PIN you're guessing.

Treat every existing PIN and invite token as already compromised. They have been
world-readable for months. Rotating them is part of the plan below.

## 2. What is *not* a problem

**The key in `osmica.html` is fine.** `sb_publishable_…` is designed to be public
and ships in every Supabase browser app on the internet. Hiding it is neither
possible nor the point. I checked the full git history: no `service_role` key and
no JWT-format secret has ever been committed, so there is nothing to rotate and
no history to rewrite.

The key is a *routing* credential, not an authorisation one. Everything above is
caused by the database granting anonymous full CRUD behind it. **Row Level
Security is the only thing that was ever supposed to be protecting this**, and it
is off.

This is also why making the repo private would have changed nothing.

## 3. The order that matters

The instinct is "lock the database down first, fix auth after." That is the wrong
order here, and it costs you a build's worth of throwaway work.

The app makes 18 direct table calls and only 3 RPC calls:

```
waiters         select ×3, update ×2, insert, delete
cafes           select ×3, update, insert
shift_requests  select ×2, update ×2, insert
date_schedules  select, upsert
rpc             verify_waiter_pin ×2, set_waiter_pin, login_waiter_by_pin
```

Owners are signed into Supabase Auth, so their calls already carry a JWT and
already have `auth.uid()`. **Owner-side RLS works the day you write the
policies.** Waiters have no session at all — every waiter call runs as `anon`.

So if you enable RLS before giving waiters an identity, every waiter path breaks,
and the only way to keep the app running is to wrap six or so read/write paths in
`SECURITY DEFINER` functions — which you then delete once waiters have real
identities. Give waiters identity *first* and the plain RLS policies cover them.

The one exception is Stage A, which is free and doesn't wait for anything.

---

## Stage A — Quick wins (a few hours, no architecture change)

Do these first regardless of everything else.

**A1. Stop shipping `pin_hash` to the browser.**
The client never uses it — it arrives only because three calls do `select('*')`.

1. Replace the three `from('waiters').select('*')` with an explicit column list
   (`id, cafe_id, name, phone, color, pattern, vacations, joined_at, created_at`).
2. Then in SQL: `REVOKE SELECT (pin_hash) ON waiters FROM anon;`

Order matters — revoke first and `select('*')` starts erroring.

**A2. Get `invite_token` out of anonymous reach.**
Used in three places. Line 1710 filters on it to claim an invite (anon path);
lines 2702 and 2834 read it to build invite URLs (owner path).

1. Move the line-1710 lookup into a `SECURITY DEFINER` function
   `claim_invite(token uuid)` that returns only the fields the setup screen needs.
   This one is *not* throwaway — Stage C uses it too.
2. Leave 2702/2834 alone; they become legitimate once owner RLS lands, since an
   owner may see tokens for their own café.
3. Then: `REVOKE SELECT (invite_token) ON waiters FROM anon;`

**A3. Kill anonymous writes.**
```sql
REVOKE INSERT, UPDATE, DELETE ON cafes, waiters, shift_requests, date_schedules FROM anon;
```
This closes the worst hole immediately. It breaks exactly one live waiter
feature — creating and updating swap requests — which is acceptable for a few
days, or can be bridged with one `SECURITY DEFINER` function if you'd rather not
regress. Owner writes are unaffected: they run as `authenticated`.

**A4. Rate-limit `login_waiter_by_pin`.**
A 4-digit PIN with unlimited attempts is a 10,000-guess brute force. Add a
per-café attempt counter with a lockout window inside the function.

**A5. Rotate what has already leaked.** After A1–A3: regenerate every invite token
and have all five waiters set new PINs.

## Stage B — Split production from development

This is what makes the rest of your workflow safe, and it unblocks both things
you asked for.

Right now there is one Supabase project and the credentials are hardcoded, so a
tunnel session on your laptop is talking to the real café's data. That is how you
lose production data to a test.

**B1.** Create a second Supabase project, `osmica-dev`. Free tier allows two.
**B2.** Apply the same schema. Seed a fake café with fake waiters.
**B3.** Pick the backend by hostname instead of hardcoding it:

```js
const IS_PROD = location.hostname === 'mpivcevic.github.io';
const SUPA = IS_PROD
  ? { url: 'https://vuvvzzktrxydfxgxugke.supabase.co', key: 'sb_publishable_…' }
  : { url: 'https://<dev-ref>.supabase.co',            key: 'sb_publishable_…' };
const sb = supabase.createClient(SUPA.url, SUPA.key);
```

Both keys are publishable, so both can sit in the file. The property this buys
you: **localhost and every tunnel URL automatically hit dev**, and it is
structurally impossible to mutate production from a test session. No env files,
no build step, nothing to remember.

**B4.** In the dev project's Auth settings, add `http://localhost:*` and your
tunnel domain to the redirect allowlist, so password-reset and confirmation
links work over the tunnel. Leave the production allowlist tight.

## Stage C — Give waiters a real identity

The core fix. Reframes the PIN from *network credential* to *local unlock for a
device-bound credential* — the banking-app model — which keeps the 4-digit UX.

**C1.** Waiter opens invite link → `signInAnonymously()` → real JWT plus a
device-scoped refresh token.
**C2.** `claim_invite()` from A2 links `auth.uid()` to `waiters.auth_user_id` and
marks the token consumed.
**C3.** PIN moves to a local unlock check against the device's stored session. It
stops being a thing the network will answer questions about.
**C4.** Delete `login_waiter_by_pin`. Once it's gone there is nothing left to
enumerate.

This solves three problems at once: device binding, working RLS for waiters (they
finally have an `auth.uid()`), and removal of the enumeration surface.

**Known trade-offs — your call:**
- Invite links become single-use. Today they're reusable, which is exactly how the
  invite-recovery path works. That path needs redesigning.
- Clearing browser data means a re-invite.
- **A shared device behind the bar stops working.** See the open question below.

## Stage D — RLS everywhere

Now that both roles have `auth.uid()`, the policies are simple.

```sql
ALTER TABLE cafes           ENABLE ROW LEVEL SECURITY;
ALTER TABLE waiters         ENABLE ROW LEVEL SECURITY;
ALTER TABLE shift_requests  ENABLE ROW LEVEL SECURITY;
ALTER TABLE date_schedules  ENABLE ROW LEVEL SECURITY;
```

- **Owner** — full access where `cafes.owner_id = auth.uid()`, and on the child
  tables where `cafe_id` belongs to a café they own.
- **Waiter** — read their own café's roster and schedule; write only rows where
  `waiter_id = (select id from waiters where auth_user_id = auth.uid())`.

Verify by re-running the probes from section 1. Every one should come back `401`
or empty. **Do not consider this stage done on the basis of the app still
working** — the app working proves the policies aren't too tight, not that
they're tight enough.

## Stage E — Hardening

- TOTP 2FA for owners (Supabase native).
- Email on new-device owner login.
- Single-use, expiring invite tokens.
- Consider dropping `phone` if the WhatsApp flow can take it at send time —
  the cheapest way to hold less personal data is not to store it.

---

## Sending it to Dottore

Once Stage B exists this is easy and safe. Point him at a deployment backed by
`osmica-dev` with seed data, not production. He gets a real, clickable app; the
café's actual roster, phone numbers and PINs are in a different database he has
no key for.

Do **not** do this before Stage B. Handing out the production URL today means
handing out anonymous delete rights over the real café.

Three ways to host the demo, cheapest first:

1. **Query param** — `?demo=1` forces the dev backend. One line on top of B3.
   Anyone can flip it, which is harmless.
2. **Separate Pages deployment** from a `demo` branch. Cleaner URL, slightly more
   to maintain.
3. **Offline demo mode** — no backend at all, in-memory fixtures. Most work, but
   note you already had this: the deleted `zamijeni_me.html` prototype was a
   working localStorage-only build, recoverable from git at `86d138f^`.

Recommendation: option 1. It costs a line and is impossible to get wrong.

---

## Decision points

Two things genuinely change the design, and I'd rather ask than guess.

**1. Is the shared-device case real?** Is there — or will there be — a tablet
behind the bar that the whole team uses? Or is the current PIN-only screen just
an incidental fallback from the prototype?

If shared devices are real, device-bound credentials in Stage C don't fit as
described, and the model becomes one kiosk identity plus per-person PIN unlock,
which is a meaningfully weaker and differently-shaped design. This decides Stage C
and is hard to reverse later.

**2. How much regression is acceptable during the fix?** A3 breaks waiter swap
requests until Stage C lands. With one real café and zero rows currently in
`shift_requests`, my read is that you can take the regression and skip the
throwaway bridge. If waiters are actively using it this week, say so and I'll
write the bridge instead.

## Suggested order

| | Stage | Effort | Unblocks |
|---|---|---|---|
| 1 | A1–A3 quick wins | hours | closes destructive writes + credential leak |
| 2 | B environment split | hours | safe tunnel dev, Dottore demo |
| 3 | A4, A5 rate limit + rotate | hours | brute force, already-leaked creds |
| 4 | C waiter identity | a build | the real fix |
| 5 | D RLS everywhere | a build | isolation between cafés |
| 6 | E hardening | ongoing | |

Stages 1 and 2 together are roughly one working session and remove every finding
that would actually hurt you today.
