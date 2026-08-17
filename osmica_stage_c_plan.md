# Stage C — Give waiters a real identity

Written 17 Aug 2026, overnight, against the state left by Stages A and B.
Nothing in this document has been applied or tested. It is a design.

---

## The problem in one paragraph

Owners authenticate through Supabase Auth and arrive with a JWT, so the database
knows who they are. Waiters do not. Every waiter request runs as `anon`, and the
only thing separating one waiter from another is a 4-digit PIN that the *server*
checks — which means the PIN is a network credential, guessable in 10,000 tries,
and `login_waiter_by_pin(cafe_id, pin)` will happily tell an attacker *which*
waiter they just became. Stage A made that expensive (rate limiting) and stopped
the credentials leaking. It could not make it stop being the design.

Stage C replaces it: every waiter gets a real Supabase identity bound to their
device, and the PIN stops being something the network will answer questions
about.

## What it fixes, concretely

| today | after Stage C |
|---|---|
| A stolen invite link + PIN works from any device | The credential lives in one browser; a forwarded link is inert |
| `login_waiter_by_pin` maps café + PIN → a waiter, so you needn't know whose PIN you're guessing | The function no longer exists |
| PIN is 10,000 guesses against the network | PIN never leaves the device |
| Waiters have no `auth.uid()`, so RLS cannot express "your own rows" | Every waiter has one — Stage D becomes writable |

That last row is the real prize. **Stage D is impossible until this lands**, and
Stage D is what closes the remaining read exposure.

---

## The design

A waiter opening an invite link calls `signInAnonymously()`. Supabase issues a
real user with a real JWT and a device-scoped refresh token stored in that
browser. `link_waiter_to_auth(token)` then binds that user id to the waiter row
and consumes the invite token.

From then on the waiter is authenticated to the database as themselves, on that
device, indefinitely — the refresh token renews silently.

The PIN becomes a **local unlock**: a gate on the app in that browser, checked
against a hash in local storage, never sent anywhere. This is the model banking
apps use, and it keeps the 4-digit UX that suits a phone behind a bar.

### Be honest about what the PIN then is

Once the PIN is a local check, **it is no longer a security boundary.** Anyone
holding the unlocked phone can bypass it with devtools, because the session that
actually authenticates is sitting in the same browser storage. It protects
against a colleague picking up your phone, not against an attacker who has it.

That is a *downgrade* in what the PIN protects and an *upgrade* in overall
security, and both halves are true. The thing that protects the account becomes
possession of the device, which is a far better credential than four digits.
Worth saying out loud so nobody later assumes the PIN is doing more than it is.

---

## Four steps, in order

Same discipline as Stage A: additive first, destructive last, each step verified
before the next.

### C1 — Add the identity column and the linking function *(additive, zero risk)*

`migrations/014_stage_c_waiter_identity.sql`, already written.

- `waiters.auth_user_id uuid UNIQUE` referencing `auth.users`
- `link_waiter_to_auth(p_token text)`, `SECURITY DEFINER`, reads `auth.uid()`
  from the caller's JWT, binds it to the waiter row matching the token, and
  rotates the invite token so it cannot be reused

Changes nothing that exists. The app does not call it yet.

**Requires a dashboard setting:** Authentication → Providers → *Anonymous
sign-ins* must be enabled, on both projects. Without it `signInAnonymously()`
returns an error and C2 silently does nothing.

### C2 — Waiters start signing in *(additive; the app still works exactly as now)*

Build v4.37, written on branch `stage-c`.

On completing an invite, after the PIN is set, the client calls
`signInAnonymously()` and then `link_waiter_to_auth(token)`. **Failure is
non-fatal** — it logs and continues, because the PIN login path is untouched and
still works. So a waiter whose linking fails is not locked out; they simply have
no identity yet and can be re-invited.

This step gives waiters identities without changing a single user-visible
behaviour. Nothing depends on the identity yet.

**One mandatory guard ships with it.** `init()` at `osmica.html:1389` calls
`sb.auth.getSession()` and routes *any* session into `enterOwnerApp()`. An
anonymously signed-in waiter has a session. Without a guard, every linked waiter
lands in the owner's admin panel — with the owner's column grants — on their next
app open. The guard is `!session.user.is_anonymous`, and it is not optional or
deferrable.

### C3 — The PIN moves to the device *(behavioural change)*

- PIN entry checks a locally stored hash (WebCrypto, PBKDF2) instead of calling
  `verify_waiter_pin`
- A linked waiter with a valid session skips café + PIN resolution entirely; the
  app knows who they are from the JWT
- `pin_hash` stops being written

Do not start C3 until every active waiter is linked. A waiter without
`auth_user_id` has no session to unlock, so for them C3 removes the only way in.
Query before starting:

```sql
select name, auth_user_id is not null as linked from public.waiters order by name;
```

### C4 — Remove the old surface *(destructive, irreversible)*

Once every waiter is linked and C3 is live:

- `DROP FUNCTION login_waiter_by_pin` — the enumeration oracle
- `DROP FUNCTION verify_waiter_pin` — the second oracle
- `DROP TABLE pin_attempts` — the rate limiter exists only to protect those two
- `ALTER TABLE waiters DROP COLUMN pin_hash` — nothing reads it
- `DROP FUNCTION is_pin_locked` and remove `pinFailureMessage()` from the client

After C4, the entire "guess a PIN, discover who you became" surface is gone, and
migration 009 can be deleted from the repo as historical.

---

## Consequences you should decide on, not discover

### 1. One device per waiter

An anonymous session lives in one browser. A waiter who wants the app on a phone
*and* a tablet needs two invites, and would be two `auth_user_id`s — which the
`UNIQUE` constraint forbids on one row.

**Options:** accept one device each (simplest, matches "personal devices only");
or drop `UNIQUE` and allow several identities per waiter (more moving parts, and
Stage D's policies get slightly harder).

**My recommendation:** accept one device. Add the second only when someone asks.

### 2. Clearing browser data means a re-invite

There is no self-service recovery any more. Today a waiter reopens their invite
link and enters their PIN. After Stage C the link is consumed and the PIN is
local, so both are gone with the browser data.

The owner reissues from the admin panel — which already has the 💬 button — and
the waiter sets a new PIN. That is a one-minute fix for the owner and no worse
than a forgotten password, but it does mean **the owner must be reachable.**

**Alternative:** keep a server-side recovery path (waiter proves identity with a
PIN, gets re-bound). That reintroduces exactly the oracle C4 deletes. Not
recommended.

### 3. It degrades the dev identity switcher

Today the switcher (v4.30) becomes any waiter on one phone by writing a local
override. After C3 that stops being enough — becoming a waiter means holding
*their* session, and one browser holds one anonymous identity.

The switcher still works for the owner and for pre-C3 flows, but per-waiter
switching on a single device conflicts with the entire point of device binding.

**Options:** accept that dev testing needs several browser profiles (private
windows work); or keep the switcher working on dev only, by leaving the PIN path
alive there. Dev already diverges deliberately on anonymous writes, so one more
documented divergence is defensible.

**My recommendation:** private windows. Adding a second permanent divergence to
dev to preserve a convenience is how dev stops being a faithful test of
production.

### 4. Anonymous users are real users

They count toward the project's user total and appear in Authentication → Users.
Six waiters is nothing, but a bug that signs in on every page load would create
thousands. The linking call happens **once**, on invite completion, and the guard
is that a waiter with a session never reaches it.

---

## What Stage C does *not* fix

Anonymous reads of names, colours, shift patterns and schedules stay open. Stage
C only creates the identities; **Stage D writes the policies that use them.**
Doing C without D leaves the exposure exactly where it is today — so C is only
worth doing as the first half of a pair.

---

## Verification, per step

Never on the strength of the app still working — that proves the policies are not
too tight, not that they are tight enough.

- **C1** — `select set_waiter_pin_by_token` unaffected; `link_waiter_to_auth`
  with no session returns `no_session`; with a bad token returns `invalid_token`.
- **C2** — complete an invite on dev, then
  `select name, auth_user_id from waiters where name like 'Eva%'` shows a uuid.
  Then **close and reopen the app**: the waiter must land on the waiter screen,
  not the owner's. That single check is what proves the `is_anonymous` guard.
- **C3** — a linked waiter opens the app offline and unlocks with the PIN; the
  network is never asked.
- **C4** — `POST /rpc/login_waiter_by_pin` returns 404.

---

## Where this leaves the threat model

After C and D, someone who reads the whole source, extracts the publishable key
and pokes at the API can enumerate nothing, read nothing and write nothing. The
key becomes what it was always meant to be: routing, not authorisation.

The remaining risks are the ordinary ones — a stolen unlocked phone, a
compromised owner email — and Stage E addresses those with 2FA and login alerts.
