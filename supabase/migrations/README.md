# Migrations

Applied by hand in the Supabase SQL Editor. There is no migration runner, so
these numbers are documentation rather than instructions — Postgres never sees
them. They exist so a file can be named unambiguously in conversation and in a
commit message.

## Numbering rule

**One shared counter across both databases. Never reuse a number.**

The next migration takes the next free number regardless of which project it
targets. As of 17 Aug 2026 the high-water mark is `014`, so the next file —
production or dev — is `015`.

Production's sequence will therefore have gaps. That is expected: a gap means
that number went to dev.

- Production migrations live in `migrations/`
- Dev migrations live in `migrations/dev/` **and carry `dev` in the filename**

Both, so that neither the folder nor the name alone has to carry the meaning.

### The two historical collisions

Before this rule, each project numbered independently, and two numbers mean
different things depending on the folder:

| number | `migrations/` | `migrations/dev/` |
|---|---|---|
| `010` | rotate leaked credentials | dev schema |
| `011` | revoke residual privileges | dev seed |

Left as they are, deliberately — renaming applied migrations breaks the link to
the commits and notes that reference them. When referring to either number, say
which folder.

## What is applied where

Verified by probing with the publishable key and no session, not by trusting the
SQL editor's success message.

### `migrations/` — `osmica-production` (`vuvvzzktrxydfxgxugke`)

| | file | state |
|---|---|---|
| 001 | claim_invite RPC | ✅ applied |
| 002 | revoke anon columns | ⚠️ ran clean, **did nothing** — superseded by 005 |
| 003 | revoke anon writes | ✅ applied |
| 004 | rate limit PIN login | ❌ **never run — superseded by 009** |
| 005 | fix anon column grants | ✅ applied |
| 006 | revoke anon phone | ✅ applied |
| 007 | token-keyed set_waiter_pin | ✅ applied |
| 008 | drop insecure set_waiter_pin | ✅ applied |
| 009 | rate limit both PIN oracles | ✅ applied |
| 010 | rotate leaked credentials | ✅ applied |
| 011 | revoke residual privileges | ✅ applied 17 Aug — mark_invite_joined confirmed gone on both |
| 014 | Stage C1: waiter identity (`auth_user_id`, `link_waiter_to_auth`) | ❌ **not run** — additive; needs Anonymous sign-ins enabled first |

### `migrations/dev/` — osmica-dev (`simavghwjnqytcyeunto`)

| | file | state |
|---|---|---|
| 010 | dev schema | ✅ applied |
| 011 | dev seed | ✅ applied |
| 012 | token-keyed set_waiter_pin (dev variant) | ✅ applied |
| 013 | align dev with production | ✅ applied |

Production's `009`, `011` and `014` are also run against dev — they are not
dev-specific, so they get no dev-numbered file.

## Two files that are kept on purpose despite never being run

**`002`** reports success and achieves nothing. A column-level
`REVOKE SELECT (col) ... FROM anon` cannot subtract from a table-level grant,
which the role already held. The working shape is `REVOKE SELECT ON t FROM anon,
PUBLIC` followed by `GRANT SELECT (safe, cols) ON t TO anon`, which is what 005
and 006 do.

**`004`** would have made things worse in a way that reads as correct: it
throttles only one of the two PIN entry points, never decays its counter (so a
café accumulating one fumbled PIN a week eventually locks itself out forever),
and leaves its helper functions `EXECUTE`-able by `PUBLIC` — meaning
`register_pin_failure` becomes a café-lockout button for anyone. `009` supersedes
it and fixes all three.

Both are more useful as worked examples than they would be deleted.

## Traps this project has already hit

1. **A column-level `REVOKE` is silently a no-op** against a table-level grant,
   and reports success. See `002` above.
2. **pgcrypto lives in the `extensions` schema.** A `SECURITY DEFINER` function
   pinned to `SET search_path = public, pg_temp` loses `crypt()` and
   `gen_salt()` — and loses them **on the happy path only**, so token- and
   format-validation smoke tests still pass while the function is broken. Use
   `public, extensions, pg_temp`. Plain trigger functions do not need the pin at
   all: they run as the invoker, not the owner.
3. **Re-running a corrected migration through a *saved query*** in the SQL editor
   re-applies the old text. Confirm what actually landed:
   `select proname, proconfig from pg_proc where proname = '…';`
4. **Audit `SECURITY DEFINER` bodies separately from table grants.** A DEFINER
   function bypasses every column grant, so the question is what it
   *authenticates*, not what it returns. Reading the bodies found an
   unauthenticated account takeover that months of endpoint probing had not.
5. **Default grants are invisible.** `TRUNCATE`, `TRIGGER` and `REFERENCES`
   arrive from Supabase's `GRANT ALL` on new tables, never appear in application
   code, and survived `003`. `TRUNCATE` also **ignores RLS**, so it must be gone
   before Stage D or the policies are bypassable. See `011`.

## Verifying anything

Never trust a green "Success". Re-probe with the publishable key and no session:

```
?select=name,color   -> 200      ?select=phone        -> 401
?select=invite_token -> 401      ?select=*            -> 401
```

Dev and production should answer identically to all four.
