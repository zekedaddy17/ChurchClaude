# Members Portal — Operations

The members area (`/members`) is built entirely inside `worker.js`. None of it
exists as a file in this repo, and that is deliberate: the repo root is the
public asset store (`wrangler.toml`: `[assets] directory = "."`), so a
members-only `.html` file here would be readable by anyone. **Never add a page
under `/members` as a file — add it to `worker.js`.**

## One-time setup

### 1. Create the admin account

Order matters. `ADMIN_EMAILS` is a deployment secret, and registering an address
that is already listed in it is refused — otherwise whoever signed up as the
church office first would inherit admin rights.

1. Register normally at `/register` with the address that will be the admin.
2. Grant it admin:
   ```
   npx wrangler secret put ADMIN_EMAILS
   # paste: office@yourchurch.org        (comma-separated for several admins)
   ```
3. Sign in at `/login`. An address in `ADMIN_EMAILS` counts as approved, so no
   manual KV editing is needed.

To add or remove an admin later, re-run `wrangler secret put ADMIN_EMAILS` with
the full list. Removal takes effect on the next request — it does not wait for
the 7-day session to expire.

### 2. Backfill accounts created before approvals existed

Accounts predating the approval queue have no `status` field, and the Worker
treats a missing `status` as **approved** so that deploying this could not lock
anyone out. Stamp them explicitly, then that fallback stops mattering:

```
npx wrangler kv key list --binding MEMBERS_KV --prefix "user:"
# for each, read it, add "status":"approved", and put it back:
npx wrangler kv key get  --binding MEMBERS_KV "user:someone@example.com"
npx wrangler kv key put  --binding MEMBERS_KV "user:someone@example.com" '<json with status>'
```

## Approving members

New sign-ups land in the queue at `/members/admin`. Approve or Deny each one.

- **Deny** deletes the account outright, so the person can sign up again later.
- Changes can take up to a minute to appear everywhere — Workers KV is
  eventually consistent, and a failed "still pending" sign-in caches that answer
  at the member's nearest datacenter. If someone is approved but still sees the
  pending message, have them wait a minute and retry.

## Updating the directory from Servant Keeper

Servant Keeper has no API, so this is a manual export. Redo it whenever the
church records change materially.

1. In Servant Keeper: **Membership Manager → Groups Keeper →** double-click your
   group **→ Select Fields** (tick the fields you want) **→ Group tab → Export →
   CSV File**. Check "list the search results using Individuals".
2. Go to `/members/admin` → *Update the Directory* → choose the file.
3. Tick the columns to publish. **Nothing is ticked by default except obvious
   contact fields** — Servant Keeper exports routinely include contribution
   totals, birthdates and background-check flags, and an unticked column is
   never uploaded. The preview shows a real example value per column so you can
   see exactly what publishing it would reveal.
4. Tick **Name** for the columns forming each person's displayed name, and
   **Search** for what members should be able to search on.
5. Press **Publish Directory**. This replaces the whole directory.

The CSV is read in your browser and never stored — not in this repo, not in
Cloudflare. Only the ticked columns are uploaded. Field labels on the directory
page are the CSV's own column headings, so if a heading reads oddly, rename it
in the Servant Keeper export and re-upload.

## Tests

```
node tests/run.mjs
```

No dependencies. Covers the approval and admin model, the `/members` route
gating, the CSV parser, and a syntax check of every `<script>` the Worker
inlines into a page — the last one matters because `node --check worker.js`
cannot see inside a template literal, so a broken escape in inlined page JS
would otherwise ship silently.
