---
name: import-identities
description: Import users/identities, organizations, roles and memberships from an iamigrate CMF bundle into a target identity provider (IdP / CIAM) — safely, with preflight, a canary batch, retries and post-import verification. Use when asked to import, load, migrate, move or restore users or organizations into an identity provider (Ory Kratos, Auth0), or to resume, retry or verify a migration import.
---

Takes a **CMF bundle** (`users.cmf.jsonl.gz` + optional `organizations.cmf.jsonl`,
`roles.cmf.jsonl`, `mapping.yaml` — see the `export-identities` skill) into a
target IdP with `iamigrate import`, staged through the driver next to this
file, `import_bundle.py` (Python 3 stdlib):

- `prepare` writes a sliced/transformed **copy** of the bundle (canary, rest, retry; strip what the target can't take; annotate orgs + source_id). The source bundle is never modified.
- `report` triages an `import-report.json` against the bundle that was imported and exits 1 on anything that needs attention.

`$SKILL` below is this skill's directory, `$EXPORT_SKILL` the `export-identities` one.

## Prerequisites

`iamigrate` on `PATH`, `python3`, `jq`, `curl`; target credentials in env.

## 0. Pick the target — never assume one

Ask if not stated. What each target takes (from `iamigrate`'s capabilities, corrected by live runs):

| Target | Password hashes | MFA | Orgs / roles | Invocation |
|---|---|---|---|---|
| `kratos` | bcrypt, argon2 | **none in practice** (see Gotchas) | no → `--annotate` | `import kratos --in F [--schema-id S]`, `$KRATOS_ADMIN_URL` |
| `auth0` | all 11 CMF algorithms | totp, sms, email | yes, from files next to `--in` | `import auth0 --in F --connection-id C [--mapping M] [--upsert]`, `$AUTH0_DOMAIN`/`$AUTH0_TOKEN` — **not live-verified here** |

## 1. Preflight

```bash
export KRATOS_ADMIN_URL=http://127.0.0.1:4434
curl -sf $KRATOS_ADMIN_URL/admin/health/ready                 # target reachable? import does NOT fail fast
python3 $EXPORT_SKILL/cmf_bundle.py check --bundle ./export     # bundle integrity
iamigrate validate --in ./export/users.cmf.jsonl.gz --target kratos   # exit 1 + one line per unsupported hash/MFA
```

Turn every `validate` problem into a decision **with the user**: fix at the
source and re-export, or strip with `prepare --drop-password-alg ALG,...`
(user imports passwordless → reset) / `--drop-mfa TYPE,...` (user re-enrolls).
If the target has no orgs (`kratos`), use `--annotate migration` so
memberships, org names, global roles and the source `source_id` land in the
user's admin metadata instead of being silently dropped. Use the **same
transform flags for every batch**.

## 2. Canary, then the rest, then retries

```bash
T="--drop-password-alg md5 --drop-mfa totp,recovery_codes --annotate migration"   # decided in step 1
python3 $SKILL/import_bundle.py prepare --bundle ./export --out ./stage/canary --first 10 --transforms "$T"
iamigrate validate --in ./stage/canary/users.cmf.jsonl.gz --target kratos      # must be 0 problem(s) now
iamigrate import kratos --in ./stage/canary/users.cmf.jsonl.gz
python3 $SKILL/import_bundle.py report --bundle ./stage/canary --report ./stage/canary/import-report.json
```

Stop and inspect the target if the canary `report` exits 1. Then:

```bash
python3 $SKILL/import_bundle.py prepare --bundle ./export --out ./stage/rest --exclude-report ./stage/canary/import-report.json --transforms "$T"
iamigrate import kratos --in ./stage/rest/users.cmf.jsonl.gz
python3 $SKILL/import_bundle.py report --bundle ./stage/rest --report ./stage/rest/import-report.json
# only if report printed "retry with": transient failures (429/5xx/connection errors)
python3 $SKILL/import_bundle.py prepare --bundle ./stage/rest --out ./stage/rest-retry --retry ./stage/rest/import-report.json
iamigrate import kratos --in ./stage/rest-retry/users.cmf.jsonl.gz
```

`report` buckets: **conflict** (409, identity already exists — expected on
re-runs, not an error), **rejected** (4xx/translation — fix data, never
retry blindly), **retryable**, **unaccounted** (in the bundle, absent from
the report). Follow-up lists: `needs_password_reset` (includes passwordless
and dropped-hash users), `needs_mfa_reenrollment` (includes `--drop-mfa`
users), `needs_recovery_code_regen`. Use `--json` to hand them on.

## 3. Verify

```bash
python3 $SKILL/import_bundle.py prepare --bundle ./export --out ./stage/all --transforms "$T"
iamigrate diff kratos --in ./stage/all/users.cmf.jsonl.gz            # want: missing in target: 0, attribute drift: 0
```

Then prove logins, not just records: with a fixture bundle
(`iamigrate testdata generate` writes `answer-key.json`) log in as a user
whose hash was kept, through the target's real login flow. Kratos native
flow (verified: 200 with the original password, 400 otherwise):

```bash
SID=$(zcat ./stage/all/users.cmf.jsonl.gz | jq -r 'select(.password) | .source_id' | head -1)
EMAIL=$(jq -r --arg s "$SID" '.entries[] | select(.source_id==$s) | .email' ./export/answer-key.json)
PASSWORD=$(jq -r --arg s "$SID" '.entries[] | select(.source_id==$s) | .password' ./export/answer-key.json)
curl -s "$KRATOS_ADMIN_URL/admin/identities?credentials_identifier=$EMAIL" | jq -c '.[0].metadata_admin.migration'
P=http://127.0.0.1:4433; flow=$(curl -s $P/self-service/login/api | jq -r .id)
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$P/self-service/login?flow=$flow" -H 'content-type: application/json' \
  -d "$(jq -nc --arg i "$EMAIL" --arg p "$PASSWORD" '{method:"password",identifier:$i,password:$p}')"
```

Report to the user: imported / conflict / rejected counts, rejected reasons,
and the three follow-up lists (these users need an email campaign or forced reset).

## Gotchas

- **`import` and `diff` always exit 0** — with rejected users, with every
  user missing, even with the target **down** (`connection refused` for
  every record, full pass, exit 0). Only `report`/`diff` output tells you.
  Health-check first.
- **Kratos v1.3.1 rejects every imported MFA credential** that iamigrate
  advertises: `json: unknown field "totp"` and `json: unknown field
  "lookup_secret"` (400), while `validate --target kratos` reports 0
  problems. Always `--drop-mfa totp,recovery_codes` for Kratos, or the whole
  user fails.
- **A 409 conflict is not proof the user is yours.** Kratos/`diff` match on
  email; a pre-existing target user with the same email looks identical. With
  `--annotate`, compare `metadata_admin.<key>.source_id`.
- **Org files only reach the target if they sit next to `--in`** — `prepare`
  copies them into every stage dir for that reason. `kratos` ignores them
  (hence `--annotate`); `auth0` matches orgs/roles **by name** and reuses
  existing ones, so staged batches are safe, and membership calls only run
  for users imported in that same batch.
- **Re-running the same batch on Kratos = all conflicts** (no upsert). Always
  build the next batch with `--exclude-report` of every previous report.
- **Kratos only stores the `email`/`username` traits from CMF, plus every
  `user_metadata` key copied into traits** (and `metadata_public`); a strict
  identity schema rejects unknown `user_metadata` keys. `app_metadata` →
  `metadata_admin`. Names are dropped; `external_id` stays empty.
- **`import kratos` ignores `mapping.yaml`**; it takes `--schema-id` (default `default`).
- **Throughput:** `import kratos` is one serial POST per user (~200 users/s against local Kratos). Plan batches accordingly.
- **Blocked users** import as Kratos `state: inactive`; verified-email flags carry over.
- **Staged bundles contain password hashes** (`prepare` writes them `0600`). Delete `./stage` after the migration.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `validate failed: N problem(s)` / `unsupported password algorithm "md5"` | re-export with a supported hash, or `prepare --drop-password-alg md5` (users need reset) |
| report `REJECTED ... unknown field "totp"` / `"lookup_secret"` | `prepare --drop-mfa totp,recovery_codes` (Kratos) |
| every record `dial tcp ...: connection refused`, `retryable N` | target down; fix, then `prepare --retry <report>` |
| `conflict_already_exists` = batch size | batch already imported; build the next one with `--exclude-report` |
| `cmf: opening gzip stream: EOF` / `not a complete gzip file` | the export that produced the bundle failed halfway (e.g. CSV `wrong number of fields` from an unquoted argon2 hash — quote fields containing commas) and left an empty file; re-export |
| `--admin-url (or $KRATOS_ADMIN_URL) is required` | export `KRATOS_ADMIN_URL` (Admin API, port 4434 by default) |
