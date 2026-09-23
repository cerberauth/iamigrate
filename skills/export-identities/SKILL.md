---
name: export-identities
description: Export users/identities, organizations, roles and memberships out of an identity provider (IdP / CIAM) into an iamigrate CMF bundle, then audit it before any import. Use when asked to export, extract, dump, back up or migrate users, organizations, tenants, roles or memberships from an identity provider (Ory Kratos, Keycloak, a CSV/JSON user dump, or any IdP via its API).
---

Produces a **CMF bundle** — the directory every `iamigrate import`/`validate`/`diff`
consumes:

```
<bundle>/
  users.cmf.jsonl.gz        identities (+ memberships, global_roles)   <- iamigrate export
  manifest.json             counts, hash algorithms, skipped records   <- iamigrate export
  mapping.yaml              scaffolded field mapping                   <- iamigrate export
  organizations.cmf.jsonl   one org per line                           <- cmf_bundle.py orgs
  roles.cmf.jsonl           one role per line                          <- cmf_bundle.py orgs
```

`iamigrate export` writes identities only. Organizations, roles and memberships
are added by the driver next to this file, `cmf_bundle.py` (Python 3 stdlib), which also audits the
finished bundle. Below, `$SKILL` is this skill's directory.

## Prerequisites

`iamigrate` on `PATH` (`iamigrate --help` lists `export`), `python3`, `jq`.

## Workflow

### 1. Pick the source path — never assume one

Ask which IdP the user is exporting from if it isn't stated. Then:

| Source | Path |
|---|---|
| Ory Kratos | native: `iamigrate export --source kratos` |
| Keycloak | native, but from a **file, not the live server**: run `kc.sh export --realm <name> --dir <out> --users realm_file` on the Keycloak host/container first (the Admin API never returns password hashes), then `iamigrate export --source keycloak --in <out>` |
| CSV / JSON dump (DB table, legacy app) | native: `iamigrate export --source flatfile` |
| Any other IdP | get the provider's own user export (with password hashes if it offers them), reshape it into a flatfile CSV/JSON, then `--source flatfile` |

Flatfile columns recognized: `source_id,email,username,given_name,family_name,locale,blocked,password,password_algorithm`.
Every other column becomes `app_metadata.<column>`. Put the org/role data there
too, or in a separate CSV (step 3).

### 2. Export identities

```bash
export KRATOS_ADMIN_URL=http://127.0.0.1:4434          # Kratos Admin API, never the public port
iamigrate export --source kratos --out ./export/
# or
iamigrate export --source flatfile --in users.csv --format csv --out ./export/
# or, from a Keycloak realm export directory (see the source table above)
iamigrate export --source keycloak --in ./realm-export --out ./export/
```

Then read `./export/manifest.json`. `export` exits 0 even when records were
skipped, and the reasons are only listed under `skipped_records`.

### 3. Add organizations, roles, memberships

Write up to four CSVs from whatever the source holds (its org API, a tenant
table, identity metadata). Then:

```bash
python3 $SKILL/cmf_bundle.py orgs --bundle ./export \
  --orgs orgs.csv --roles roles.csv --memberships memberships.csv [--global-roles global_roles.csv]
```

| CSV | Columns | Notes |
|---|---|---|
| `orgs.csv` | `source_id,name[,display_name]` | extra columns -> org `metadata` |
| `roles.csv` | `source_id,name[,description]` | |
| `memberships.csv` | `user,organization[,roles]` | one row per user × org; roles `;`-separated |
| `global_roles.csv` | `user,roles` | roles not scoped to an org |

- `user` matches a user's CMF `source_id`, falling back to any of their emails (case-insensitive).
- `organization`/`roles` are **source_ids** from `orgs.csv`/`roles.csv`, not display names.
- Each CSV you pass replaces that field on every user, so re-runs are idempotent.
- Any unknown reference aborts the run with `file:line` errors, and nothing is written.

Worked example (verified): the org lives in Kratos identity metadata, the
usual place on OSS Kratos. `metadata_admin` = `{"org":"acme","org_roles":["admin"]}`
exports to `app_metadata`.

```bash
zcat ./export/users.cmf.jsonl.gz | jq -r 'select(.app_metadata.org) | [.source_id, .app_metadata.org, (.app_metadata.org_roles|join(";"))] | @csv' \
  | (echo user,organization,roles; cat) > memberships.csv
zcat ./export/users.cmf.jsonl.gz | jq -r 'select(.app_metadata.org) | .app_metadata.org' | sort -u \
  | awk 'BEGIN{print "source_id,name"}{print $1","$1}' > orgs.csv
zcat ./export/users.cmf.jsonl.gz | jq -r '.app_metadata.org_roles[]?' | sort -u \
  | awk 'BEGIN{print "source_id,name"}{print $1","$1}' > roles.csv
python3 $SKILL/cmf_bundle.py orgs --bundle ./export --orgs orgs.csv --roles roles.csv --memberships memberships.csv
```

### 4. Audit — the export is not done until this passes

```bash
python3 $SKILL/cmf_bundle.py check --bundle ./export          # exit 1 on integrity errors; --json for machine output
iamigrate map --target <target> --mapping ./export/mapping.yaml
iamigrate validate --in ./export/users.cmf.jsonl.gz --mapping ./export/mapping.yaml --target <target>
chmod 600 ./export/*
```

`check` **errors** on: duplicate user/org/role `source_id`, duplicate org or
role **names** (targets match on name), memberships or roles that point to
something missing, a wrong `cmf_version`, and unparsable org/role files.
It **warns** on: a primary email shared by several users, users with no
login identifier, users with no password hash (they'll need a reset),
non-portable MFA (users must re-enroll), records skipped at export, and orgs
with no members.

Report the `check` summary to the user: user count, hash algorithms, org/role
counts, and every warning.

## Gotchas

- **The bundle is a credential dump.** It holds password hashes and TOTP
  secrets, and `iamigrate export` creates `users.cmf.jsonl.gz` as `0664`.
  Run `chmod 600`, never commit it, and delete it after the migration.
  (`cmf_bundle.py` rewrites the file as `0600`.)
- **Org files must sit next to `users.cmf.jsonl.gz`**, with exactly these
  names and uncompressed. `import` looks for them only in `dirname(--in)`, and
  **silently ignores them if they are missing or fail to parse**. `check` is
  the only thing that catches that.
- **Only targets with org support use the org files.** `import auth0`
  creates the orgs and roles. `import kratos` (`SupportsOrgs=false`) drops
  them, and `validate --target kratos` still reports `0 problem(s)`.
- **OSS Kratos (v1.3.1) has no organizations.** `/admin/organizations`
  returns 404, and `organization_id` on an identity is rejected with
  `json: unknown field "organization_id"`. Deployments keep tenancy in
  `metadata_admin`/`metadata_public` (exported as `app_metadata`/`user_metadata`)
  or in traits, so look there.
- **Kratos export keeps only the `email`, `username`, and `phone` traits.** Names or
  anything else under `traits` is dropped, and `source_id` becomes the Kratos
  identity UUID. If membership data is keyed by something else, use email in
  the `user` column.
- **Keycloak export needs a `kc.sh export` file, not a live connection** — the
  Admin API's user endpoints never include `secretData`, so `--in` takes the
  export's `--file` or `--dir` output, not a URL. `source_id` becomes the
  Keycloak user UUID; realm/client roles and group membership aren't read, so
  org/role data has to come from `attributes` (`app_metadata`/`user_metadata`)
  the same way as Kratos.
- **A flatfile hash with no algorithm is skipped, not errored.** A raw md5 or
  sha hex digest with an empty `password_algorithm` ends up in
  `manifest.json.skipped_records`. Always fill `password_algorithm` for raw
  digests. bcrypt, argon2, scrypt, pbkdf2 and LDAP hashes are detected
  automatically.
- **The scaffolded `mapping.yaml` has `target: ""`.** `validate --mapping`
  fails until you run `iamigrate map --target <t>`. `--source`/`--target`
  are always required: iamigrate has no default provider.

## Provider notes (general IdP facts, not exercised here)

- Hosted IdPs often **won't export password hashes** through their API. Some
  only hand them over on request, and some never do. Without hashes, users
  are exported without passwords, and `check` warns that they will need a
  reset. Tell the user before they plan a cutover.
- An "organization" goes by many names: tenant, workspace, group, realm-level
  org. Ask what the source uses. Nested groups have to be flattened into orgs
  plus roles, because CMF orgs are flat.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `--admin-url (or $KRATOS_ADMIN_URL) is required` | set `KRATOS_ADMIN_URL` to the Admin API (port 4434 by default) |
| `required flag(s) "source" not set` | pass `--source kratos`, `--source keycloak`, or `--source flatfile` |
| `keycloak: no *-realm.json or *-users-*.json file in ...` | `--in` isn't a `kc.sh export` output; re-run `kc.sh export` and point `--in` at its `--file`/`--dir` |
| `keycloak: realm export must be a single realm object` | `--in` is an export of every realm (a JSON array); export one realm at a time with `--realm <name>` |
| `exported N users -> ... (M skipped)` with M > 0 | read `manifest.json` `skipped_records`; for `raw digest format requires a Hint.Algorithm` fill `password_algorithm` |
| `mapping: target is required` | `iamigrate map --target <t> --mapping ./export/mapping.yaml` |
| `cmf_bundle: <csv>:N: user 'x' matches no source_id or email` | the user was skipped at export or is keyed differently; check `manifest.json`, use the email |
| `cmf_bundle: <csv>: missing column(s) ...` | header names must match the table in step 3 exactly |
| `check`: `duplicate organization name` | two source orgs share a name; rename one (e.g. suffix its source_id) in `orgs.csv` and re-run `orgs` |
