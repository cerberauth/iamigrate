# iamigrate

A vendor-neutral CLI for migrating CIAM identities between providers. Export users into a canonical format, validate them against your target, and import them in — no vendor lock-in on the format in between.

## Install

**Homebrew**

```sh
brew install cerberauth/tap/iamigrate
```

**Docker**

```sh
docker run --rm ghcr.io/cerberauth/iamigrate --help
```

**Linux packages** (deb/rpm/apk/archlinux) and **Scoop**, **WinGet**, **Chocolatey** on Windows are also available. Or grab a prebuilt binary from the [releases page](https://github.com/cerberauth/iamigrate/releases).

See the [installation guide](https://www.cerberauth.com/docs/iamigrate/) for the full list of options.

## Quick start

```sh
# Generate synthetic test data + a cleartext answer key for login verification
iamigrate testdata generate --count 1000 --hash bcrypt:cost=10 --mfa totp:rate=0.3 --out ./fixtures/

# Dry-run against your target's capabilities, no network calls
iamigrate validate --in ./fixtures/users.cmf.jsonl.gz --target auth0

# Import into a disposable Auth0 tenant
export AUTH0_DOMAIN=your-tenant.us.auth0.com
export AUTH0_TOKEN=...
iamigrate import auth0 --in ./fixtures/users.cmf.jsonl.gz --connection-id con_xxx
```

## Migrating from a flat file

```sh
iamigrate export --source flatfile --in users.csv --format csv --out ./export/
iamigrate validate --in ./export/users.cmf.jsonl.gz --mapping ./export/mapping.yaml --target auth0
```

## Migrating with Ory Kratos

Kratos can be either side of a migration: export identities out of a running
instance via its Admin API, or import a CMF file into one.

```sh
export KRATOS_ADMIN_URL=http://127.0.0.1:4434

# Export every identity (with its bcrypt/argon2id password hash) into CMF
iamigrate export --source kratos --out ./export/

# ...or import a CMF file as new identities against a given schema
iamigrate import kratos --in ./fixtures/users.cmf.jsonl.gz --schema-id default

# Reconcile a CMF file against the live instance after import
iamigrate diff kratos --in ./fixtures/users.cmf.jsonl.gz
```

Kratos only supports importing pre-existing bcrypt and argon2id password
hashes and totp/lookup_secret (recovery codes) MFA factors -- see
`iamigrate validate --target kratos` to catch anything else before running
an import. A disposable Kratos instance for trying this locally is in
[`.docker/kratos`](.docker/kratos).

## Migrating with Keycloak

Keycloak can also be either side of a migration: import a CMF file into a
realm via the Admin API, or export a realm's users (with their password
hashes) from a `kc.sh export` realm export, since the Admin API never
returns hashes.

```sh
# Import a CMF file as new users into a realm
iamigrate import keycloak --in ./fixtures/users.cmf.jsonl.gz \
  --url http://127.0.0.1:8080 --realm acme --username admin --password admin

# ...or export a `kc.sh export` realm export into CMF
iamigrate export --source keycloak --in ./realm-export --out ./export/

# Reconcile a CMF file against the live realm after import
iamigrate diff keycloak --in ./fixtures/users.cmf.jsonl.gz \
  --url http://127.0.0.1:8080 --realm acme --username admin --password admin
```

Keycloak only supports importing pre-existing pbkdf2 and argon2 password
hashes (its two built-in hash providers) and totp MFA factors -- see
`iamigrate validate --target keycloak` to catch anything else before running
an import. A disposable Keycloak instance for trying this locally is in
[`.docker/keycloak`](.docker/keycloak).

## Learn more

- [Documentation](https://www.cerberauth.com/docs/iamigrate/)
- [CLI reference](https://www.cerberauth.com/docs/iamigrate/reference/cli/)

## License

MIT, see [LICENSE](LICENSE).
