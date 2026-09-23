#!/usr/bin/env python3
"""Build and audit an iamigrate CMF export bundle (stdlib only, Python 3.8+).

A bundle is the directory `iamigrate export` writes (users.cmf.jsonl.gz,
manifest.json, mapping.yaml), optionally completed with
organizations.cmf.jsonl and roles.cmf.jsonl, which `iamigrate import`
picks up automatically when they sit next to the users file.

  cmf_bundle.py orgs  --bundle DIR --orgs orgs.csv [--roles roles.csv]
                      [--memberships memberships.csv] [--global-roles global_roles.csv]
  cmf_bundle.py check --bundle DIR [--json]

CSV inputs (header row required, extra columns noted per file):
  orgs.csv          source_id,name[,display_name]   other columns -> metadata
  roles.csv         source_id,name[,description]
  memberships.csv   user,organization[,roles]       one row per user x org
  global_roles.csv  user,roles                      roles outside any org
`user` matches a CMF user's source_id first, then (case-insensitively) any of
their emails. `organization` and `roles` are source_ids from orgs.csv /
roles.csv; multiple roles are separated by ';'.

`orgs` treats each given CSV as the full truth: --memberships replaces every
user's memberships, --global-roles every user's global_roles (re-runs are
idempotent). It fails without writing anything if a row references an
unknown user, org or role.
"""
import argparse
import collections
import csv
import gzip
import json
import os
import sys

USERS = "users.cmf.jsonl.gz"
ORGS = "organizations.cmf.jsonl"
ROLES = "roles.cmf.jsonl"
CMF_VERSION = "1.0"


def die(msg):
    print(f"cmf_bundle: {msg}", file=sys.stderr)
    sys.exit(1)


def read_csv(path, required):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
        cols = rows[0].keys() if rows else []
    missing = [c for c in required if rows and c not in cols]
    if missing:
        die(f"{path}: missing column(s) {', '.join(missing)} (has: {', '.join(cols)})")
    return [{k: (v or "").strip() for k, v in r.items() if k is not None} for r in rows]


def split_roles(v):
    return [r.strip() for r in (v or "").split(";") if r.strip()]


def read_users(bundle):
    path = os.path.join(bundle, USERS)
    if not os.path.exists(path):
        die(f"{path} not found -- run `iamigrate export` first")
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_users(bundle, users):
    path = os.path.join(bundle, USERS)
    tmp = path + ".tmp"
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        for u in users:
            f.write(json.dumps(u, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.chmod(tmp, 0o600)  # password hashes and MFA secrets live in here
    os.replace(tmp, path)


def read_jsonl(path):
    if not os.path.exists(path):
        return None
    out = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                # iamigrate import silently skips an unparsable orgs/roles file
                die(f"{path}:{n}: invalid JSON ({e}); iamigrate import would ignore this whole file")
    return out


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")


def user_index(users):
    by_id, by_email = {}, {}
    for i, u in enumerate(users):
        by_id[u.get("source_id")] = i
        for e in u.get("emails") or []:
            by_email.setdefault((e.get("value") or "").lower(), i)
    return by_id, by_email


def cmd_orgs(a):
    users = read_users(a.bundle)
    by_id, by_email = user_index(users)
    errors = []

    orgs = []
    for r in read_csv(a.orgs, ["source_id", "name"]):
        o = {"source_id": r.pop("source_id"), "name": r.pop("name")}
        if r.get("display_name"):
            o["display_name"] = r.pop("display_name")
        r.pop("display_name", None)
        meta = {k: v for k, v in r.items() if v}
        if meta:
            o["metadata"] = meta
        orgs.append(o)
    org_ids = {o["source_id"] for o in orgs}

    roles = []
    if a.roles:
        for r in read_csv(a.roles, ["source_id", "name"]):
            role = {"source_id": r["source_id"], "name": r["name"]}
            if r.get("description"):
                role["description"] = r["description"]
            roles.append(role)
    role_ids = {r["source_id"] for r in roles}

    def resolve(ref, where):
        i = by_id.get(ref)
        if i is None:
            i = by_email.get(ref.lower())
        if i is None:
            errors.append(f"{where}: user {ref!r} matches no source_id or email in {USERS}")
        return i

    def check_roles(rs, where):
        for r in rs:
            if r not in role_ids:
                errors.append(f"{where}: role {r!r} not in {a.roles or 'roles.csv (not given)'}")

    memberships = collections.defaultdict(list)
    if a.memberships:
        for n, r in enumerate(read_csv(a.memberships, ["user", "organization"]), start=2):
            where = f"{a.memberships}:{n}"
            i = resolve(r["user"], where)
            if r["organization"] not in org_ids:
                errors.append(f"{where}: organization {r['organization']!r} not in {a.orgs}")
            rs = split_roles(r.get("roles"))
            check_roles(rs, where)
            if i is not None:
                m = {"organization": r["organization"]}
                if rs:
                    m["roles"] = rs
                memberships[i].append(m)

    global_roles = {}
    if a.global_roles:
        for n, r in enumerate(read_csv(a.global_roles, ["user", "roles"]), start=2):
            where = f"{a.global_roles}:{n}"
            i = resolve(r["user"], where)
            rs = split_roles(r["roles"])
            check_roles(rs, where)
            if i is not None:
                global_roles[i] = rs

    if errors:
        for e in errors[:50]:
            print(f"error: {e}", file=sys.stderr)
        die(f"{len(errors)} error(s); nothing written")

    for i, u in enumerate(users):
        if a.memberships:
            u.pop("memberships", None)
            if i in memberships:
                u["memberships"] = memberships[i]
        if a.global_roles:
            u.pop("global_roles", None)
            if i in global_roles:
                u["global_roles"] = global_roles[i]
    write_users(a.bundle, users)
    write_jsonl(os.path.join(a.bundle, ORGS), orgs)
    if a.roles:
        write_jsonl(os.path.join(a.bundle, ROLES), roles)
    print(f"wrote {len(orgs)} organizations, {len(roles)} roles; "
          f"memberships on {len(memberships)} users, global roles on {len(global_roles)} users")


def cmd_check(a):
    users = read_users(a.bundle)
    orgs = read_jsonl(os.path.join(a.bundle, ORGS))
    roles = read_jsonl(os.path.join(a.bundle, ROLES))
    manifest = {}
    mpath = os.path.join(a.bundle, "manifest.json")
    if os.path.exists(mpath):
        with open(mpath, encoding="utf-8") as f:
            manifest = json.load(f)

    errors, warnings = [], []
    ids = collections.Counter(u.get("source_id") for u in users)
    for sid, n in ids.items():
        if not sid:
            errors.append(f"{n} user(s) without source_id")
        elif n > 1:
            errors.append(f"duplicate user source_id {sid!r} x{n}")
    for u in users:
        if u.get("cmf_version") != CMF_VERSION:
            errors.append(f"user {u.get('source_id')!r}: cmf_version {u.get('cmf_version')!r} != {CMF_VERSION!r}")
            break
    emails = collections.Counter(
        (e.get("value") or "").lower() for u in users for e in (u.get("emails") or []) if e.get("primary"))
    dup_emails = [e for e, n in emails.items() if n > 1]
    if dup_emails:
        warnings.append(f"{len(dup_emails)} primary email(s) shared by several users, e.g. {dup_emails[0]!r} "
                        "-- most targets key users by email")
    no_login = [u["source_id"] for u in users if not (u.get("emails") or u.get("phones") or u.get("username"))]
    if no_login:
        warnings.append(f"{len(no_login)} user(s) with no email, phone or username, e.g. {no_login[0]!r}")

    hashes = collections.Counter((u.get("password") or {}).get("algorithm", "none") for u in users)
    if hashes.get("none"):
        warnings.append(f"{hashes['none']} user(s) without a password hash -- they will need a reset "
                        "(or passwordless/SSO) on the target")
    nonportable = collections.Counter(
        f["type"] for u in users for f in (u.get("mfa_factors") or []) if not f.get("portable"))
    if nonportable:
        warnings.append("non-portable MFA factors (users must re-enroll): "
                        + ", ".join(f"{t}={n}" for t, n in sorted(nonportable.items())))
    skipped = manifest.get("skipped_records") or []
    if skipped:
        warnings.append(f"{len(skipped)} source record(s) skipped at export, see manifest.json "
                        f"(first: {skipped[0].get('source_id')}: {skipped[0].get('reason')})")

    org_ids = set()
    if orgs is not None:
        c = collections.Counter(o.get("source_id") for o in orgs)
        errors += [f"duplicate organization source_id {k!r}" for k, n in c.items() if n > 1 or not k]
        names = collections.Counter(o.get("name") for o in orgs)
        errors += [f"duplicate organization name {k!r} (targets match orgs by name)" for k, n in names.items()
                   if n > 1 or not k]
        org_ids = set(c)
    role_ids = set()
    if roles is not None:
        c = collections.Counter(r.get("source_id") for r in roles)
        errors += [f"duplicate role source_id {k!r}" for k, n in c.items() if n > 1 or not k]
        names = collections.Counter(r.get("name") for r in roles)
        errors += [f"duplicate role name {k!r} (targets match roles by name)" for k, n in names.items()
                   if n > 1 or not k]
        role_ids = set(c)

    members = collections.Counter()
    dangling = collections.Counter()
    for u in users:
        for m in u.get("memberships") or []:
            members[m.get("organization")] += 1
            if m.get("organization") not in org_ids:
                dangling[f"organization {m.get('organization')!r}"] += 1
            for r in m.get("roles") or []:
                if r not in role_ids:
                    dangling[f"role {r!r}"] += 1
        for r in u.get("global_roles") or []:
            if r not in role_ids:
                dangling[f"role {r!r}"] += 1
    errors += [f"{n} reference(s) to unknown {what}" for what, n in dangling.items()]
    if orgs:
        empty = [o["name"] for o in orgs if not members.get(o["source_id"])]
        if empty:
            warnings.append(f"{len(empty)} organization(s) without members, e.g. {empty[0]!r}")
    if members and orgs is None:
        errors.append(f"users carry memberships but {ORGS} is missing")

    summary = {
        "users": len(users),
        "password_algorithms": dict(hashes),
        "users_with_mfa": sum(1 for u in users if u.get("mfa_factors")),
        "organizations": None if orgs is None else len(orgs),
        "roles": None if roles is None else len(roles),
        "users_with_memberships": sum(1 for u in users if u.get("memberships")),
        "users_with_global_roles": sum(1 for u in users if u.get("global_roles")),
        "skipped_at_export": len(skipped),
        "errors": errors,
        "warnings": warnings,
    }
    if a.json:
        print(json.dumps(summary, indent=2))
    else:
        for k, v in summary.items():
            if k not in ("errors", "warnings"):
                print(f"{k:24} {v if v is not None else '-'}")
        for w in warnings:
            print(f"WARN  {w}")
        for e in errors:
            print(f"ERROR {e}")
        print("bundle OK" if not errors else f"bundle has {len(errors)} error(s)")
    sys.exit(1 if errors else 0)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("orgs", help="write organizations/roles files and merge memberships into users")
    o.add_argument("--bundle", required=True)
    o.add_argument("--orgs", required=True)
    o.add_argument("--roles")
    o.add_argument("--memberships")
    o.add_argument("--global-roles")
    o.set_defaults(fn=cmd_orgs)
    c = sub.add_parser("check", help="audit a bundle; exits 1 on integrity errors")
    c.add_argument("--bundle", required=True)
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_check)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
