#!/usr/bin/env python3
"""Stage and triage `iamigrate import` runs over a CMF bundle (stdlib only, Python 3.8+).

  import_bundle.py prepare --bundle SRC --out DST [selection] [transforms]
  import_bundle.py report  --bundle DIR --report import-report.json [--json]

prepare writes a new bundle DST (users.cmf.jsonl.gz + copies of
organizations/roles/mapping files) holding a slice of SRC's users:
  --first N                 canary: the first N users
  --exclude-report R ...    everyone not already in R's `succeeded` (repeatable)
  --retry R                 only users R failed with a retryable error (429/5xx/network)
and optionally transforms them:
  --drop-password-alg A,B   strip password hashes the target can't import; those
                            users import passwordless and `report` lists them for reset
  --drop-mfa T,U            strip MFA factor types the target rejects (e.g. totp);
                            `report` lists those users for re-enrollment
  --annotate KEY            copy source_id, memberships (with org names) and
                            global_roles into app_metadata[KEY]; for targets without
                            organization support, or to keep a source-id trail
  --transforms "FLAGS"      the flags above as one quoted string, e.g. from a variable

report reads an import-report.json against the bundle that was imported, sorts
failures into conflict / rejected / retryable, lists follow-ups (password
reset, MFA re-enrollment, recovery codes) and exits 1 if anything other than
a conflict (the user already exists) failed or no user was accounted for.
"""
import argparse
import collections
import gzip
import json
import os
import re
import shlex
import shutil
import sys

USERS = "users.cmf.jsonl.gz"
SIDE_FILES = ("organizations.cmf.jsonl", "roles.cmf.jsonl", "mapping.yaml")
PREPARED = "prepare.json"  # what prepare stripped, so report can list follow-ups


def die(msg):
    print(f"import_bundle: {msg}", file=sys.stderr)
    sys.exit(1)


def read_users(bundle):
    path = os.path.join(bundle, USERS)
    if not os.path.exists(path):
        die(f"{path} not found")
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
    except (EOFError, OSError) as e:
        die(f"{path}: not a complete gzip file ({e}) -- did the export fail halfway?")


def read_report(path):
    with open(path, encoding="utf-8") as f:
        r = json.load(f)
    return {k: (v or ([] if k != "org_id_map" and k != "role_id_map" else {})) for k, v in r.items()}


def classify(err):
    """conflict | retryable | rejected, from an ImportError's code/message."""
    m = re.search(r"status (\d{3})", err.get("message") or "")
    status = int(m.group(1)) if m else None
    if status == 409 or re.search(r"already exists|DUPLICATED_USER", err.get("message") or "", re.I):
        return "conflict"
    if status == 429 or (status and status >= 500):
        return "retryable"
    if err.get("code") == "REQUEST_ERROR" and status is None:
        return "retryable"  # transport error: timeout, connection refused, ...
    return "rejected"


def cmd_prepare(a):
    if os.path.abspath(a.bundle) == os.path.abspath(a.out):
        die("--out must differ from --bundle")
    users = read_users(a.bundle)

    if a.first is not None:
        users = users[: a.first]
    done = set()
    for r in a.exclude_report or []:
        done |= set(read_report(r).get("succeeded", []))
    if done:
        users = [u for u in users if u["source_id"] not in done]
    if a.retry:
        rep = read_report(a.retry)
        keep = {e["source_id"] for e in rep.get("failed", []) if e.get("source_id") and classify(e) == "retryable"}
        users = [u for u in users if u["source_id"] in keep]

    # A stage built from another stage (e.g. --retry) inherits its follow-ups.
    selected = {u["source_id"] for u in users}
    inherited = {}
    if os.path.exists(os.path.join(a.bundle, PREPARED)):
        with open(os.path.join(a.bundle, PREPARED), encoding="utf-8") as f:
            inherited = json.load(f)
    dropped_pw = [s for s in inherited.get("dropped_password", []) if s in selected]
    dropped_mfa = [s for s in inherited.get("dropped_mfa", []) if s in selected]
    if a.drop_password_alg:
        algs = {x.strip() for x in a.drop_password_alg.split(",") if x.strip()}
        for u in users:
            if (u.get("password") or {}).get("algorithm") in algs:
                u["password"] = None
                dropped_pw.append(u["source_id"])
    if a.drop_mfa:
        types = {x.strip() for x in a.drop_mfa.split(",") if x.strip()}
        for u in users:
            factors = u.get("mfa_factors") or []
            kept = [f for f in factors if f.get("type") not in types]
            if len(kept) != len(factors):
                if kept:
                    u["mfa_factors"] = kept
                else:
                    u.pop("mfa_factors")
                dropped_mfa.append(u["source_id"])

    if a.annotate:
        org_names = {}
        opath = os.path.join(a.bundle, "organizations.cmf.jsonl")
        if os.path.exists(opath):
            with open(opath, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        o = json.loads(line)
                        org_names[o["source_id"]] = o.get("name")
        for u in users:
            note = {"source_id": u["source_id"]}
            if u.get("memberships"):
                note["memberships"] = [dict(m, name=org_names.get(m["organization"])) for m in u["memberships"]]
            if u.get("global_roles"):
                note["global_roles"] = u["global_roles"]
            u["app_metadata"] = dict(u.get("app_metadata") or {}, **{a.annotate: note})

    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, USERS)
    with gzip.open(path + ".tmp", "wt", encoding="utf-8") as f:
        for u in users:
            f.write(json.dumps(u, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.chmod(path + ".tmp", 0o600)
    os.replace(path + ".tmp", path)
    for name in SIDE_FILES:
        if os.path.exists(os.path.join(a.bundle, name)):
            shutil.copyfile(os.path.join(a.bundle, name), os.path.join(a.out, name))
    with open(os.path.join(a.out, PREPARED), "w", encoding="utf-8") as f:
        json.dump({"dropped_password": dropped_pw, "dropped_mfa": dropped_mfa}, f, indent=2)
    stale = os.path.join(a.out, "import-report.json")
    if os.path.exists(stale):
        os.remove(stale)
    print(f"prepared {len(users)} users -> {path}"
          + (f" ({len(dropped_pw)} password hashes dropped)" if dropped_pw else "")
          + (f" (MFA dropped on {len(dropped_mfa)} users)" if dropped_mfa else "")
          + (f" (annotated app_metadata.{a.annotate})" if a.annotate else ""))
    if not users:
        print("nothing to import", file=sys.stderr)


def cmd_report(a):
    users = {u["source_id"]: u for u in read_users(a.bundle)}
    rep = read_report(a.report)
    succeeded = set(rep.get("succeeded", []))
    buckets = collections.defaultdict(list)
    phase_errors = []
    for e in rep.get("failed", []):
        if not e.get("source_id"):
            phase_errors.append(e.get("message", ""))  # org/role phase, not tied to one user
            continue
        buckets[classify(e)].append(e)
    failed_ids = {e["source_id"] for es in buckets.values() for e in es}
    unaccounted = sorted(set(users) - succeeded - failed_ids)

    prepared = {}
    ppath = os.path.join(a.bundle, PREPARED)
    if os.path.exists(ppath):
        with open(ppath, encoding="utf-8") as f:
            prepared = json.load(f)
    no_password = sorted(s for s in succeeded if s in users and not users[s].get("password"))
    reset = sorted(set(rep.get("requires_password_reset", [])) | set(no_password))
    reasons = collections.Counter(re.sub(r"\s+", " ", e.get("message", ""))[:140] for e in buckets["rejected"])

    summary = {
        "bundle_users": len(users),
        "succeeded": len(succeeded),
        "conflict_already_exists": len(buckets["conflict"]),
        "rejected": len(buckets["rejected"]),
        "retryable": len(buckets["retryable"]),
        "unaccounted": len(unaccounted),
        "org_role_phase_errors": len(phase_errors),
        "orgs_mapped": len(rep.get("org_id_map", {})),
        "roles_mapped": len(rep.get("role_id_map", {})),
        "needs_password_reset": reset,
        "needs_mfa_reenrollment": sorted(set(rep.get("requires_reenrollment", []))
                                         | (succeeded & set(prepared.get("dropped_mfa", [])))),
        "needs_recovery_code_regen": sorted(rep.get("requires_recovery_code_regen", [])),
        "rejected_reasons": dict(reasons.most_common(10)),
        "retryable_ids": [e["source_id"] for e in buckets["retryable"]],
        "unaccounted_ids": unaccounted[:50],
        "org_role_phase_error_samples": phase_errors[:5],
    }
    if a.json:
        print(json.dumps(summary, indent=2))
    else:
        for k in ("bundle_users", "succeeded", "conflict_already_exists", "rejected", "retryable",
                  "unaccounted", "org_role_phase_errors", "orgs_mapped", "roles_mapped"):
            print(f"{k:26} {summary[k]}")
        for k in ("needs_password_reset", "needs_mfa_reenrollment", "needs_recovery_code_regen"):
            v = summary[k]
            print(f"{k:26} {len(v)}" + (f"  e.g. {', '.join(v[:3])}" if v else ""))
        for msg, n in summary["rejected_reasons"].items():
            print(f"REJECTED x{n}: {msg}")
        for msg in summary["org_role_phase_error_samples"]:
            print(f"ORG/ROLE PHASE: {msg[:200]}")
        if unaccounted:
            print(f"UNACCOUNTED: {', '.join(unaccounted[:10])}")
        if buckets["retryable"]:
            print(f"retry with: prepare --retry {a.report}")
    bad = buckets["rejected"] or buckets["retryable"] or unaccounted or phase_errors
    sys.exit(1 if bad or not (succeeded or buckets["conflict"]) else 0)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("prepare", help="write a sliced/transformed copy of a bundle")
    pr.add_argument("--bundle", required=True)
    pr.add_argument("--out", required=True)
    pr.add_argument("--first", type=int)
    pr.add_argument("--exclude-report", action="append")
    pr.add_argument("--retry")
    pr.add_argument("--drop-password-alg")
    pr.add_argument("--drop-mfa")
    pr.add_argument("--annotate")
    pr.set_defaults(fn=cmd_prepare)
    rp = sub.add_parser("report", help="triage an import-report.json; exit 1 on real failures")
    rp.add_argument("--bundle", required=True)
    rp.add_argument("--report", required=True)
    rp.add_argument("--json", action="store_true")
    rp.set_defaults(fn=cmd_report)
    # --transforms "<flags>" expands in place, so one quoted variable can carry
    # the same transform flags to every batch in bash and zsh alike.
    argv = sys.argv[1:]
    while "--transforms" in argv:
        i = argv.index("--transforms")
        if i + 1 >= len(argv):
            die("--transforms needs a value")
        argv[i:i + 2] = shlex.split(argv[i + 1])
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
