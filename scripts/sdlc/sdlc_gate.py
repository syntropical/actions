#!/usr/bin/env python3
"""Secure-SDLC gate evaluator for the reusable secure-sdlc workflow.

Every scanner in the workflow runs in report mode and writes JSON. This script is the
single place that decides pass or fail:

  * normalises each scanner's output into one finding shape;
  * applies the repo's exception register (.security/exceptions.yaml);
  * applies the blocking policy (which severities block, per gate);
  * honours mode = report | enforce (report never fails on findings, but an
    invalid or expired exception register is always reported);
  * writes a coverage statement (what ran, against what, what it found) to the
    job summary, and a machine-readable evidence file for the release attestation.

It never prints an all-clear. Zero findings is reported as coverage: the scanners,
versions, rule sets and targets that produced zero findings.

Stdlib only, plus PyYAML when the exception register is YAML.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Gates that block in enforce mode, and the minimum severity that blocks.
# Secrets block at any severity: a leaked credential has no "low".
DEFAULT_BLOCK_AT = {
    "secrets": "info",
    "sast": "high",
    "sca": "high",
    "licence": "high",
    "iac": "high",
    "actions-pinning": "medium",
    "dco": "medium",
}

# Maximum exception lifetime by severity (days from approved_on to expires).
MAX_EXCEPTION_DAYS = {"critical": 30, "high": 90, "medium": 180, "low": 365, "info": 365, "unknown": 90}
EXCEPTION_REASONS = {
    "not_reachable", "not_exploitable", "no_fix_available", "false_positive", "accepted_risk",
}
EXCEPTION_REQUIRED = ("id", "scanner", "severity", "reason", "justification",
                      "approved_by", "approved_on", "expires")

# Licences that would reach into tenant IP layered on top of a platform module.
COPYLEFT = re.compile(r"\b(A?GPL|SSPL|EUPL|OSL|CPAL|RPL|Sleepycat)\b", re.I)
WEAK_COPYLEFT = re.compile(r"\b(LGPL|MPL|EPL|CDDL)\b", re.I)


@dataclass
class Finding:
    gate: str
    id: str                    # rule / advisory / check id
    severity: str
    title: str
    location: str = ""         # path[:line] or package@version
    fix_available: bool | None = None
    excepted_by: str | None = None
    blocking: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


# ── normalisers ─────────────────────────────────────────────────────────────

def _load(path: str | None) -> Any:
    if not path:
        return None
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return None
    return json.loads(p.read_text())


def cvss_to_severity(score: str | float | None) -> str:
    try:
        s = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "unknown"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "info"


def parse_gitleaks(data: Any) -> list[Finding]:
    out = []
    for r in data or []:
        loc = f"{r.get('File', '')}:{r.get('StartLine', '')}"
        commit = (r.get("Commit") or "")[:12]
        out.append(Finding(
            gate="secrets", id=r.get("Fingerprint") or r.get("RuleID", "secret"),
            severity="critical", title=f"{r.get('RuleID', 'secret')}: {r.get('Description', '')}".strip(),
            location=f"{loc} @ {commit}" if commit else loc,
            extra={"rule": r.get("RuleID")},
        ))
    return out


def parse_semgrep(data: Any) -> list[Finding]:
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    out = []
    for r in (data or {}).get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        # Prefer the rule's own impact/confidence when the registry supplies it.
        s = sev.get(extra.get("severity", ""), "unknown")
        if str(meta.get("impact", "")).upper() == "HIGH" and extra.get("severity") == "ERROR":
            s = "high"
        out.append(Finding(
            gate="sast", id=r.get("check_id", "semgrep"), severity=s,
            title=(extra.get("message") or "").strip().splitlines()[0][:200] if extra.get("message") else r.get("check_id", ""),
            location=f"{r.get('path', '')}:{r.get('start', {}).get('line', '')}",
            extra={"cwe": meta.get("cwe"), "owasp": meta.get("owasp")},
        ))
    return out


def _has_fix(vuln: dict) -> bool:
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    return True
    return False


def parse_osv(data: Any) -> tuple[list[Finding], list[Finding]]:
    """Returns (vulnerability findings, licence findings)."""
    vulns: list[Finding] = []
    lic: list[Finding] = []
    for res in (data or {}).get("results", []) or []:
        src = (res.get("source") or {}).get("path", "")
        for pkg in res.get("packages", []) or []:
            p = pkg.get("package", {}) or {}
            where = f"{p.get('ecosystem', '')}:{p.get('name', '')}@{p.get('version', '')}"
            by_id = {v.get("id"): v for v in pkg.get("vulnerabilities", []) or []}
            for grp in pkg.get("groups", []) or []:
                ids = grp.get("ids", []) or []
                primary = next((i for i in ids if i.startswith("GHSA-")), ids[0] if ids else "osv")
                fix = any(_has_fix(by_id[i]) for i in ids if i in by_id)
                summary = next((by_id[i].get("summary") for i in ids if i in by_id and by_id[i].get("summary")), "")
                vulns.append(Finding(
                    gate="sca", id=primary, severity=cvss_to_severity(grp.get("max_severity")),
                    title=summary or ", ".join(ids), location=f"{where} ({src})", fix_available=fix,
                    extra={"aliases": sorted(set(ids) | set(grp.get("aliases", []) or []))},
                ))
            for spdx in pkg.get("licenses", []) or []:
                name = spdx if isinstance(spdx, str) else str(spdx)
                if COPYLEFT.search(name):
                    s = "high"
                elif WEAK_COPYLEFT.search(name):
                    s = "medium"
                elif name.upper() in ("UNKNOWN", ""):
                    s = "low"
                else:
                    continue
                lic.append(Finding(gate="licence", id=f"{p.get('name', '')}:{name}", severity=s,
                                   title=f"Licence {name}", location=where))
    return vulns, lic


def parse_checkov(data: Any) -> list[Finding]:
    # checkov emits one object, or a list of them when several frameworks match.
    blocks = data if isinstance(data, list) else [data] if data else []
    out = []
    for b in blocks:
        if not isinstance(b, dict):
            continue
        for c in (b.get("results") or {}).get("failed_checks", []) or []:
            # Without a vendor API key checkov reports severity as null. Treat that as
            # "unknown" rather than inventing one: it is reported, and blocks only if the
            # caller lowers iac's block threshold to unknown.
            sev = (c.get("severity") or "unknown").lower()
            lines = c.get("file_line_range") or []
            out.append(Finding(
                gate="iac", id=c.get("check_id", "checkov"), severity=sev if sev in SEV_RANK else "unknown",
                title=c.get("check_name", ""),
                location=f"{(c.get('file_path') or '').lstrip('/')}:{lines[0] if lines else ''}",
                extra={"framework": b.get("check_type")},
            ))
    return out


USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)", re.M)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def check_action_pinning(workflow_dir: Path, trusted_owners: set[str]) -> list[Finding]:
    out = []
    if not workflow_dir.is_dir():
        return out
    for wf in sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml"))):
        text = wf.read_text(errors="replace")
        for m in USES_RE.finditer(text):
            ref = m.group(1)
            if ref.startswith("./") or ref.startswith("docker://"):
                if ref.startswith("docker://") and "@sha256:" not in ref:
                    line = text[: m.start()].count("\n") + 1
                    out.append(Finding("actions-pinning", ref, "medium", "Container action not pinned by digest",
                                       f"{wf.as_posix()}:{line}"))
                continue
            if "@" not in ref:
                continue
            target, version = ref.rsplit("@", 1)
            owner = target.split("/", 1)[0].lower()
            if SHA_RE.match(version) or owner in trusted_owners:
                continue
            line = text[: m.start()].count("\n") + 1
            out.append(Finding("actions-pinning", target, "medium",
                               f"Third-party action pinned to mutable ref '{version}', not a commit SHA",
                               f"{wf.as_posix()}:{line}"))
    return out


def check_dco(commits: Iterable[dict]) -> list[Finding]:
    out = []
    for c in commits:
        if c.get("parents", 1) > 1:     # merge commits are exempt
            continue
        if not re.search(r"^Signed-off-by: .+ <[^>]+>\s*$", c.get("message", ""), re.M):
            out.append(Finding("dco", c["sha"][:12], "medium", f"Commit lacks a Signed-off-by trailer: {c.get('subject', '')[:80]}",
                               c["sha"][:12]))
    return out


def read_commits(path: str | None) -> list[dict]:
    """Reads `git log --format=%H%x1f%P%x1f%s%x1f%B%x1e` output."""
    if not path or not Path(path).exists():
        return []
    out = []
    for rec in Path(path).read_text(errors="replace").split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        parts = rec.split("\x1f")
        if len(parts) < 4:
            continue
        out.append({"sha": parts[0], "parents": len(parts[1].split()), "subject": parts[2], "message": parts[3]})
    return out


# ── exception register ─────────────────────────────────────────────────────

def load_exceptions(path: Path, today: dt.date) -> tuple[list[dict], list[str]]:
    """Returns (valid, unexpired entries; problems). Problems always surface."""
    if not path.exists():
        return [], []
    raw = path.read_text()
    try:
        if path.suffix in (".yaml", ".yml"):
            import yaml  # type: ignore
            doc = yaml.safe_load(raw) or {}
        else:
            doc = json.loads(raw or "{}")
    except Exception as e:  # noqa: BLE001 — any parse failure is a register problem
        return [], [f"{path}: cannot parse ({e})"]
    entries = doc.get("exceptions", []) if isinstance(doc, dict) else []
    valid, problems = [], []
    for i, e in enumerate(entries):
        tag = f"{path}#{i} ({e.get('id', '?') if isinstance(e, dict) else '?'})"
        if not isinstance(e, dict):
            problems.append(f"{tag}: not a mapping")
            continue
        missing = [k for k in EXCEPTION_REQUIRED if not e.get(k)]
        if missing:
            problems.append(f"{tag}: missing {', '.join(missing)}")
            continue
        if e["reason"] not in EXCEPTION_REASONS:
            problems.append(f"{tag}: reason must be one of {sorted(EXCEPTION_REASONS)}")
            continue
        sev = str(e["severity"]).lower()
        if sev not in SEV_RANK:
            problems.append(f"{tag}: unknown severity {e['severity']}")
            continue
        try:
            approved = dt.date.fromisoformat(str(e["approved_on"]))
            expires = dt.date.fromisoformat(str(e["expires"]))
        except ValueError:
            problems.append(f"{tag}: approved_on/expires must be YYYY-MM-DD")
            continue
        if (expires - approved).days > MAX_EXCEPTION_DAYS[sev]:
            problems.append(f"{tag}: a {sev} exception may last at most {MAX_EXCEPTION_DAYS[sev]} days")
            continue
        if expires < today:
            problems.append(f"{tag}: expired {expires.isoformat()}")
            continue
        valid.append(e)
    return valid, problems


def match_exception(f: Finding, exceptions: list[dict]) -> str | None:
    for e in exceptions:
        if e["scanner"] != f.gate:
            continue
        ids = {f.id, *(f.extra.get("aliases") or [])}
        if f.extra.get("rule"):
            ids.add(f.extra["rule"])
        if e["id"] not in ids:
            continue
        glob = e.get("path")
        if glob and not fnmatch.fnmatch(f.location.split(":", 1)[0], glob):
            continue
        return e["id"]
    return None


# ── evaluation ─────────────────────────────────────────────────────────────

def evaluate(findings: list[Finding], exceptions: list[dict], block_at: dict[str, str],
             sca_require_fix: bool) -> None:
    for f in findings:
        f.excepted_by = match_exception(f, exceptions)
        threshold = block_at.get(f.gate)
        if threshold is None or f.excepted_by:
            continue
        if SEV_RANK.get(f.severity, SEV_RANK["unknown"]) <= SEV_RANK[threshold]:
            if f.gate == "sca" and sca_require_fix and f.fix_available is False:
                continue      # nothing to upgrade to; reported, and needs an exception to clear
            f.blocking = True


def render_summary(findings: list[Finding], coverage: list[dict], problems: list[str], mode: str,
                   failed: bool) -> str:
    lines = ["## Secure SDLC gate", ""]
    lines.append(f"**Mode:** `{mode}` · **Result:** {'blocking findings' if failed else ('findings reported, not enforced' if mode == 'report' and any(f.blocking for f in findings) else 'no blocking findings')}")
    lines += ["", "### Coverage", "", "| Gate | Scanner | Version | Scope | Findings | Blocking | Excepted |", "|---|---|---|---|---|---|---|"]
    for c in coverage:
        g = c["gate"]
        fs = [f for f in findings if f.gate == g]
        lines.append(f"| {g} | {c.get('scanner', '')} | {c.get('version', '')} | {c.get('scope', '')} | "
                     f"{len(fs)} | {sum(f.blocking for f in fs)} | {sum(bool(f.excepted_by) for f in fs)} |")
    lines += ["", "Zero findings means the listed scanners found nothing in the listed scope. "
              "It is a coverage statement, not a statement that the code is free of defects.", ""]
    if problems:
        lines += ["### Exception register problems", ""] + [f"- {p}" for p in problems] + [""]
    blocking = [f for f in findings if f.blocking]
    if blocking:
        lines += ["### Blocking findings", "", "| Gate | Severity | ID | Location | Title |", "|---|---|---|---|---|"]
        for f in sorted(blocking, key=lambda x: (SEV_RANK.get(x.severity, 9), x.gate))[:100]:
            lines.append(f"| {f.gate} | {f.severity} | `{f.id}` | `{f.location}` | {f.title.replace('|', '/')} |")
        if len(blocking) > 100:
            lines.append(f"| … | | | | {len(blocking) - 100} more in the evidence artifact |")
        lines += ["", "To clear a finding you cannot fix yet, add a time-boxed entry to `.security/exceptions.yaml`."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--mode", choices=("report", "enforce"), default="report")
    ap.add_argument("--gitleaks"); ap.add_argument("--semgrep"); ap.add_argument("--osv"); ap.add_argument("--checkov")
    ap.add_argument("--commits", help="git log dump for the DCO check")
    ap.add_argument("--workflows", default=".github/workflows")
    ap.add_argument("--trusted-action-owners", default="actions github syntropical")
    ap.add_argument("--exceptions", default=".security/exceptions.yaml")
    ap.add_argument("--coverage", help="JSON list of {gate, scanner, version, scope}")
    ap.add_argument("--block-at", default="", help="overrides, e.g. 'iac=unknown,sast=medium,dco=off'")
    ap.add_argument("--sca-require-fix", action="store_true", default=True)
    ap.add_argument("--evidence", default="sdlc-evidence.json")
    ap.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY", ""))
    ap.add_argument("--today", default="")
    a = ap.parse_args(argv)

    today = dt.date.fromisoformat(a.today) if a.today else dt.date.today()
    block_at = dict(DEFAULT_BLOCK_AT)
    for kv in filter(None, (s.strip() for s in a.block_at.split(","))):
        k, _, v = kv.partition("=")
        if v == "off":
            block_at.pop(k, None)
        elif v in SEV_RANK:
            block_at[k] = v
        else:
            print(f"::error::bad --block-at entry {kv!r}", file=sys.stderr)
            return 2

    findings: list[Finding] = []
    findings += parse_gitleaks(_load(a.gitleaks))
    findings += parse_semgrep(_load(a.semgrep))
    vulns, lic = parse_osv(_load(a.osv))
    findings += vulns + lic
    findings += parse_checkov(_load(a.checkov))
    owners = {o.lower() for o in a.trusted_action_owners.split()}
    findings += check_action_pinning(Path(a.workflows), owners)
    commits = read_commits(a.commits)
    findings += check_dco(commits)

    exceptions, problems = load_exceptions(Path(a.exceptions), today)
    evaluate(findings, exceptions, block_at, a.sca_require_fix)

    coverage = _load(a.coverage) or []
    has_blocking = any(f.blocking for f in findings)
    failed = (a.mode == "enforce" and (has_blocking or bool(problems)))

    if a.summary:
        with open(a.summary, "a") as fh:
            fh.write(render_summary(findings, coverage, problems, a.mode, failed))

    evidence = {
        "schema": "syntropical.dev/sdlc-evidence/v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "commit": os.environ.get("GITHUB_SHA", ""),
        "event": os.environ.get("GITHUB_EVENT_NAME", ""),
        "mode": a.mode,
        "result": "fail" if failed else "pass",
        "block_at": block_at,
        "coverage": coverage,
        "commits_checked": len(commits),
        "exceptions_applied": sorted({f.excepted_by for f in findings if f.excepted_by}),
        "exception_register_problems": problems,
        "counts": {g: {s: sum(1 for f in findings if f.gate == g and f.severity == s) for s in SEVERITIES}
                   for g in sorted({c.get("gate") for c in coverage} | {f.gate for f in findings})},
        "findings": [asdict(f) for f in findings],
    }
    Path(a.evidence).write_text(json.dumps(evidence, indent=2, default=str))

    for f in findings:
        if f.blocking:
            level = "error" if a.mode == "enforce" else "warning"
            path, _, line = f.location.partition(":")
            loc = f" file={path},line={line.split()[0]}" if line[:1].isdigit() else ""
            print(f"::{level}{loc}::[{f.gate}/{f.severity}] {f.id}: {f.title}")
    for p in problems:
        print(f"::{'error' if a.mode == 'enforce' else 'warning'}::exception register: {p}")
    print(f"secure-sdlc: {len(findings)} findings, {sum(f.blocking for f in findings)} blocking, "
          f"{len(problems)} register problems, mode={a.mode} -> {'FAIL' if failed else 'pass'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
