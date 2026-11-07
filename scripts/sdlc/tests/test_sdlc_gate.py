"""Tests for the secure-SDLC gate evaluator. Run: python -m pytest scripts/sdlc/tests -q"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sdlc_gate as g  # noqa: E402

TODAY = "2026-11-07"


def _w(tmp: Path, name: str, data) -> str:
    p = tmp / name
    p.write_text(data if isinstance(data, str) else json.dumps(data))
    return str(p)


OSV_HIGH_FIXABLE = {"results": [{"source": {"path": "uv.lock"}, "packages": [{
    "package": {"name": "jinja2", "version": "3.1.2", "ecosystem": "PyPI"},
    "vulnerabilities": [{"id": "GHSA-aaaa", "summary": "XSS in jinja2",
                         "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}]}]}],
    "groups": [{"ids": ["GHSA-aaaa", "PYSEC-1"], "aliases": ["CVE-2024-1"], "max_severity": "7.5"}],
    "licenses": ["BSD-3-Clause"],
}]}]}

OSV_HIGH_NOFIX = {"results": [{"source": {"path": "package-lock.json"}, "packages": [{
    "package": {"name": "leftpad", "version": "1.0.0", "ecosystem": "npm"},
    "vulnerabilities": [{"id": "GHSA-bbbb", "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}],
    "groups": [{"ids": ["GHSA-bbbb"], "max_severity": "8.1"}],
    "licenses": ["AGPL-3.0-only"],
}]}]}

SEMGREP = {"results": [
    {"check_id": "python.lang.security.audit.eval", "path": "src/x.py", "start": {"line": 3},
     "extra": {"severity": "ERROR", "message": "eval of untrusted input", "metadata": {}}},
    {"check_id": "python.style.thing", "path": "src/y.py", "start": {"line": 9},
     "extra": {"severity": "WARNING", "message": "meh", "metadata": {}}},
]}

GITLEAKS = [{"RuleID": "generic-api-key", "Description": "Generic API Key", "File": "deploy/a.env",
             "StartLine": 4, "Commit": "abcdef1234567890", "Fingerprint": "abcdef:deploy/a.env:generic-api-key:4"}]

CHECKOV = [{"check_type": "dockerfile", "results": {"failed_checks": [
    {"check_id": "CKV_DOCKER_3", "check_name": "Ensure a user is created", "file_path": "/Dockerfile",
     "file_line_range": [1, 20], "severity": None}]}}]


def run(tmp_path, mode="enforce", **files):
    args = ["--mode", mode, "--today", TODAY, "--workflows", str(tmp_path / "wf"),
            "--exceptions", str(tmp_path / "exceptions.yaml"),
            "--evidence", str(tmp_path / "ev.json"), "--summary", str(tmp_path / "summary.md")]
    for k, v in files.items():
        args += [f"--{k}", _w(tmp_path, f"{k}.json", v)]
    rc = g.main(args)
    return rc, json.loads((tmp_path / "ev.json").read_text()), (tmp_path / "summary.md").read_text()


def test_clean_inputs_pass_and_report_coverage_not_clearance(tmp_path):
    cov = [{"gate": "sast", "scanner": "semgrep", "version": "1", "scope": "whole tree"}]
    rc, ev, md = run(tmp_path, semgrep={"results": []}, coverage=cov)
    assert rc == 0 and ev["result"] == "pass"
    assert "coverage statement, not a statement that the code is free of defects" in md
    assert "no vulnerabilities" not in md.lower()


def test_high_sast_blocks_in_enforce_but_not_in_report(tmp_path):
    rc, ev, _ = run(tmp_path, semgrep=SEMGREP)
    assert rc == 1
    blocking = [f for f in ev["findings"] if f["blocking"]]
    assert [f["id"] for f in blocking] == ["python.lang.security.audit.eval"]
    rc2, ev2, _ = run(tmp_path, mode="report", semgrep=SEMGREP)
    assert rc2 == 0 and ev2["result"] == "pass"


def test_secret_always_blocks(tmp_path):
    rc, ev, _ = run(tmp_path, gitleaks=GITLEAKS)
    assert rc == 1 and ev["findings"][0]["gate"] == "secrets"


def test_sca_high_with_fix_blocks_without_fix_reports(tmp_path):
    rc, ev, _ = run(tmp_path, osv=OSV_HIGH_FIXABLE)
    assert rc == 1
    rc, ev, _ = run(tmp_path, osv=OSV_HIGH_NOFIX)
    sca = [f for f in ev["findings"] if f["gate"] == "sca"]
    assert sca and not sca[0]["blocking"] and sca[0]["fix_available"] is False
    # ...but its AGPL licence does block.
    assert rc == 1
    assert any(f["gate"] == "licence" and f["blocking"] for f in ev["findings"])


def test_exception_clears_finding_by_alias(tmp_path):
    (tmp_path / "exceptions.yaml").write_text(
        "exceptions:\n"
        "  - id: CVE-2024-1\n    scanner: sca\n    severity: high\n    reason: not_reachable\n"
        "    justification: template rendering never takes user input\n"
        "    approved_by: Security Owner\n    approved_on: 2026-11-01\n    expires: 2026-12-01\n")
    rc, ev, _ = run(tmp_path, osv=OSV_HIGH_FIXABLE)
    assert rc == 0
    assert ev["exceptions_applied"] == ["CVE-2024-1"]


def test_expired_or_overlong_exception_fails_enforce(tmp_path):
    (tmp_path / "exceptions.yaml").write_text(
        "exceptions:\n"
        "  - {id: X, scanner: sast, severity: critical, reason: accepted_risk, justification: j,"
        " approved_by: a, approved_on: 2026-09-01, expires: 2026-12-31}\n"
        "  - {id: Y, scanner: sast, severity: low, reason: false_positive, justification: j,"
        " approved_by: a, approved_on: 2026-01-01, expires: 2026-02-01}\n")
    rc, ev, md = run(tmp_path, semgrep={"results": []})
    assert rc == 1
    probs = ev["exception_register_problems"]
    assert any("at most 30 days" in p for p in probs) and any("expired" in p for p in probs)
    assert "Exception register problems" in md


def test_exception_path_glob_must_match(tmp_path):
    (tmp_path / "exceptions.yaml").write_text(
        "exceptions:\n"
        "  - {id: python.lang.security.audit.eval, scanner: sast, severity: high, reason: false_positive,"
        " justification: j, approved_by: a, approved_on: 2026-11-01, expires: 2026-12-01, path: 'tools/*'}\n")
    rc, _, _ = run(tmp_path, semgrep=SEMGREP)
    assert rc == 1


def test_checkov_null_severity_reported_not_blocking_by_default(tmp_path):
    rc, ev, _ = run(tmp_path, checkov=CHECKOV)
    assert rc == 0
    f = ev["findings"][0]
    assert f["severity"] == "unknown" and f["location"] == "Dockerfile:1"


def test_block_at_override(tmp_path):
    rc = g.main(["--mode", "enforce", "--today", TODAY, "--checkov", _w(tmp_path, "c.json", CHECKOV),
                 "--block-at", "iac=unknown", "--workflows", str(tmp_path / "none"),
                 "--exceptions", str(tmp_path / "none.yaml"), "--evidence", str(tmp_path / "e.json"), "--summary", ""])
    assert rc == 1


def test_action_pinning(tmp_path):
    wf = tmp_path / "wf"
    wf.mkdir()
    (wf / "ci.yml").write_text(
        "jobs:\n  a:\n    steps:\n"
        "      - uses: actions/checkout@v5\n"
        "      - uses: syntropical/actions/.github/workflows/python-ci.yml@v1\n"
        "      - uses: someone/tool@v2\n"
        "      - uses: someone/tool@0123456789abcdef0123456789abcdef01234567\n"
        "      - uses: ./local-action\n"
        "      - uses: docker://alpine:3\n")
    findings = g.check_action_pinning(wf, {"actions", "github", "syntropical"})
    assert sorted(f.id for f in findings) == ["docker://alpine:3", "someone/tool"]


def test_dco(tmp_path):
    log = ("a" * 40 + "\x1f" + "p1\x1f" + "feat: x\x1f" + "feat: x\n\nSigned-off-by: A B <a@b.c>\n\x1e"
           + "b" * 40 + "\x1f" + "p1\x1f" + "fix: y\x1f" + "fix: y\n\x1e"
           + "c" * 40 + "\x1f" + "p1 p2\x1f" + "Merge\x1f" + "Merge\n\x1e")
    commits = g.read_commits(_w(tmp_path, "log.txt", log))
    out = g.check_dco(commits)
    assert [f.id for f in out] == ["b" * 12]


@pytest.mark.parametrize("score,sev", [("9.8", "critical"), ("7.0", "high"), ("5", "medium"),
                                        ("0.1", "low"), (None, "unknown"), ("", "unknown")])
def test_cvss(score, sev):
    assert g.cvss_to_severity(score) == sev
