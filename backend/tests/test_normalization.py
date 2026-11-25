import pytest
from app.planner.schema import (
    normalize_finding,
    UnifiedFinding,
    Severity,
    Category,
    FixClass,
    FixType,
)


def test_gitleaks_normalization():
    raw = {
        "tool": "gitleaks",
        "id": "leak-detected",
        "rule_id": "aws-access-token",
        "file": "config/aws.py",
        "line": 14,
        "severity": "Critical",
        "description": "Potential leak of aws-access-token (AKIA...)",
        "code_snippet": "AWS_KEY = 'AKIA1234567890EXAMPLE'",
    }
    f = normalize_finding(raw)
    assert isinstance(f, UnifiedFinding)
    assert f.tool == "gitleaks"
    assert f.category == Category.SECRET
    assert f.fix_class == FixClass.MANUAL_ONLY
    assert f.fix_type == FixType.MANUAL
    assert f.severity == Severity.CRITICAL
    assert "MANUAL ROTATION REQUIRED" in f.suggested_fix
    assert "git-filter-repo" in f.suggested_fix or "scrub" in f.suggested_fix.lower()


def test_hadolint_normalization():
    raw = {
        "tool": "hadolint",
        "id": "DL3008",
        "file": "Dockerfile",
        "line": 4,
        "severity": "Medium",
        "description": "Pin versions in apt-get install",
        "fix_suggestion": "Pin packages explicitly with version",
    }
    f = normalize_finding(raw)
    assert f.tool == "hadolint"
    assert f.category == Category.DOCKER
    assert f.fix_class == FixClass.AUTO_VERIFIED
    assert f.rule_id == "DL3008"
    assert f.line == 4


def test_actionlint_sha_pinning_normalization():
    raw = {
        "tool": "actionlint",
        "id": "action-tag",
        "file": ".github/workflows/ci.yml",
        "line": 12,
        "severity": "High",
        "description": "Pin action commit SHA instead of branch tag",
    }
    f = normalize_finding(raw)
    assert f.tool == "actionlint"
    assert f.category == Category.WORKFLOW
    assert f.fix_class == FixClass.SAFE_AUTO
    assert f.fix_type == FixType.CONFIG_INSERT


def test_semgrep_code_issue_normalization():
    raw = {
        "tool": "semgrep",
        "id": "python.lang.security.deserialization.pickle",
        "file": "app/worker.py",
        "line": 45,
        "severity": "High",
        "description": "Avoid using pickle for untrusted data serialization",
        "fix_suggestion": "Use json or safer serializer",
        "cve": "CVE-2023-XXXX",
    }
    f = normalize_finding(raw)
    assert f.tool == "semgrep"
    assert f.category == Category.CODE
    assert f.fix_class == FixClass.AUTO_VERIFIED
    assert f.cve == "CVE-2023-XXXX"


def test_semgrep_credential_turns_into_manual_only():
    raw = {
        "tool": "semgrep",
        "id": "generic.secrets.security.detected-private-key",
        "file": "certs/server.pem",
        "line": 1,
        "severity": "Critical",
        "description": "Detected hardcoded private key",
    }
    f = normalize_finding(raw)
    assert f.category == Category.SECRET
    assert f.fix_class == FixClass.MANUAL_ONLY
    assert f.fix_type == FixType.MANUAL


def test_secrets_in_git_history_reported_with_commit_and_never_auto_fixed():
    # Requirement A2: Secrets found only in git history are reported as "found in commit X, rotate"
    # and never planned as auto-fixes.
    from app.planner.planner import create_fix_plan

    raw_history_secret = {
        "tool": "gitleaks",
        "id": "historic-leak-1",
        "rule_id": "stripe-secret-key",
        "file": "billing/stripe.py",
        "line": 25,
        "commit": "a1b2c3d4e5f67890",
        "is_history_leak": True,
        "description": "Potential leak of stripe-secret-key found in commit a1b2c3d",
    }
    finding = normalize_finding(raw_history_secret)
    assert finding.is_history_leak is True
    assert finding.commit == "a1b2c3d4e5f67890"
    assert "found in commit a1b2c3d" in finding.suggested_fix
    assert "rotate" in finding.suggested_fix.lower()
    assert finding.fix_class == FixClass.MANUAL_ONLY

    # Ensure Fix Plan strictly treats it as MANUAL_ONLY in Phase 1
    plan = create_fix_plan([finding])
    p1 = plan.phases[0]
    assert p1.phase_number == 1
    assert p1.auto_fixable is False
    assert len(p1.findings) == 1
    assert p1.findings[0].id == finding.id
    assert plan.auto_fixable_count == 0


def test_gitleaks_redaction_no_raw_secrets():
    # Requirement A3: Gitleaks runs with redaction. No raw secret values in report_json, UI, or findings
    raw_leak = {
        "tool": "gitleaks",
        "id": "github-pat",
        "rule_id": "github-pat",
        "file": "ci/deploy.py",
        "line": 10,
        "description": "Potential leak of github-pat (Secret: ghp_REAL_RAW_SECRET_LEAK_VAL)",
    }
    finding = normalize_finding(raw_leak)
    assert "ghp_REAL_RAW_SECRET_LEAK_VAL" not in finding.description
    assert "[REDACTED]" in finding.description


def test_osv_dependency_normalization():
    raw = {
        "tool": "osv",
        "id": "OSV-jinja2",
        "package": "jinja2",
        "current_version": "2.11.3",
        "fixed_version": "3.1.4",
        "file": "requirements.txt",
        "severity": "High",
        "cve": "CVE-2024-34064, CVE-2024-22195",
        "description": "Multiple XSS vulnerabilities in Jinja2",
    }
    f = normalize_finding(raw)
    assert f.tool == "osv"
    assert f.category == Category.DEPENDENCY
    assert f.fix_class == FixClass.AUTO_VERIFIED
    assert f.fix_type == FixType.VERSION_BUMP
    assert f.package == "jinja2"
    assert f.fixed_version == "3.1.4"
    assert f.resolved_issue_count == 2
