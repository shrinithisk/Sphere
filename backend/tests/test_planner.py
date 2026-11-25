import pytest
from app.planner.schema import (
    UnifiedFinding,
    Severity,
    Category,
    FixClass,
    FixType,
    normalize_finding,
)
from app.planner.planner import (
    create_fix_plan,
    FixPlan,
    PhasePlan,
)


def test_fix_plan_phase_order_and_categorization():
    raw_findings = [
        # Secret
        {"tool": "gitleaks", "id": "gitleaks-1", "file": ".env", "line": 2, "severity": "Critical", "description": "API Key"},
        # Code flaw
        {"tool": "semgrep", "id": "semgrep-sqli", "file": "db.py", "line": 34, "severity": "High", "description": "SQL Injection"},
        # Dependency
        {"tool": "osv", "id": "osv-requests", "package": "requests", "file": "requirements.txt", "severity": "Medium", "current_version": "2.20.0", "fixed_version": "2.31.0"},
        # Dockerfile
        {"tool": "hadolint", "id": "DL3002", "file": "Dockerfile", "line": 1, "severity": "High", "description": "Root user"},
        # Workflow
        {"tool": "actionlint", "id": "action-tag", "file": ".github/workflows/ci.yml", "line": 8, "severity": "Low", "description": "Pin SHA"},
    ]

    unified = [normalize_finding(r) for r in raw_findings]
    plan = create_fix_plan(unified, baseline_status="STATIC-VERIFIED (tests not run)")

    assert isinstance(plan, FixPlan)
    assert len(plan.phases) == 6

    # Verify exact phase numbering and sequence
    p1 = plan.phases[0]
    p2 = plan.phases[1]
    p3 = plan.phases[2]
    p4 = plan.phases[3]
    p5 = plan.phases[4]
    p6 = plan.phases[5]

    assert p1.phase_number == 1
    assert p1.category == Category.SECRET.value
    assert p1.auto_fixable is False
    assert len(p1.findings) == 1
    assert p1.findings[0].category == Category.SECRET

    assert p2.phase_number == 2
    assert p2.category == "baseline"
    assert p2.status == "STATIC-VERIFIED (tests not run)"

    assert p3.phase_number == 3
    assert p3.category == Category.DEPENDENCY.value
    assert p3.auto_fixable is True
    assert len(p3.findings) == 1
    assert p3.findings[0].package == "requests"

    assert p4.phase_number == 4
    assert p4.category == Category.CODE.value
    assert p4.auto_fixable is True
    assert len(p4.findings) == 1
    assert p4.findings[0].file == "db.py"

    assert p5.phase_number == 5
    assert p5.category == Category.DOCKER.value
    assert p5.auto_fixable is True
    assert len(p5.findings) == 1
    assert p5.findings[0].file == "Dockerfile"

    assert p6.phase_number == 6
    assert p6.category == Category.WORKFLOW.value
    assert p6.auto_fixable is True
    assert len(p6.findings) == 1
    assert p6.findings[0].file == ".github/workflows/ci.yml"


def test_secrets_never_marked_auto_fixable():
    secret_findings = [
        {"tool": "gitleaks", "id": "l1", "file": "keys.py", "line": 1, "severity": "Critical", "description": "Stripe key"},
        {"tool": "semgrep", "id": "generic.secrets.key", "file": "auth.py", "line": 10, "severity": "Critical", "description": "JWT Secret"},
    ]
    unified = [normalize_finding(r) for r in secret_findings]
    plan = create_fix_plan(unified)

    # All secrets must be quarantined into Phase 1
    p1 = plan.phases[0]
    assert len(p1.findings) == 2
    for f in p1.findings:
        assert f.fix_class == FixClass.MANUAL_ONLY
        assert f.fix_type == FixType.MANUAL

    # Other phases must have 0 findings
    for p in plan.phases[1:]:
        assert len(p.findings) == 0

    assert plan.auto_fixable_count == 0
    assert plan.manual_only_count == 2
