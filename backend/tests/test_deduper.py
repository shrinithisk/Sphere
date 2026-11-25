import pytest
from app.planner.schema import (
    UnifiedFinding,
    Severity,
    Category,
    FixClass,
    FixType,
)
from app.planner.deduper import (
    deduplicate_and_group,
    calculate_health_score,
    parse_semver_tuple,
)


def test_semver_parsing():
    assert parse_semver_tuple("3.1.4") == (3, 1, 4)
    assert parse_semver_tuple("2.0") == (2, 0, 0)
    assert parse_semver_tuple("v1.12.3-alpha") == (1, 12, 3)
    assert parse_semver_tuple(None) == (0, 0, 0)


def test_multi_cve_package_grouping():
    # 3 separate OSV findings for the same package 'urllib3'
    finding_1 = {
        "tool": "osv",
        "id": "GHSA-1",
        "package": "urllib3",
        "file": "requirements.txt",
        "current_version": "1.26.4",
        "fixed_version": "1.26.5",
        "severity": "Medium",
        "cve": "CVE-2021-33503",
        "description": "ReDoS in URL authority parsing",
    }
    finding_2 = {
        "tool": "osv",
        "id": "GHSA-2",
        "package": "urllib3",
        "file": "requirements.txt",
        "current_version": "1.26.4",
        "fixed_version": "1.26.17",
        "severity": "High",
        "cve": "CVE-2023-43804",
        "description": "Cookie leak on redirect",
    }
    finding_3 = {
        "tool": "osv",
        "id": "GHSA-3",
        "package": "urllib3",
        "file": "requirements.txt",
        "current_version": "1.26.4",
        "fixed_version": "1.26.18",
        "severity": "High",
        "cve": "CVE-2023-45803",
        "description": "Request body not stripped on redirect",
    }

    deduped, score_metrics = deduplicate_and_group([finding_1, finding_2, finding_3])

    # Should consolidate into exactly 1 finding
    assert len(deduped) == 1
    grouped = deduped[0]

    assert grouped.package == "urllib3"
    # Must pick the highest required fixed version (1.26.18)
    assert grouped.fixed_version == "1.26.18"
    assert grouped.resolved_issue_count == 3
    assert "1 fix resolves 3 issues" in grouped.suggested_fix
    assert "1 fix resolves 3 issues" in grouped.description
    assert grouped.severity == Severity.HIGH
    assert "CVE-2021-33503" in grouped.cve
    assert "CVE-2023-45803" in grouped.cve


def test_overlapping_file_line_deduplication():
    # Semgrep and Gitleaks both flag line 20 of main.py
    semgrep_finding = {
        "tool": "semgrep",
        "id": "generic.secrets.security.detected-token",
        "file": "main.py",
        "line": 20,
        "severity": "Medium",
        "description": "Hardcoded secret string detected",
    }
    gitleaks_finding = {
        "tool": "gitleaks",
        "id": "github-pat",
        "file": "main.py",
        "line": 20,
        "severity": "Critical",
        "description": "Potential leak of GitHub Personal Access Token",
    }

    deduped, score = deduplicate_and_group([semgrep_finding, gitleaks_finding])

    # Should merge into 1 finding at (main.py, 20)
    assert len(deduped) == 1
    merged = deduped[0]
    # Retains highest severity (Critical from Gitleaks)
    assert merged.severity == Severity.CRITICAL
    assert merged.category == Category.SECRET
    assert merged.fix_class == FixClass.MANUAL_ONLY
    assert merged.resolved_issue_count == 2
    assert "Also flagged by" in merged.description


def test_dedupe_strictest_fix_class_both_orderings():
    # Requirement A1: Dedupe keeps the strictest fix_class (MANUAL_ONLY wins),
    # e.g. Gitleaks + Semgrep on the same file/line stays MANUAL_ONLY regardless of encounter order.
    
    # Ordering 1: MANUAL_ONLY first (Gitleaks), AUTO_VERIFIED second (Semgrep)
    f_manual_first = [
        {"tool": "gitleaks", "id": "pat-leak", "file": "app.py", "line": 42, "severity": "Critical", "description": "Token leak"},
        {"tool": "semgrep", "id": "sast-hardcoded", "file": "app.py", "line": 42, "severity": "Medium", "description": "Hardcoded secret string"},
    ]
    deduped_1, _ = deduplicate_and_group(f_manual_first)
    assert len(deduped_1) == 1
    assert deduped_1[0].fix_class == FixClass.MANUAL_ONLY
    assert deduped_1[0].category == Category.SECRET

    # Ordering 2: AUTO_VERIFIED first (Semgrep), MANUAL_ONLY second (Gitleaks)
    f_auto_first = [
        {"tool": "semgrep", "id": "sast-hardcoded", "file": "app.py", "line": 42, "severity": "Medium", "description": "Hardcoded secret string"},
        {"tool": "gitleaks", "id": "pat-leak", "file": "app.py", "line": 42, "severity": "Critical", "description": "Token leak"},
    ]
    deduped_2, _ = deduplicate_and_group(f_auto_first)
    assert len(deduped_2) == 1
    assert deduped_2[0].fix_class == FixClass.MANUAL_ONLY
    assert deduped_2[0].category == Category.SECRET
    assert deduped_2[0].severity == Severity.CRITICAL


def test_grouped_dependency_sets_is_major_bump():
    # Requirement A4: is_major_bump is set on grouped dependency findings
    
    # Major bump: 1.2.0 -> 2.0.0
    major_findings = [
        {"tool": "osv", "id": "GHSA-m1", "package": "requests", "file": "requirements.txt", "current_version": "1.2.0", "fixed_version": "1.5.0", "severity": "Medium"},
        {"tool": "osv", "id": "GHSA-m2", "package": "requests", "file": "requirements.txt", "current_version": "1.2.0", "fixed_version": "2.0.0", "severity": "High"},
    ]
    deduped_major, _ = deduplicate_and_group(major_findings)
    assert len(deduped_major) == 1
    assert deduped_major[0].is_major_bump is True
    assert deduped_major[0].fixed_version == "2.0.0"

    # Non-major bump: 1.2.0 -> 1.3.1
    minor_findings = [
        {"tool": "osv", "id": "GHSA-n1", "package": "requests", "file": "requirements.txt", "current_version": "1.2.0", "fixed_version": "1.3.0", "severity": "Medium"},
        {"tool": "osv", "id": "GHSA-n2", "package": "requests", "file": "requirements.txt", "current_version": "1.2.0", "fixed_version": "1.3.1", "severity": "High"},
    ]
    deduped_minor, _ = deduplicate_and_group(minor_findings)
    assert len(deduped_minor) == 1
    assert deduped_minor[0].is_major_bump is False
    assert deduped_minor[0].fixed_version == "1.3.1"


def test_score_recalculation_after_dedup():
    findings = [
        {"tool": "hadolint", "id": "DL3008", "file": "Dockerfile", "line": 5, "severity": "Medium"},
        {"tool": "actionlint", "id": "action-tag", "file": ".github/workflows/build.yml", "line": 10, "severity": "Low"},
        {"tool": "osv", "id": "GHSA-1", "package": "pkg1", "file": "requirements.txt", "severity": "High", "current_version": "1.0", "fixed_version": "1.1"},
        {"tool": "osv", "id": "GHSA-2", "package": "pkg1", "file": "requirements.txt", "severity": "High", "current_version": "1.0", "fixed_version": "1.2"},
    ]

    deduped, score = deduplicate_and_group(findings)
    # 4 raw findings -> 3 deduped (the 2 OSV findings for pkg1 merge into 1 High)
    assert len(deduped) == 3

    # Deduction: 1 High (15) + 1 Medium (5) + 1 Low (1) = 21
    # Expected score: 100 - 21 = 79
    assert score["deduction"] == 21
    assert score["repo_score"] == 79
