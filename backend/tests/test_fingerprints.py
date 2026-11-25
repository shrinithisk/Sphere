import pytest
from app.verifier.fingerprint import compute_finding_fingerprint
from app.planner.schema import UnifiedFinding, Category, FixClass, FixType


def test_osv_fingerprint_no_snippet():
    # Requirement 4: Fingerprint for OSV findings with no snippet:
    # package + advisory id + manifest file, with whitespace normalization
    fp1 = compute_finding_fingerprint(
        rule_id="GHSA-1234-abcd",
        file_path="requirements.txt",
        snippet=None,
        tool="osv",
        package="urllib3",
    )
    # Same data with different path casing / formatting or whitespace
    fp2 = compute_finding_fingerprint(
        rule_id="  GHSA-1234-ABCD  ",
        file_path="./requirements.txt",
        snippet="",
        tool="OSV",
        package=" URLLIB3 ",
    )
    assert fp1 == fp2
    assert isinstance(fp1, str)
    assert len(fp1) == 64  # SHA-256


def test_osv_unified_finding_fingerprint():
    # Test OSV finding via UnifiedFinding model
    finding = UnifiedFinding(
        id="OSV-requests-requirements.txt",
        tool="osv",
        rule_id="GHSA-j8r2-6x86-q33q",
        file="requirements.txt",
        package="requests",
        category=Category.DEPENDENCY,
        fix_type=FixType.VERSION_BUMP,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Upgrade requests",
        code_snippet=None,  # No snippet for OSV
    )
    assert finding.fingerprint is not None
    # Compute expected fingerprint directly
    expected = compute_finding_fingerprint(
        rule_id="GHSA-j8r2-6x86-q33q",
        file_path="requirements.txt",
        snippet=None,
        tool="osv",
        package="requests",
    )
    assert finding.fingerprint == expected


def test_linter_fingerprint_normalized_line_text():
    # Requirement 4: Linters with no snippet use normalized line text with whitespace collapsed
    fp_tab = compute_finding_fingerprint(
        rule_id="hadolint-DL3008",
        file_path="Dockerfile",
        line_text="apt-get   install   -y   curl\t\tbuild-essential\n",
    )
    fp_space = compute_finding_fingerprint(
        rule_id="hadolint-DL3008",
        file_path="./Dockerfile",
        line_text="apt-get install -y curl build-essential",
    )
    assert fp_tab == fp_space
