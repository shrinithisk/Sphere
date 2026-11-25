import os
import pytest
from app.planner.schema import (
    UnifiedFinding,
    Category,
    FixClass,
    FixType,
    FixStatus,
)
from app.planner.planner import create_fix_plan
from app.verifier.runner import run_verification_loop


@pytest.mark.asyncio
async def test_breaking_fix_is_reverted_with_log_attached(tmp_path):
    # Setup test project
    src_dir = tmp_path / "broken_test_repo"
    src_dir.mkdir()
    code_file = src_dir / "worker.py"
    code_file.write_text("def process_data(x):\n    return x * 2\n")

    # A broken patch that introduces fatal Python syntax error
    broken_finding = UnifiedFinding(
        id="SEMGREP-test-broken",
        tool="semgrep",
        rule_id="broken-patch-rule",
        file="worker.py",
        line=2,
        category=Category.CODE,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Broken syntax fix",
        original_block="return x * 2",
        patched_block="return x * ::: syntax error :::",
    )

    plan = create_fix_plan([broken_finding])
    result = await run_verification_loop(str(src_dir), plan)

    # Must NOT have applied the broken fix
    assert result.total_applied == 0
    assert result.total_reverted == 1
    assert result.commit_count == 0

    reverted = result.reverted_fixes[0]
    assert reverted.status == FixStatus.REVERTED
    assert "STATIC SYNTAX CHECK FAILED" in reverted.verification_log
    assert "syntax" in reverted.verification_log.lower()

    # Verify original code file in source repo remains clean
    with open(str(code_file), "r") as f:
        assert "x * 2" in f.read()


@pytest.mark.asyncio
async def test_clean_fix_is_verified_and_committed(tmp_path):
    src_dir = tmp_path / "clean_test_repo"
    src_dir.mkdir()
    req_file = src_dir / "requirements.txt"
    req_file.write_text("urllib3==1.26.4\n")

    valid_finding = UnifiedFinding(
        id="OSV-urllib3",
        tool="osv",
        rule_id="CVE-2023-45803",
        file="requirements.txt",
        category=Category.DEPENDENCY,
        fix_type=FixType.VERSION_BUMP,
        fix_class=FixClass.AUTO_VERIFIED,
        package="urllib3",
        current_version="1.26.4",
        fixed_version="1.26.18",
        suggested_fix="Upgrade urllib3 to 1.26.18",
        original_block="urllib3==1.26.4",
        patched_block="urllib3==1.26.18",
    )

    plan = create_fix_plan([valid_finding])
    result = await run_verification_loop(str(src_dir), plan)

    assert result.total_applied == 1
    assert result.total_reverted == 0
    assert result.commit_count == 1
    assert result.applied_fixes[0].status == FixStatus.VERIFIED
    # Requirement B1: STATIC-VERIFIED set only after static checks pass
    assert result.verification_label == "STATIC-VERIFIED (tests not run)"
    assert result.baseline_profile.static_checks_passed is True
    assert "STATIC-VERIFIED" in result.applied_fixes[0].verification_log
    assert "urllib3==1.26.18" in result.unified_diff


@pytest.mark.asyncio
async def test_rescan_reverts_if_target_finding_still_present(tmp_path):
    # Requirement B3: Reverted if its target finding is still present afterwards (using stable fingerprints)
    src_dir = tmp_path / "target_still_present_repo"
    src_dir.mkdir()
    code_file = src_dir / "app.py"
    code_file.write_text("API_ENDPOINT = 'http://insecure.internal'\n")

    finding = UnifiedFinding(
        id="SEMGREP-insecure-transport",
        tool="semgrep",
        rule_id="insecure-transport",
        file="app.py",
        line=1,
        category=Category.CODE,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Upgrade to https",
        original_block="http://insecure.internal",
        patched_block="https://insecure.internal",
    )

    # Mock rescan_callback that reports the target finding is STILL present
    async def mock_rescan(sandbox_path):
        return {
            "findings": [
                {
                    "rule_id": "insecure-transport",
                    "file": "app.py",
                    "code_snippet": None,
                    "description": None,
                }
            ]
        }

    plan = create_fix_plan([finding])
    result = await run_verification_loop(str(src_dir), plan, rescan_callback=mock_rescan)

    assert result.total_applied == 0
    assert result.total_reverted == 1
    assert result.reverted_fixes[0].status == FixStatus.REVERTED
    assert "still detected in rescan" in result.reverted_fixes[0].verification_log
    assert result.verification_label == "UNVERIFIED"


@pytest.mark.asyncio
async def test_rescan_reverts_if_new_findings_introduced(tmp_path):
    # Requirement B3: Stable fingerprint regression detection
    src_dir = tmp_path / "regression_repo"
    src_dir.mkdir()
    code_file = src_dir / "app.py"
    code_file.write_text("x = 1\n")

    finding = UnifiedFinding(
        id="SEMGREP-safe-fix",
        tool="semgrep",
        rule_id="rule-a",
        file="app.py",
        line=1,
        category=Category.CODE,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Update x",
        original_block="x = 1",
        patched_block="x = 2",
    )

    call_count = 0
    async def mock_rescan(sandbox_path):
        nonlocal call_count
        call_count += 1
        # First call is baseline (empty)
        if call_count == 1:
            return {"findings": []}
        # Second call reports a new regression finding introduced by patch
        return {
            "findings": [
                {
                    "rule_id": "new-regression-rule",
                    "file": "app.py",
                    "code_snippet": "x = 2",
                }
            ]
        }

    plan = create_fix_plan([finding])
    result = await run_verification_loop(str(src_dir), plan, rescan_callback=mock_rescan)

    assert result.total_applied == 0
    assert result.total_reverted == 1
    assert "new regression finding" in result.reverted_fixes[0].verification_log
    assert result.verification_label == "UNVERIFIED"


@pytest.mark.asyncio
async def test_bisection_on_batch_failure(tmp_path):
    # Requirement B4: Bisect on batch failure to isolate and revert only the failing fix
    src_dir = tmp_path / "batch_bisect_repo"
    src_dir.mkdir()
    (src_dir / ".github" / "workflows").mkdir(parents=True)
    wf_file = src_dir / ".github" / "workflows" / "deploy.yml"
    wf_file.write_text("name: Deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n      - uses: actions/setup-python@0a5c61591373683505ea898e09a3ea4f39ef2b9c\n")

    good_fix = UnifiedFinding(
        id="WORKFLOW-pin-checkout",
        tool="actionlint",
        rule_id="pin-sha-checkout",
        file=".github/workflows/deploy.yml",
        category=Category.WORKFLOW,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.SAFE_AUTO,
        suggested_fix="Pin checkout SHA",
        original_block="actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
        patched_block="actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4",
    )

    bad_fix = UnifiedFinding(
        id="WORKFLOW-pin-python",
        tool="actionlint",
        rule_id="pin-sha-python",
        file=".github/workflows/deploy.yml",
        category=Category.WORKFLOW,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.SAFE_AUTO,
        suggested_fix="Pin python SHA",
        original_block="actions/setup-python@0a5c61591373683505ea898e09a3ea4f39ef2b9c",
        patched_block="actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5 --with-bad-trigger",
    )

    # Rescan callback that reports regression ONLY if bad_fix is present in sandbox
    async def mock_rescan(sandbox_path):
        target = os.path.join(sandbox_path, ".github", "workflows", "deploy.yml")
        content = open(target).read() if os.path.exists(target) else ""
        if "--with-bad-trigger" in content:
            return {"findings": [{"rule_id": "bad-trigger-regression", "file": ".github/workflows/deploy.yml"}]}
        return {"findings": []}

    plan = create_fix_plan([good_fix, bad_fix])
    result = await run_verification_loop(str(src_dir), plan, rescan_callback=mock_rescan)

    # Bisection should have salvaged good_fix and reverted bad_fix
    assert result.total_applied == 1
    assert result.total_reverted == 1
    assert result.applied_fixes[0].id == "WORKFLOW-pin-checkout"
    assert result.reverted_fixes[0].id == "WORKFLOW-pin-python"
    assert result.verification_label == "STATIC-VERIFIED (tests not run)"


@pytest.mark.asyncio
async def test_secrets_never_auto_fixed_in_verification_loop(tmp_path):
    src_dir = tmp_path / "secrets_repo"
    src_dir.mkdir()
    env_file = src_dir / ".env"
    env_file.write_text("AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n")

    secret_finding = UnifiedFinding(
        id="GITLEAKS-aws-key",
        tool="gitleaks",
        rule_id="aws-access-token",
        file=".env",
        line=1,
        category=Category.SECRET,
        fix_type=FixType.MANUAL,
        fix_class=FixClass.MANUAL_ONLY,
        suggested_fix="Manual secret rotation required",
    )

    plan = create_fix_plan([secret_finding])
    result = await run_verification_loop(str(src_dir), plan)

    # Must be quarantined as manual only
    assert result.total_applied == 0
    assert len(result.manual_only_fixes) == 1
    assert result.manual_only_fixes[0].status == FixStatus.MANUAL
    assert "MANUAL ACTION ONLY" in result.manual_only_fixes[0].verification_log
    assert result.commit_count == 0
