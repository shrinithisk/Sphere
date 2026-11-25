import os
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app, _verification_tasks
from app.auth import create_access_token
from app.database import get_db_connection
from app.planner.schema import UnifiedFinding, Category, FixClass, FixStatus, Severity, FixType
from app.pr_builder.pr_grouper import group_fixes_by_pr, build_pr_body
from app.pr_builder.publisher import publish_verified_fixes_to_github, compute_git_blob_sha


@pytest.fixture
def auth_headers():
    token = create_access_token(data={"sub": "m3user", "user_id": 401})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_user_scan(auth_headers):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = 777")
    cursor.execute("DELETE FROM scans WHERE id = 778")
    
    # 777: GitHub scan
    cursor.execute("""
        INSERT INTO scans (id, user_id, repo_url, repo_name, status, score, report_json, commit_sha, verification_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        777,
        401,
        "https://github.com/shrinithisk/Sphere",
        "Sphere",
        "Completed",
        85,
        json.dumps({
            "findings": [
                {
                    "id": "CODE-1",
                    "tool": "semgrep",
                    "rule_id": "hardcoded-jwt-secret",
                    "file": "app/auth.py",
                    "line": 10,
                    "severity": "High",
                    "description": "Hardcoded JWT secret detected",
                    "code_snippet": "SECRET = 'static-key'",
                    "fix_suggestion": "SECRET = os.getenv('JWT_SECRET_KEY')",
                }
            ]
        }),
        "abcdef1234567890abcdef1234567890abcdef12",
        json.dumps({
            "status": "COMPLETED",
            "verification_label": "STATIC-VERIFIED (tests not run)",
            "total_applied": 1,
            "total_reverted": 0,
            "commit_count": 1,
            "unified_diff": "diff --git a/app/auth.py b/app/auth.py\n--- a/app/auth.py\n+++ b/app/auth.py\n@@ -10 +10 @@\n-SECRET = 'static-key'\n+SECRET = os.getenv('JWT_SECRET_KEY')",
            "applied_fixes": [
                {
                    "id": "CODE-1",
                    "tool": "semgrep",
                    "rule_id": "hardcoded-jwt-secret",
                    "file": "app/auth.py",
                    "line": 10,
                    "severity": "High",
                    "category": "code",
                    "fix_type": "line_replace",
                    "fix_class": "AUTO_VERIFIED",
                    "suggested_fix": "Use environment variable",
                    "confidence": 0.9,
                    "is_major_bump": False,
                    "draft_pr_only": True,
                    "original_block": "SECRET = 'static-key'",
                    "patched_block": "SECRET = os.getenv('JWT_SECRET_KEY')",
                }
            ],
            "reverted_fixes": [],
            "manual_only_fixes": [],
            "major_bump_fixes": [],
        }),
    ))

    # 778: ZIP scan
    cursor.execute("""
        INSERT INTO scans (id, user_id, repo_url, repo_name, status, score, report_json, commit_sha, verification_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        778,
        401,
        "ZIP Upload: archive.zip",
        "archive.zip",
        "Completed",
        90,
        json.dumps({"findings": []}),
        None,
        json.dumps({
            "status": "COMPLETED",
            "verification_label": "STATIC-VERIFIED (tests not run)",
            "unified_diff": "diff --git a/vuln.py b/vuln.py\n+fixed_code",
            "applied_fixes": [],
        }),
    ))

    conn.commit()
    conn.close()
    yield 777
    
    # Cleanup
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scans WHERE id IN (777, 778)")
    conn.commit()
    conn.close()


def test_semgrep_llm_fixes_always_produce_draft_prs():
    """Requirement: Semgrep/LLM fixes always produce draft PRs."""
    finding = UnifiedFinding(
        id="SEMGREP-1",
        tool="semgrep",
        rule_id="python.lang.security.insecure-deserialization",
        file="worker.py",
        line=15,
        category=Category.CODE,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Replace pickle.loads with safe deserializer",
        original_block="pickle.loads(data)",
        patched_block="json.loads(data)",
    )

    groups = group_fixes_by_pr([finding])
    assert "code" in groups
    code_group = groups["code"]
    assert code_group["branch"] == "sphere/fix-code"
    assert code_group["draft_pr_only"] is True
    assert len(code_group["fixes"]) == 1

    pr_body = build_pr_body(code_group, verification_label="STATIC-VERIFIED (tests not run)")
    assert "Draft Pull Request" in pr_body
    assert "Code Remediations" in pr_body
    assert "worker.py" in pr_body


def test_major_bumps_always_go_to_separate_draft_pr():
    """Requirement: Major bumps always go to a separate draft PR."""
    minor_dep = UnifiedFinding(
        id="OSV-patch-1",
        tool="osv",
        rule_id="CVE-2023-1001",
        file="package.json",
        category=Category.DEPENDENCY,
        package="lodash",
        current_version="4.17.20",
        fixed_version="4.17.21",
        is_major_bump=False,
        suggested_fix="Upgrade lodash to 4.17.21",
        patched_block='"lodash": "4.17.21"',
    )

    major_dep = UnifiedFinding(
        id="OSV-major-1",
        tool="osv",
        rule_id="CVE-2024-9999",
        file="package.json",
        category=Category.DEPENDENCY,
        package="express",
        current_version="4.18.2",
        fixed_version="5.0.0",
        is_major_bump=True,
        suggested_fix="Upgrade express to 5.0.0 (breaking changes)",
        patched_block='"express": "5.0.0"',
    )

    groups = group_fixes_by_pr([minor_dep, major_dep])
    assert "dependencies_minor" in groups
    assert "dependencies_major" in groups

    minor_group = groups["dependencies_minor"]
    assert minor_group["branch"] == "sphere/fix-dependencies-patch"
    assert minor_group["is_major_pr"] is False
    assert len(minor_group["fixes"]) == 1
    assert minor_group["fixes"][0].package == "lodash"

    major_group = groups["dependencies_major"]
    assert major_group["branch"] == "sphere/fix-dependencies-major"
    assert major_group["is_major_pr"] is True
    assert major_group["draft_pr_only"] is True
    assert len(major_group["fixes"]) == 1
    assert major_group["fixes"][0].package == "express"

    major_body = build_pr_body(major_group, verification_label="STATIC-VERIFIED (tests not run)")
    assert "Major Version Bumps Detected" in major_body
    assert "HIGH (Major version upgrades may introduce breaking API changes)" in major_body
    assert "Draft Pull Request" in major_body


@pytest.mark.asyncio
async def test_upstream_blob_sha_mismatch_skips_fix_as_stale(tmp_path):
    """
    Requirement: Before pushing, verify each target file's blob SHA on the default branch
    still matches the verified baseline. If not, skip that fix as 'stale, rescan needed'.
    """
    repo_dir = tmp_path / "baseline_repo"
    repo_dir.mkdir()
    target_file = repo_dir / "app.py"
    target_file.write_text("API_KEY = 'old_secret'\n")

    finding = UnifiedFinding(
        id="TEST-STALE-1",
        tool="semgrep",
        rule_id="hardcoded-key",
        file="app.py",
        category=Category.CODE,
        suggested_fix="Rotate key",
        original_block="API_KEY = 'old_secret'",
        patched_block="API_KEY = os.getenv('API_KEY')",
    )

    with patch("app.pr_builder.publisher.GitHubClient") as MockClient:
        mock_instance = MockClient.return_value
        mock_instance.get_default_branch = AsyncMock(return_value="main")
        mock_instance.get_ref_commit_sha = AsyncMock(return_value="head123456")
        mock_instance.get_default_branch_ci_details = AsyncMock(return_value={"status": "PASSING", "check_runs": [], "workflow_runs": []})
        mock_instance.get_default_branch_ci_status = AsyncMock(return_value="PASSING")

        # Remote file has DIFFERENT blob SHA (e.g. someone pushed upstream)
        mock_instance.get_file_blob_sha = AsyncMock(return_value="completely_different_upstream_blob_sha")

        result = await publish_verified_fixes_to_github(
            repo_url="https://github.com/shrinithisk/Sphere",
            verified_fixes=[finding],
            token="ghp_fake1234567890abcdef1234567890abcdef",
            baseline_repo_path=str(repo_dir),
        )

        assert len(result["skipped_stale_fixes"]) == 1
        skipped = result["skipped_stale_fixes"][0]
        assert skipped["finding_id"] == "TEST-STALE-1"
        assert skipped["file"] == "app.py"
        assert "stale, rescan needed" in skipped["reason"]
        # No PR was published because all fixes in group were skipped
        assert len(result["pull_requests"]) == 0


def test_zip_scans_cannot_open_prs_and_provide_downloadable_patch(test_user_scan, auth_headers):
    """Requirement: ZIP scans cannot open PRs: return a downloadable patch/diff instead."""
    client = TestClient(app)

    # 1. Attempt to publish PR for ZIP scan (ID 778) -> must fail with 400
    resp_publish = client.post(
        "/api/scans/778/publish-prs",
        headers={**auth_headers, "X-GitHub-Token": "ghp_mocktoken1234567890abcdef"},
    )
    assert resp_publish.status_code == 400
    assert "ZIP scans cannot open Pull Requests" in resp_publish.json()["detail"]
    assert "Download the verified patch/diff instead" in resp_publish.json()["detail"]

    # 2. Request patch download for ZIP scan (ID 778)
    resp_patch = client.get("/api/scans/778/patch", headers=auth_headers)
    assert resp_patch.status_code == 200
    assert resp_patch.headers["content-type"].startswith("text/plain")
    assert "attachment; filename=sphere-scan-778.patch" in resp_patch.headers["content-disposition"]
    assert "diff --git a/vuln.py b/vuln.py" in resp_patch.text


def test_verification_background_job_and_status(test_user_scan, auth_headers):
    """Requirement: POST /api/scans/{id}/verify as background job and status endpoint."""
    client = TestClient(app)

    # Clean in-memory task store
    if 777 in _verification_tasks:
        del _verification_tasks[777]

    # Check initial status
    resp_status = client.get("/api/scans/777/verify/status", headers=auth_headers)
    assert resp_status.status_code == 200
    status_data = resp_status.json()
    assert status_data["status"] == "COMPLETED"
    assert status_data["verification_label"] == "STATIC-VERIFIED (tests not run)"

    # Trigger background verification
    with patch("app.main.run_scan_verification_background") as mock_bg:
        resp_trigger = client.post("/api/scans/777/verify", headers=auth_headers)
        assert resp_trigger.status_code == 200
        data = resp_trigger.json()
        assert data["status"] == "RUNNING"
        assert data["scan_id"] == 777
        assert "started" in data["message"].lower() or "progress" in data["message"].lower()
        mock_bg.assert_called_once()


@pytest.mark.asyncio
async def test_run_scan_verification_background_execution(tmp_path):
    """Tests the background verification worker logic with mocked clone & verification loop."""
    from app.main import run_scan_verification_background
    mock_scan_row = {
        "id": 901,
        "repo_url": "https://github.com/shrinithisk/Sphere",
        "commit_sha": "headsha123",
        "report_json": json.dumps({"findings": []}),
    }

    with patch("git.Repo.clone_from") as mock_clone, \
         patch("app.main.run_verification_loop") as mock_loop:
        mock_loop.return_value = MagicMock(
            verification_label="STATIC-VERIFIED (tests not run)",
            total_applied=0,
            total_reverted=0,
            commit_count=0,
            unified_diff="",
            applied_fixes=[],
            reverted_fixes=[],
            manual_only_fixes=[],
            major_bump_fixes=[],
            logs=[],
        )

        await run_scan_verification_background(901, mock_scan_row, user_id=401)
        assert 901 in _verification_tasks
        assert _verification_tasks[901]["status"] == "COMPLETED"
        assert _verification_tasks[901]["verification_label"] == "STATIC-VERIFIED (tests not run)"


@pytest.mark.asyncio
async def test_git_data_api_atomic_pr_publishing_flow(tmp_path):
    """
    Requirement: Pushes via Git Data API (in-memory PAT only), one commit per verified fix,
    PRs opened in Draft mode, and CI status polled.
    """
    repo_dir = tmp_path / "git_data_repo"
    repo_dir.mkdir()
    app_file = repo_dir / "app.py"
    app_file.write_text("SECRET_VAL = 'hardcoded'\n")

    local_blob_sha = compute_git_blob_sha("SECRET_VAL = 'hardcoded'\n")

    finding1 = UnifiedFinding(
        id="FIX-1",
        tool="semgrep",
        rule_id="hardcoded-secret",
        file="app.py",
        category=Category.CODE,
        suggested_fix="Use env var",
        original_block="SECRET_VAL = 'hardcoded'",
        patched_block="SECRET_VAL = os.getenv('SECRET_VAL')",
    )

    with patch("app.pr_builder.publisher.GitHubClient") as MockClient:
        client_mock = MockClient.return_value
        client_mock.get_default_branch = AsyncMock(return_value="main")
        client_mock.get_ref_commit_sha = AsyncMock(return_value="main_sha_000")
        client_mock.get_default_branch_ci_details = AsyncMock(return_value={"status": "PASSING", "check_runs": [], "workflow_runs": []})
        client_mock.get_default_branch_ci_status = AsyncMock(return_value="PASSING")
        client_mock.get_file_blob_sha = AsyncMock(return_value=local_blob_sha)
        client_mock.create_blob = AsyncMock(return_value="blob_new_111")
        client_mock.create_tree = AsyncMock(return_value="tree_new_222")
        client_mock.create_commit = AsyncMock(return_value="commit_new_333")
        client_mock.create_or_update_branch = AsyncMock(return_value=True)
        client_mock.create_pull_request = AsyncMock(return_value={
            "number": 42,
            "node_id": "PR_node_abc123",
            "html_url": "https://github.com/shrinithisk/Sphere/pull/42",
        })
        client_mock.get_check_runs = AsyncMock(return_value={"all_passed": True, "runs": []})
        client_mock.poll_check_runs = AsyncMock(return_value={"total_count": 1, "all_completed": True, "all_passed": True, "status": "PASSING"})
        client_mock.mark_pr_ready_for_review = AsyncMock(return_value=True)

        res = await publish_verified_fixes_to_github(
            repo_url="https://github.com/shrinithisk/Sphere",
            verified_fixes=[finding1],
            token="ghp_mock_pat_in_memory_only",
            baseline_repo_path=str(repo_dir),
        )

        assert res["status"] == "SUCCESS"
        assert len(res["pull_requests"]) == 1
        pr = res["pull_requests"][0]
        assert pr["branch"] == "sphere/fix-code"
        assert pr["pr_number"] == 42
        assert pr["commit_count"] == 1
        assert "commit_new_333" in pr["commits"]

        # Assert Git Data API methods were called
        client_mock.create_blob.assert_called_once()
        client_mock.create_tree.assert_called_once()
        client_mock.create_commit.assert_called_once()
        # Code fixes remain draft PR
        assert pr["draft"] is True


@pytest.mark.asyncio
async def test_ci_scenarios_passing_failing_never_starting_and_baseline_red():
    """
    Requirement 1: Tests with a mocked GitHub client for:
    - CI passing (non-code, non-major PR marks ready for review)
    - CI failing (PR remains draft)
    - CI never starting (PR remains draft with CI_NEVER_STARTED status)
    - Baseline already red (default branch CI failed, recorded in baseline metadata)
    """
    docker_finding = UnifiedFinding(
        id="DOCKER-1",
        tool="hadolint",
        rule_id="DL3002",
        file="Dockerfile",
        category=Category.DOCKER,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Run as non-root user",
        original_block="USER root",
        patched_block="USER 1001",
    )

    # 1. CI Passing scenario
    with patch("app.pr_builder.publisher.GitHubClient") as MockClient:
        c = MockClient.return_value
        c.get_default_branch = AsyncMock(return_value="main")
        c.get_ref_commit_sha = AsyncMock(return_value="main_head_sha")
        c.get_default_branch_ci_details = AsyncMock(return_value={"status": "PASSING", "check_runs": [], "workflow_runs": []})
        c.get_default_branch_ci_status = AsyncMock(return_value="PASSING")
        c.get_file_blob_sha = AsyncMock(return_value=None)
        c.create_blob = AsyncMock(return_value="blob_1")
        c.create_tree = AsyncMock(return_value="tree_1")
        c.create_commit = AsyncMock(return_value="commit_1")
        c.create_or_update_branch = AsyncMock(return_value=True)
        c.create_pull_request = AsyncMock(return_value={"number": 101, "node_id": "PR_node_pass", "html_url": "https://pr/101"})
        c.poll_check_runs = AsyncMock(return_value={"total_count": 1, "all_completed": True, "all_passed": True, "status": "PASSING"})
        c.mark_pr_ready_for_review = AsyncMock(return_value=True)

        res_pass = await publish_verified_fixes_to_github(
            repo_url="https://github.com/shrinithisk/Sphere",
            verified_fixes=[docker_finding],
            token="ghp_mock_token_pass",
        )
        assert res_pass["status"] == "SUCCESS"
        pr = res_pass["pull_requests"][0]
        assert pr["branch"] == "sphere/fix-docker"
        assert pr["draft"] is False
        c.mark_pr_ready_for_review.assert_called_once_with("PR_node_pass")

    # 2. CI Failing scenario
    with patch("app.pr_builder.publisher.GitHubClient") as MockClient:
        c = MockClient.return_value
        c.get_default_branch = AsyncMock(return_value="main")
        c.get_ref_commit_sha = AsyncMock(return_value="main_head_sha")
        c.get_default_branch_ci_details = AsyncMock(return_value={"status": "PASSING", "check_runs": [], "workflow_runs": []})
        c.get_default_branch_ci_status = AsyncMock(return_value="PASSING")
        c.get_file_blob_sha = AsyncMock(return_value=None)
        c.create_blob = AsyncMock(return_value="blob_1")
        c.create_tree = AsyncMock(return_value="tree_1")
        c.create_commit = AsyncMock(return_value="commit_1")
        c.create_or_update_branch = AsyncMock(return_value=True)
        c.create_pull_request = AsyncMock(return_value={"number": 102, "node_id": "PR_node_fail", "html_url": "https://pr/102"})
        c.poll_check_runs = AsyncMock(return_value={"total_count": 1, "all_completed": True, "all_passed": False, "status": "FAILED"})
        c.mark_pr_ready_for_review = AsyncMock(return_value=True)

        res_fail = await publish_verified_fixes_to_github(
            repo_url="https://github.com/shrinithisk/Sphere",
            verified_fixes=[docker_finding],
            token="ghp_mock_token_fail",
        )
        pr_fail = res_fail["pull_requests"][0]
        assert pr_fail["draft"] is True
        c.mark_pr_ready_for_review.assert_not_called()

    # 3. CI Never Starting scenario
    with patch("app.pr_builder.publisher.GitHubClient") as MockClient:
        c = MockClient.return_value
        c.get_default_branch = AsyncMock(return_value="main")
        c.get_ref_commit_sha = AsyncMock(return_value="main_head_sha")
        c.get_default_branch_ci_details = AsyncMock(return_value={"status": "NO_CI_DETECTED", "check_runs": [], "workflow_runs": []})
        c.get_default_branch_ci_status = AsyncMock(return_value="NO_CI_DETECTED")
        c.get_file_blob_sha = AsyncMock(return_value=None)
        c.create_blob = AsyncMock(return_value="blob_1")
        c.create_tree = AsyncMock(return_value="tree_1")
        c.create_commit = AsyncMock(return_value="commit_1")
        c.create_or_update_branch = AsyncMock(return_value=True)
        c.create_pull_request = AsyncMock(return_value={"number": 103, "node_id": "PR_node_noci", "html_url": "https://pr/103"})
        c.poll_check_runs = AsyncMock(return_value={"total_count": 0, "all_completed": False, "all_passed": False, "status": "CI_NEVER_STARTED"})
        c.mark_pr_ready_for_review = AsyncMock(return_value=True)

        res_noci = await publish_verified_fixes_to_github(
            repo_url="https://github.com/shrinithisk/Sphere",
            verified_fixes=[docker_finding],
            token="ghp_mock_token_noci",
        )
        pr_noci = res_noci["pull_requests"][0]
        assert pr_noci["draft"] is True
        assert pr_noci["ci_status"]["status"] == "CI_NEVER_STARTED"
        c.mark_pr_ready_for_review.assert_not_called()

    # 4. Baseline Already Red scenario
    with patch("app.pr_builder.publisher.GitHubClient") as MockClient:
        c = MockClient.return_value
        c.get_default_branch = AsyncMock(return_value="main")
        c.get_ref_commit_sha = AsyncMock(return_value="main_head_sha")
        c.get_default_branch_ci_details = AsyncMock(return_value={
            "status": "FAILED",
            "head_sha": "main_head_sha",
            "check_runs": [{"name": "test", "conclusion": "failure"}],
            "workflow_runs": [{"name": "CI", "conclusion": "failure"}],
        })
        c.get_default_branch_ci_status = AsyncMock(return_value="FAILED")
        c.get_file_blob_sha = AsyncMock(return_value=None)
        c.create_blob = AsyncMock(return_value="blob_1")
        c.create_tree = AsyncMock(return_value="tree_1")
        c.create_commit = AsyncMock(return_value="commit_1")
        c.create_or_update_branch = AsyncMock(return_value=True)
        c.create_pull_request = AsyncMock(return_value={"number": 104, "node_id": "PR_node_red", "html_url": "https://pr/104"})
        c.poll_check_runs = AsyncMock(return_value={"total_count": 1, "all_completed": True, "all_passed": False, "status": "FAILED"})

        res_red = await publish_verified_fixes_to_github(
            repo_url="https://github.com/shrinithisk/Sphere",
            verified_fixes=[docker_finding],
            token="ghp_mock_token_red",
        )
        assert res_red["default_ci_status"] == "FAILED"
        assert res_red["baseline_ci"]["status"] == "FAILED"
        assert len(res_red["baseline_ci"]["check_runs"]) == 1


@pytest.mark.asyncio
async def test_publishing_fails_cleanly_if_branch_moved_upstream():
    """
    Requirement 8: Base all replayed commits on the head SHA used for the stale check
    and fail cleanly if the branch moved upstream.
    """
    fix = UnifiedFinding(
        id="FIX-WORKFLOW",
        tool="actionlint",
        rule_id="action-sha",
        file=".github/workflows/deploy.yml",
        category=Category.WORKFLOW,
        suggested_fix="Pin SHA",
        original_block="uses: actions/checkout@v2",
        patched_block="uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    )

    with patch("app.pr_builder.publisher.GitHubClient") as MockClient:
        c = MockClient.return_value
        c.get_default_branch = AsyncMock(return_value="main")
        # First call: baseline head SHA
        # Second call: branch moved to another SHA upstream
        c.get_ref_commit_sha = AsyncMock(side_effect=["initial_head_sha_111", "moved_head_sha_222"])
        c.get_default_branch_ci_details = AsyncMock(return_value={"status": "PASSING"})
        c.get_default_branch_ci_status = AsyncMock(return_value="PASSING")
        c.get_file_blob_sha = AsyncMock(return_value=None)

        with pytest.raises(RuntimeError) as exc_info:
            await publish_verified_fixes_to_github(
                repo_url="https://github.com/shrinithisk/Sphere",
                verified_fixes=[fix],
                token="ghp_mock_token_moved",
            )

        assert "moved upstream" in str(exc_info.value).lower()
        assert "rescan needed" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_multi_commit_chaining_tree_built_on_previous_commit():
    """
    Requirement 8: Add a test that builds each commit's tree on the previous commit.
    """
    fix1 = UnifiedFinding(
        id="FIX-WF-1",
        tool="actionlint",
        rule_id="sha-pinning-1",
        file=".github/workflows/build.yml",
        category=Category.WORKFLOW,
        suggested_fix="Pin checkout",
        original_block="uses: actions/checkout@v2",
        patched_block="uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    )
    fix2 = UnifiedFinding(
        id="FIX-WF-2",
        tool="actionlint",
        rule_id="sha-pinning-2",
        file=".github/workflows/test.yml",
        category=Category.WORKFLOW,
        suggested_fix="Pin setup-python",
        original_block="uses: actions/setup-python@v2",
        patched_block="uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
    )

    with patch("app.pr_builder.publisher.GitHubClient") as MockClient:
        c = MockClient.return_value
        c.get_default_branch = AsyncMock(return_value="main")
        c.get_ref_commit_sha = AsyncMock(return_value="base_main_sha")
        c.get_default_branch_ci_details = AsyncMock(return_value={"status": "PASSING"})
        c.get_default_branch_ci_status = AsyncMock(return_value="PASSING")
        c.get_file_blob_sha = AsyncMock(return_value=None)
        c.create_blob = AsyncMock(side_effect=["blob_sha_1", "blob_sha_2"])
        c.create_tree = AsyncMock(side_effect=["tree_sha_1", "tree_sha_2"])
        c.create_commit = AsyncMock(side_effect=["commit_sha_1", "commit_sha_2"])
        c.create_or_update_branch = AsyncMock(return_value=True)
        c.create_pull_request = AsyncMock(return_value={"number": 105, "node_id": "PR_chain", "html_url": "https://pr/105"})
        c.poll_check_runs = AsyncMock(return_value={"total_count": 0, "status": "NO_CI"})

        res = await publish_verified_fixes_to_github(
            repo_url="https://github.com/shrinithisk/Sphere",
            verified_fixes=[fix1, fix2],
            token="ghp_mock_token_chain",
        )

        assert res["status"] == "SUCCESS"
        pr = res["pull_requests"][0]
        assert pr["commit_count"] == 2
        assert pr["commits"] == ["commit_sha_1", "commit_sha_2"]

        # Assert commit 1 was based on base_main_sha
        c.create_tree.assert_any_call(
            "shrinithisk", "Sphere", base_tree_sha="base_main_sha", tree_entries=[{"path": ".github/workflows/build.yml", "mode": "100644", "type": "blob", "sha": "blob_sha_1"}]
        )
        c.create_commit.assert_any_call(
            "shrinithisk", "Sphere", message=c.create_commit.call_args_list[0][1]["message"], tree_sha="tree_sha_1", parent_commit_sha="base_main_sha"
        )

        # Assert commit 2 was based on commit_sha_1 (chained!)
        c.create_tree.assert_any_call(
            "shrinithisk", "Sphere", base_tree_sha="commit_sha_1", tree_entries=[{"path": ".github/workflows/test.yml", "mode": "100644", "type": "blob", "sha": "blob_sha_2"}]
        )
        c.create_commit.assert_any_call(
            "shrinithisk", "Sphere", message=c.create_commit.call_args_list[1][1]["message"], tree_sha="tree_sha_2", parent_commit_sha="commit_sha_1"
        )

