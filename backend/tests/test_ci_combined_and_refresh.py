import os
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.database import init_db, get_db_connection
from app.auth import create_access_token
from app.pr_builder.github_client import GitHubClient


@pytest.fixture
def client_and_auth(tmp_path, monkeypatch):
    test_db = tmp_path / "test_ci_refresh.db"
    monkeypatch.setenv("SPHERE_DB_PATH", str(test_db))
    monkeypatch.setattr("app.database.DB_PATH", str(test_db))
    init_db(str(test_db))

    conn = get_db_connection(str(test_db))
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("ci_user", "hash"))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()

    token = create_access_token({"sub": "ci_user", "user_id": user_id})
    return TestClient(app), token, user_id, str(test_db)


@pytest.mark.asyncio
async def test_zero_checks_never_means_passed():
    """
    Requirement 3: Confirm that zero check-runs/statuses can NEVER produce all_passed = True.
    """
    client = GitHubClient(token="github_pat_test1234567890")
    client.get_check_runs = AsyncMock(return_value={"total_count": 0, "all_completed": False, "all_passed": False, "check_runs": []})
    client.get_commit_combined_status = AsyncMock(return_value={"state": "pending", "total_count": 0, "statuses": []})

    ci_status = await client.get_combined_ci_status("owner", "repo", "sha123")
    assert ci_status["total_count"] == 0
    assert ci_status["all_passed"] is False
    assert ci_status["status"] == "CI_NEVER_STARTED"


@pytest.mark.asyncio
async def test_combined_ci_status_with_both_check_runs_and_commit_statuses():
    """
    Requirement 3: Query combined commit status as well as check runs.
    """
    client = GitHubClient(token="github_pat_test1234567890")
    # Check runs passing
    client.get_check_runs = AsyncMock(return_value={
        "total_count": 1,
        "all_completed": True,
        "all_passed": True,
        "check_runs": [{"name": "test", "status": "completed", "conclusion": "success"}],
    })
    # Commit status also passing
    client.get_commit_combined_status = AsyncMock(return_value={
        "state": "success",
        "total_count": 1,
        "statuses": [{"context": "ci/circleci", "state": "success"}],
    })

    ci_status = await client.get_combined_ci_status("owner", "repo", "sha123")
    assert ci_status["total_count"] == 2
    assert ci_status["all_completed"] is True
    assert ci_status["all_passed"] is True
    assert ci_status["status"] == "PASSING"


def test_red_baseline_blocks_auto_ready(client_and_auth):
    """
    Requirement 3: A red baseline blocks auto-ready.
    Even if the PR's CI is passing, if the default branch baseline is FAILED,
    the PR must remain in draft mode.
    """
    test_client, auth_token, user_id, db_path = client_and_auth

    # Insert a scan with a published PR in draft mode
    initial_v_data = {
        "status": "COMPLETED",
        "published_prs": [{
            "group": "dependencies_minor",
            "branch": "sphere/deps-minor",
            "pr_number": 42,
            "pr_node_id": "PR_node_42",
            "pr_url": "https://github.com/test/repo/pull/42",
            "head_sha": "commit_sha_head",
            "draft": True,
            "is_major_pr": False,
            "is_code_pr": False,
            "ci_status": {"status": "QUEUED", "total_count": 0, "all_passed": False},
        }]
    }

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (user_id, repo_url, repo_name, status, verification_json, source_type)
        VALUES (?, ?, ?, ?, ?, 'github')
    """, (user_id, "https://github.com/test/repo", "repo", "Completed", json.dumps(initial_v_data)))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Mock GitHubClient: PR CI is PASSING, but default branch baseline is FAILED
    with patch("app.main.GitHubClient") as mock_cls:
        instance = MagicMock()
        mock_cls.return_value = instance
        instance.get_default_branch = AsyncMock(return_value="main")
        instance.get_default_branch_ci_details = AsyncMock(return_value={"status": "FAILED", "total_checks": 1})
        instance.get_combined_ci_status = AsyncMock(return_value={
            "status": "PASSING",
            "total_count": 2,
            "all_completed": True,
            "all_passed": True,
        })
        instance.mark_pr_ready_for_review = AsyncMock(return_value=True)

        resp = test_client.post(
            f"/api/scans/{scan_id}/prs/refresh-ci",
            headers={
                "Authorization": f"Bearer {auth_token}",
                "X-GitHub-Token": "github_pat_test1234567890",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["baseline_red"] is True
        pr = data["published_prs"][0]
        # PR MUST remain draft because baseline is red!
        assert pr["draft"] is True
        instance.mark_pr_ready_for_review.assert_not_called()


def test_passing_ci_mutates_pr_ready_via_graphql(client_and_auth):
    """
    Requirement 3: When CI passes, baseline is not red, and PR is not major/code,
    mark-ready mutates the PR ready for review via GraphQL.
    """
    test_client, auth_token, user_id, db_path = client_and_auth

    initial_v_data = {
        "status": "COMPLETED",
        "published_prs": [{
            "group": "dependencies_minor",
            "branch": "sphere/deps-minor",
            "pr_number": 43,
            "pr_node_id": "PR_node_43",
            "pr_url": "https://github.com/test/repo/pull/43",
            "head_sha": "commit_sha_head_2",
            "draft": True,
            "is_major_pr": False,
            "is_code_pr": False,
            "ci_status": {"status": "QUEUED", "total_count": 0, "all_passed": False},
        }]
    }

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (user_id, repo_url, repo_name, status, verification_json, source_type)
        VALUES (?, ?, ?, ?, ?, 'github')
    """, (user_id, "https://github.com/test/repo", "repo", "Completed", json.dumps(initial_v_data)))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()

    with patch("app.main.GitHubClient") as mock_cls:
        instance = MagicMock()
        mock_cls.return_value = instance
        instance.get_default_branch = AsyncMock(return_value="main")
        instance.get_default_branch_ci_details = AsyncMock(return_value={"status": "PASSING", "total_checks": 1})
        instance.get_combined_ci_status = AsyncMock(return_value={
            "status": "PASSING",
            "total_count": 2,
            "all_completed": True,
            "all_passed": True,
        })
        instance.mark_pr_ready_for_review = AsyncMock(return_value=True)

        resp = test_client.post(
            f"/api/scans/{scan_id}/prs/refresh-ci",
            headers={
                "Authorization": f"Bearer {auth_token}",
                "X-GitHub-Token": "github_pat_test1234567890",
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        pr = data["published_prs"][0]
        # Should now be marked ready!
        assert pr["draft"] is False
        instance.mark_pr_ready_for_review.assert_called_once_with("PR_node_43")


def test_major_and_code_prs_always_remain_draft(client_and_auth):
    """
    Requirement 1 & 3: Major version bumps and Semgrep/LLM code patches
    always stay draft until a human explicitly reviews and merges them.
    """
    test_client, auth_token, user_id, db_path = client_and_auth

    initial_v_data = {
        "status": "COMPLETED",
        "published_prs": [
            {
                "group": "major_bump",
                "branch": "sphere/deps-major-lodash",
                "pr_number": 51,
                "pr_node_id": "PR_node_51",
                "head_sha": "sha_major",
                "draft": True,
                "is_major_pr": True,
                "is_code_pr": False,
            },
            {
                "group": "code",
                "branch": "sphere/code-fixes",
                "pr_number": 52,
                "pr_node_id": "PR_node_52",
                "head_sha": "sha_code",
                "draft": True,
                "is_major_pr": False,
                "is_code_pr": True,
            }
        ]
    }

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (user_id, repo_url, repo_name, status, verification_json, source_type)
        VALUES (?, ?, ?, ?, ?, 'github')
    """, (user_id, "https://github.com/test/repo", "repo", "Completed", json.dumps(initial_v_data)))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()

    with patch("app.main.GitHubClient") as mock_cls:
        instance = MagicMock()
        mock_cls.return_value = instance
        instance.get_default_branch = AsyncMock(return_value="main")
        instance.get_default_branch_ci_details = AsyncMock(return_value={"status": "PASSING", "total_checks": 1})
        instance.get_combined_ci_status = AsyncMock(return_value={
            "status": "PASSING",
            "total_count": 2,
            "all_completed": True,
            "all_passed": True,
        })
        instance.mark_pr_ready_for_review = AsyncMock(return_value=True)

        resp = test_client.post(
            f"/api/scans/{scan_id}/prs/refresh-ci",
            headers={
                "Authorization": f"Bearer {auth_token}",
                "X-GitHub-Token": "github_pat_test1234567890",
            }
        )
        assert resp.status_code == 200
        prs = resp.json()["published_prs"]
        assert prs[0]["draft"] is True
        assert prs[1]["draft"] is True
        instance.mark_pr_ready_for_review.assert_not_called()
