import os
import re
import hashlib
from typing import List, Dict, Any, Optional, Tuple

from app.planner.schema import UnifiedFinding
from app.pr_builder.github_client import GitHubClient
from app.pr_builder.pr_grouper import group_fixes_by_pr, build_pr_body


def compute_git_blob_sha(content: str) -> str:
    """Computes the standard Git blob SHA-1: sha1('blob ' + size + '\0' + content)."""
    data = content.encode("utf-8")
    header = f"blob {len(data)}\0".encode("utf-8")
    return hashlib.sha1(header + data).hexdigest()


async def publish_verified_fixes_to_github(
    repo_url: str,
    verified_fixes: List[UnifiedFinding],
    token: str,
    baseline_repo_path: Optional[str] = None,
    scanned_commit_sha: Optional[str] = None,
    verification_label: str = "STATIC-VERIFIED (tests not run)",
) -> Dict[str, Any]:
    """
    Publishes verified fixes to GitHub via the Git Data API:
    - Verifies each target file's blob SHA on default branch matches baseline.
      If modified upstream, skips that fix as "stale, rescan needed".
    - Groups fixes by category (Dependencies Minor, Major, Docker, Workflows, Code).
    - Major bumps and Semgrep/LLM patches always go to separate Draft PRs.
    - Pushes one commit per fix via Git Data API (in-memory PAT only).
    - Opens Draft Pull Request.
    - Polls GitHub Actions CI check runs; if CI passes, mutates PR to ready for review via GraphQL.
    """
    if "github.com" not in repo_url:
        raise ValueError("Publishing PRs is only supported for GitHub repositories.")

    clean_url = repo_url.rstrip("/").replace(".git", "")
    parts = clean_url.split("github.com/")[-1].split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid GitHub repository URL: {repo_url}")

    owner, repo = parts[0], parts[1]
    client = GitHubClient(token=token)

    # Step 1: Default branch and baseline CI status
    default_branch = await client.get_default_branch(owner, repo)
    default_branch_head_sha = await client.get_ref_commit_sha(owner, repo, default_branch)
    baseline_ci = await client.get_default_branch_ci_details(owner, repo, default_branch)
    default_ci_status = baseline_ci.get("status", "UNKNOWN")

    # Step 2: Group fixes
    pr_groups = group_fixes_by_pr(verified_fixes)
    if not pr_groups:
        return {
            "status": "NO_FIXES",
            "message": "No verified fixes available to publish.",
            "pull_requests": [],
            "skipped_stale_fixes": [],
            "baseline_ci": baseline_ci,
        }

    published_prs = []
    skipped_stale_fixes = []

    # Step 3: Process each PR group
    for group_key, group_info in pr_groups.items():
        fixes: List[UnifiedFinding] = group_info["fixes"]
        active_fixes: List[UnifiedFinding] = []

        # Stale blob check: verify remote blob SHA on default branch matches baseline
        for f in fixes:
            remote_blob = await client.get_file_blob_sha(owner, repo, f.file, ref=default_branch)
            # If baseline repo path is provided, compute local baseline file blob SHA
            if baseline_repo_path and os.path.isdir(baseline_repo_path):
                local_file = os.path.join(baseline_repo_path, f.file)
                if os.path.isfile(local_file):
                    with open(local_file, "r", encoding="utf-8", errors="ignore") as fp:
                        local_content = fp.read()
                    local_blob = compute_git_blob_sha(local_content)
                    if remote_blob and remote_blob != local_blob:
                        skipped_stale_fixes.append({
                            "finding_id": f.id,
                            "file": f.file,
                            "reason": "stale, rescan needed (upstream file changed on default branch)",
                        })
                        continue

            active_fixes.append(f)

        if not active_fixes:
            continue

        # Requirement 8: Fail cleanly if the branch moved between stale check and replay
        latest_head_sha = await client.get_ref_commit_sha(owner, repo, default_branch)
        if latest_head_sha != default_branch_head_sha:
            raise RuntimeError(
                f"Branch '{default_branch}' moved upstream ({default_branch_head_sha[:7]} -> {latest_head_sha[:7]}) during publishing; rescan needed."
            )

        group_info["fixes"] = active_fixes
        branch_name = group_info["branch"]
        parent_sha = default_branch_head_sha
        created_commits = []

        # Git Data API: Create one commit per verified fix (chained on previous commit)
        for fix in active_fixes:
            # Prepare updated file content
            patched_content = fix.patched_block or ""
            # If we have baseline repo path, apply patch to original file content
            if baseline_repo_path and os.path.isdir(baseline_repo_path):
                local_file = os.path.join(baseline_repo_path, fix.file)
                if os.path.isfile(local_file):
                    with open(local_file, "r", encoding="utf-8", errors="ignore") as fp:
                        orig = fp.read()
                    if fix.original_block and fix.original_block in orig and fix.patched_block:
                        patched_content = orig.replace(fix.original_block, fix.patched_block, 1)

            blob_sha = await client.create_blob(owner, repo, patched_content)

            # Build this commit's tree on parent_sha's tree (chaining commits)
            tree_sha = await client.create_tree(
                owner,
                repo,
                base_tree_sha=parent_sha,
                tree_entries=[{
                    "path": fix.file,
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob_sha,
                }],
            )

            cat = fix.category if isinstance(fix.category, str) else fix.category.value
            commit_msg = (
                f"fix({cat}): resolve {fix.package or fix.rule_id} in {fix.file}\n\n"
                f"Finding ID: {fix.id}\n"
                f"Rule: {fix.rule_id}\n"
                f"Resolved Count: {fix.resolved_issue_count}"
            )
            commit_sha = await client.create_commit(
                owner,
                repo,
                message=commit_msg,
                tree_sha=tree_sha,
                parent_commit_sha=parent_sha,
            )
            created_commits.append({"sha": commit_sha, "message": commit_msg})
            parent_sha = commit_sha

        # Create or update branch
        await client.create_or_update_branch(owner, repo, branch_name, parent_sha)

        # Build comprehensive PR description
        pr_body = build_pr_body(
            group_info=group_info,
            verification_label=verification_label,
            default_branch_ci=default_ci_status,
            branch_ci_status="INITIALIZING",
            commits_list=created_commits,
        )

        # Open Draft Pull Request
        pr = await client.create_pull_request(
            owner=owner,
            repo=repo,
            title=group_info["title"],
            body=pr_body,
            head_branch=branch_name,
            base_branch=default_branch,
            draft=True,  # Open every PR as draft initially
        )

        pr_node_id = pr.get("node_id")
        pr_number = pr.get("number")
        pr_url = pr.get("html_url")

        # Poll CI check runs for PR head commit SHA with combined statuses
        ci_summary = await client.poll_check_runs(owner, repo, parent_sha)
        is_ready = False

        is_major = group_info.get("is_major_pr", False)
        is_code = (group_key == "code")
        baseline_red = (baseline_ci.get("status") == "FAILED")

        # Mark ready ONLY when:
        # 1. CI passed (all_passed is True)
        # 2. Total checks > 0 (zero checks can never produce ready)
        # 3. Default branch baseline CI is not red (red baseline blocks auto-ready)
        # 4. Not a major bump PR (major bumps always stay draft)
        # 5. Not a code patch PR (code patches always stay draft)
        if (
            ci_summary.get("all_passed") is True
            and ci_summary.get("total_count", 0) > 0
            and not baseline_red
            and not is_major
            and not is_code
            and pr_node_id
        ):
            try:
                is_ready = await client.mark_pr_ready_for_review(pr_node_id)
            except Exception:
                is_ready = False

        published_prs.append({
            "group": group_key,
            "branch": branch_name,
            "pr_number": pr_number,
            "pr_node_id": pr_node_id,
            "pr_url": pr_url,
            "head_sha": parent_sha,
            "draft": not is_ready,
            "is_major_pr": is_major,
            "is_code_pr": is_code,
            "commit_count": len(created_commits),
            "commits": [c["sha"] for c in created_commits],
            "ci_status": ci_summary,
        })

    return {
        "status": "SUCCESS",
        "default_branch": default_branch,
        "default_ci_status": default_ci_status,
        "baseline_ci": baseline_ci,
        "pull_requests": published_prs,
        "skipped_stale_fixes": skipped_stale_fixes,
    }
