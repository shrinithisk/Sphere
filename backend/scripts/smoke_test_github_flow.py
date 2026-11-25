#!/usr/bin/env python3
"""
Sphere Manual Smoke-Test Script for GitHub Integration
------------------------------------------------------
Verifies the end-to-end GitHub flow using a fine-grained Personal Access Token (PAT)
on a throwaway GitHub repository.

Security: Never pass the token via CLI argument (--pat), which leaks into shell history
and system process lists. Set GITHUB_PAT env var or enter when securely prompted by getpass.

Required Fine-Grained PAT Permissions on the target repository:
  1. Repository permissions -> Contents: Read and write
  2. Repository permissions -> Pull requests: Read and write
  3. Repository permissions -> Workflows: Read and write
  4. Repository permissions -> Checks: Read-only

Usage:
  export GITHUB_PAT=github_pat_xxxx
  python scripts/smoke_test_github_flow.py --repo https://github.com/owner/throwaway-repo
  OR (secure hidden prompt)
  python scripts/smoke_test_github_flow.py --repo https://github.com/owner/throwaway-repo
"""

import sys
import os
import argparse
import asyncio
import time
import getpass
from typing import Dict, Any

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.pr_builder.github_client import GitHubClient
from app.pr_builder.publisher import compute_git_blob_sha


def print_step(num: int, title: str):
    print(f"\n\033[1;34m[Step {num}]\033[0m \033[1m{title}\033[0m")


def print_success(msg: str):
    print(f"  \033[1;32m✔\033[0m {msg}")


def print_warn(msg: str):
    print(f"  \033[1;33m⚠\033[0m {msg}")


def print_error(msg: str):
    print(f"  \033[1;31m✖\033[0m {msg}")


async def run_smoke_test(repo_url: str, pat: str):
    print("\033[1;36m========================================================\033[0m")
    print("\033[1;36m       🛡️ Sphere GitHub Integration Smoke Test          \033[0m")
    print("\033[1;36m========================================================\033[0m")

    # Clean URL
    clean_url = repo_url.rstrip("/").replace(".git", "")
    parts = clean_url.split("github.com/")[-1].split("/")
    if len(parts) < 2:
        print_error(f"Invalid repository URL: {repo_url}")
        sys.exit(1)

    owner, repo = parts[0], parts[1]
    print(f"Target Repository : \033[1m{owner}/{repo}\033[0m")
    print(f"Token Masked      : \033[1m{pat[:4]}...{pat[-4:] if len(pat) > 8 else ''}\033[0m")

    client = GitHubClient(token=pat)

    # Step 1: Verify Repo access and Default Branch
    print_step(1, "Validating repository access and querying default branch...")
    try:
        repo_info = await client.get_repo_info(owner, repo)
        default_branch = repo_info.get("default_branch", "main")
        print_success(f"Connected! Default branch is '{default_branch}'. Full name: {repo_info.get('full_name')}")
    except Exception as e:
        print_error(f"Failed to connect to repository. Check PAT and permissions: {e}")
        sys.exit(1)

    # Step 2: Fetch default branch commit SHA and Baseline CI
    print_step(2, "Capturing default branch head SHA and baseline CI check runs...")
    try:
        head_sha = await client.get_ref_commit_sha(owner, repo, default_branch)
        print_success(f"Default branch head commit SHA: {head_sha}")

        baseline_ci = await client.get_default_branch_ci_details(owner, repo, default_branch)
        print_success(f"Baseline CI status: {baseline_ci.get('status')} (Total checks: {baseline_ci.get('total_checks')})")
    except Exception as e:
        print_error(f"Failed to fetch branch reference or CI: {e}")
        sys.exit(1)

    # Step 3: Upstream Stale Blob SHA Check
    print_step(3, "Checking file blob SHA on default branch (stale check simulation)...")
    target_filename = "README.md"
    try:
        blob_sha = await client.get_file_blob_sha(owner, repo, target_filename, ref=default_branch)
        if blob_sha:
            print_success(f"Existing '{target_filename}' blob SHA on default branch: {blob_sha}")
        else:
            print_warn(f"'{target_filename}' not found on default branch; will create a new test file.")
            target_filename = "sphere-security-audit.md"
    except Exception as e:
        print_error(f"Error checking file blob SHA: {e}")
        sys.exit(1)

    # Step 4: Create Git Data API objects (Blob -> Tree -> Commit)
    print_step(4, "Creating Git Data API objects (Atomic commit via Git Data API)...")
    test_timestamp = int(time.time())
    new_branch_name = f"sphere/smoke-test-{test_timestamp}"
    test_content = (
        f"# Sphere Security Remediation Smoke Test\n\n"
        f"- Verified at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
        f"- Target Branch: `{default_branch}`\n"
        f"- Security Status: `STATIC-VERIFIED (tests not run)`\n"
        f"- Pipeline Baseline: `{baseline_ci.get('status')}`\n\n"
        f"*Automated verified commit generated via Sphere Git Data API bot.*\n"
    )

    try:
        # Create Blob
        new_blob_sha = await client.create_blob(owner, repo, test_content)
        print_success(f"1/3 Created Git Blob SHA: {new_blob_sha}")

        # Create Tree based on default branch head
        tree_entries = [{
            "path": target_filename,
            "mode": "100644",
            "type": "blob",
            "sha": new_blob_sha,
        }]
        new_tree_sha = await client.create_tree(owner, repo, base_tree_sha=head_sha, tree_entries=tree_entries)
        print_success(f"2/3 Created Git Tree SHA: {new_tree_sha} (chained on parent tree: {head_sha[:7]})")

        # Create Commit
        commit_msg = (
            f"chore(security): automated smoke-test verification patch\n\n"
            f"Timestamp: {test_timestamp}\n"
            f"Verification: STATIC-VERIFIED\n"
        )
        new_commit_sha = await client.create_commit(
            owner,
            repo,
            message=commit_msg,
            tree_sha=new_tree_sha,
            parent_commit_sha=head_sha,
        )
        print_success(f"3/3 Created Git Commit SHA: {new_commit_sha} (parent: {head_sha[:7]})")
    except Exception as e:
        print_error(f"Git Data API commit creation failed: {e}")
        sys.exit(1)

    # Step 5: Push Branch Reference
    print_step(5, f"Creating feature branch '{new_branch_name}' via Git Refs API...")
    try:
        ref_res = await client.create_or_update_branch(owner, repo, new_branch_name, new_commit_sha)
        print_success(f"Branch created successfully: refs/heads/{new_branch_name}")
    except Exception as e:
        print_error(f"Failed to create branch reference: {e}")
        sys.exit(1)

    # Step 6: Open Draft Pull Request
    print_step(6, "Opening Draft Pull Request on GitHub...")
    pr_body = (
        f"## 🛡️ Sphere Automated Security Smoke Test\n\n"
        f"**Target Branch**: `{default_branch}`  \n"
        f"**Verification Status**: `STATIC-VERIFIED (tests not run)`  \n"
        f"**Baseline CI**: `{baseline_ci.get('status')}`  \n"
        f"**Head Commit**: `{new_commit_sha[:7]}`  \n\n"
        f"> [!NOTE]\n"
        f"> This is an automated verification PR to confirm GitHub PAT permissions, "
        f"Git Data API replay, and Draft PR lifecycle.\n\n"
        f"### ↩️ How to Revert\n"
        f"```bash\n"
        f"git revert {new_commit_sha[:7]}\n"
        f"```\n"
    )

    pr_number = None
    pr_node_id = None
    pr_url = None
    try:
        pr = await client.create_pull_request(
            owner=owner,
            repo=repo,
            title="test(sphere): automated verification smoke-test PR",
            body=pr_body,
            head_branch=new_branch_name,
            base_branch=default_branch,
            draft=True,
        )
        pr_number = pr.get("number")
        pr_node_id = pr.get("node_id")
        pr_url = pr.get("html_url")
        print_success(f"Draft Pull Request #{pr_number} created: \033[1;32m{pr_url}\033[0m")
    except Exception as e:
        print_error(f"Failed to open Pull Request: {e}")
        sys.exit(1)

    # Step 7: Poll Check Runs for Head SHA
    print_step(7, f"Polling GitHub Actions check runs for PR head commit {new_commit_sha[:7]}...")
    ci_res = await client.poll_check_runs(owner, repo, new_commit_sha, max_attempts=3, initial_delay=1.5)
    print_success(f"CI Polling Result: status={ci_res.get('status')}, total_checks={ci_res.get('total_count')}")

    # Step 8: Test GraphQL markPullRequestReadyForReview (if permitted)
    print_step(8, "Testing GraphQL draft transition (markPullRequestReadyForReview)...")
    if pr_node_id:
        try:
            marked_ready = await client.mark_pr_ready_for_review(pr_node_id)
            if marked_ready:
                print_success(f"Successfully marked PR #{pr_number} as Ready for Review via GraphQL!")
            else:
                print_warn("PR remained in draft mode (GraphQL mutation completed or review was restricted).")
        except Exception as e:
            print_warn(f"GraphQL draft transition skipped or token lacks PR triage permissions: {e}")

    print("\n\033[1;32m========================================================\033[0m")
    print(f"\033[1;32m       ✔ Smoke Test Completed Successfully!            \033[0m")
    print(f" View PR: \033[1m{pr_url}\033[0m")
    print("\033[1;32m========================================================\033[0m\n")


def main():
    parser = argparse.ArgumentParser(description="Sphere GitHub Integration Smoke Test")
    parser.add_argument("--repo", required=True, help="Target GitHub repo URL, e.g. https://github.com/owner/throwaway")
    args = parser.parse_args()

    pat = os.getenv("GITHUB_PAT")
    if not pat:
        try:
            pat = getpass.getpass("Enter GitHub Fine-Grained PAT (starts with github_pat_): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

    if not pat:
        print_error("A valid GitHub PAT is required (via GITHUB_PAT environment variable or secure prompt).")
        sys.exit(1)

    asyncio.run(run_smoke_test(args.repo, pat))


if __name__ == "__main__":
    main()
