import httpx
from typing import Dict, Any, Optional, List, Tuple


class GitHubClient:
    """
    Client for interacting with the GitHub REST and GraphQL APIs.
    Security: The Personal Access Token (PAT) is held strictly in memory
    and is never written to disk, database, .git/config, or logs.
    """

    def __init__(self, token: str, timeout: float = 30.0):
        if not token or not isinstance(token, str):
            raise ValueError("A valid in-memory GitHub Personal Access Token is required.")
        self.token = token.strip()
        self.timeout = timeout
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Sphere-Security-Bot/1.0",
        }

    async def get_repo_info(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetches repository metadata including default branch."""
        url = f"https://api.github.com/repos/{owner}/{repo}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url, headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    async def get_default_branch(self, owner: str, repo: str) -> str:
        """Retrieves the default branch name of the repository."""
        info = await self.get_repo_info(owner, repo)
        return info.get("default_branch", "main")

    async def get_ref_commit_sha(self, owner: str, repo: str, branch: str) -> str:
        """Retrieves the latest commit SHA for a branch."""
        url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{branch}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url, headers=self.headers)
            resp.raise_for_status()
            data = resp.json()
            return data["object"]["sha"]

    async def get_file_blob_sha(self, owner: str, repo: str, path: str, ref: str) -> Optional[str]:
        """
        Retrieves the blob SHA of a specific file at a given ref/commit on the default branch.
        Used to detect if the target file was modified upstream ("stale, rescan needed").
        """
        clean_path = path.lstrip("./").lstrip("/")
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{clean_path}?ref={ref}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url, headers=self.headers)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            return data.get("sha")

    async def create_blob(self, owner: str, repo: str, content: str) -> str:
        """Creates a Git blob object and returns its SHA."""
        url = f"https://api.github.com/repos/{owner}/{repo}/git/blobs"
        payload = {
            "content": content,
            "encoding": "utf-8",
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, headers=self.headers, json=payload)
            resp.raise_for_status()
            return resp.json()["sha"]

    async def create_tree(
        self,
        owner: str,
        repo: str,
        base_tree_sha: str,
        tree_entries: List[Dict[str, Any]],
    ) -> str:
        """
        Creates a Git tree object containing updated file entries.
        Each entry has: path, mode, type ('blob'), sha.
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees"
        payload = {
            "base_tree": base_tree_sha,
            "tree": tree_entries,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, headers=self.headers, json=payload)
            resp.raise_for_status()
            return resp.json()["sha"]

    async def create_commit(
        self,
        owner: str,
        repo: str,
        message: str,
        tree_sha: str,
        parent_commit_sha: str,
    ) -> str:
        """Creates a Git commit object via the Git Data API."""
        url = f"https://api.github.com/repos/{owner}/{repo}/git/commits"
        payload = {
            "message": message,
            "tree": tree_sha,
            "parents": [parent_commit_sha],
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, headers=self.headers, json=payload)
            resp.raise_for_status()
            return resp.json()["sha"]

    async def create_or_update_branch(
        self,
        owner: str,
        repo: str,
        branch_name: str,
        commit_sha: str,
    ) -> Dict[str, Any]:
        """Creates a new branch ref or updates an existing one."""
        ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs"
        get_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{branch_name}"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Check if branch exists
            get_resp = await client.get(get_url, headers=self.headers)
            if get_resp.status_code == 200:
                # Update existing ref
                patch_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch_name}"
                patch_resp = await client.patch(
                    patch_url,
                    headers=self.headers,
                    json={"sha": commit_sha, "force": True},
                )
                patch_resp.raise_for_status()
                return patch_resp.json()
            else:
                # Create new ref
                create_resp = await client.post(
                    ref_url,
                    headers=self.headers,
                    json={"ref": f"refs/heads/{branch_name}", "sha": commit_sha},
                )
                create_resp.raise_for_status()
                return create_resp.json()

    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str,
        draft: bool = True,
    ) -> Dict[str, Any]:
        """
        Opens a Pull Request via GitHub REST API.
        All PRs are initially opened in DRAFT mode.
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        payload = {
            "title": title,
            "body": body,
            "head": head_branch,
            "base": base_branch,
            "draft": draft,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, headers=self.headers, json=payload)
            if resp.status_code == 422:
                # PR might already exist for this branch
                data = resp.json()
                if "already exists" in str(data):
                    # Fetch existing PR
                    list_resp = await client.get(
                        f"{url}?head={owner}:{head_branch}&state=open",
                        headers=self.headers,
                    )
                    prs = list_resp.json()
                    if prs:
                        return prs[0]
            resp.raise_for_status()
            return resp.json()

    async def get_check_runs(
        self,
        owner: str,
        repo: str,
        commit_ref: str,
    ) -> Dict[str, Any]:
        """
        Polls check runs for a commit ref:
        GET /repos/{owner}/{repo}/commits/{ref}/check-runs
        Returns summary of check runs, status, and conclusions.
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_ref}/check-runs"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url, headers=self.headers)
            resp.raise_for_status()
            data = resp.json()

            check_runs = data.get("check_runs", [])
            total_count = data.get("total_count", 0)

            all_completed = True
            all_passed = True if total_count > 0 else False

            for run in check_runs:
                status = run.get("status")  # "queued", "in_progress", "completed"
                conclusion = run.get("conclusion")  # "success", "failure", "neutral", "timed_out", etc.
                if status != "completed":
                    all_completed = False
                if conclusion != "success":
                    all_passed = False

            return {
                "total_count": total_count,
                "all_completed": all_completed,
                "all_passed": all_passed,
                "check_runs": [
                    {
                        "name": r.get("name"),
                        "status": r.get("status"),
                        "conclusion": r.get("conclusion"),
                        "html_url": r.get("html_url"),
                    }
                    for r in check_runs
                ],
            }

    async def get_commit_combined_status(
        self,
        owner: str,
        repo: str,
        commit_ref: str,
    ) -> Dict[str, Any]:
        """
        Fetches commit status for a ref via GitHub REST API:
        GET /repos/{owner}/{repo}/commits/{ref}/status
        Covers older/third-party CI systems that report via statuses rather than check-runs.
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_ref}/status"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=self.headers)
                if resp.status_code == 404:
                    return {"state": "pending", "total_count": 0, "statuses": []}
                resp.raise_for_status()
                data = resp.json()
                return {
                    "state": data.get("state"),  # pending, success, failure, error
                    "total_count": data.get("total_count", 0),
                    "statuses": [
                        {
                            "context": s.get("context"),
                            "state": s.get("state"),
                            "description": s.get("description"),
                            "target_url": s.get("target_url"),
                        }
                        for s in data.get("statuses", [])
                    ],
                }
        except Exception:
            return {"state": "pending", "total_count": 0, "statuses": []}

    async def get_combined_ci_status(
        self,
        owner: str,
        repo: str,
        commit_ref: str,
    ) -> Dict[str, Any]:
        """
        Queries BOTH Check Runs and Commit Statuses.
        Rules:
        - If total_count == 0 across both: all_passed = False, status = 'CI_NEVER_STARTED'.
        - If any check or status is pending/queued/in_progress: status = 'IN_PROGRESS', all_completed = False.
        - If all checks completed:
            - If any check conclusion != 'success' or status state in ('failure', 'error'): status = 'FAILED', all_passed = False.
            - If all checks 'success': status = 'PASSING', all_passed = True.
        """
        check_runs = await self.get_check_runs(owner, repo, commit_ref)
        statuses = await self.get_commit_combined_status(owner, repo, commit_ref)

        cr_count = check_runs.get("total_count", 0)
        st_count = statuses.get("total_count", 0)
        total_count = cr_count + st_count

        if total_count == 0:
            return {
                "total_count": 0,
                "all_completed": False,
                "all_passed": False,
                "status": "CI_NEVER_STARTED",
                "check_runs": [],
                "commit_statuses": [],
            }

        is_in_progress = False
        if cr_count > 0 and not check_runs.get("all_completed", False):
            is_in_progress = True
        if st_count > 0 and statuses.get("state") == "pending":
            is_in_progress = True

        if is_in_progress:
            return {
                "total_count": total_count,
                "all_completed": False,
                "all_passed": False,
                "status": "IN_PROGRESS",
                "check_runs": check_runs.get("check_runs", []),
                "commit_statuses": statuses.get("statuses", []),
            }

        has_failure = False
        if cr_count > 0 and not check_runs.get("all_passed", False):
            has_failure = True
        if st_count > 0 and statuses.get("state") in ("failure", "error"):
            has_failure = True

        if has_failure:
            return {
                "total_count": total_count,
                "all_completed": True,
                "all_passed": False,
                "status": "FAILED",
                "check_runs": check_runs.get("check_runs", []),
                "commit_statuses": statuses.get("statuses", []),
            }

        return {
            "total_count": total_count,
            "all_completed": True,
            "all_passed": True,
            "status": "PASSING",
            "check_runs": check_runs.get("check_runs", []),
            "commit_statuses": statuses.get("statuses", []),
        }

    async def get_workflow_runs(self, owner: str, repo: str, branch: str) -> List[Dict[str, Any]]:
        """Fetches latest workflow runs for a branch."""
        url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs?branch={branch}&per_page=5"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=self.headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return [
                        {
                            "name": r.get("name"),
                            "status": r.get("status"),
                            "conclusion": r.get("conclusion"),
                            "html_url": r.get("html_url"),
                            "head_sha": r.get("head_sha"),
                        }
                        for r in data.get("workflow_runs", [])
                    ]
        except Exception:
            pass
        return []

    async def get_default_branch_ci_details(
        self,
        owner: str,
        repo: str,
        default_branch: str,
    ) -> Dict[str, Any]:
        """
        Captures baseline CI status & details of the default branch's latest commit.
        Fetches check-runs, commit statuses, and GitHub Actions workflow runs.
        """
        try:
            head_sha = await self.get_ref_commit_sha(owner, repo, default_branch)
            ci = await self.get_combined_ci_status(owner, repo, head_sha)
            wf_runs = await self.get_workflow_runs(owner, repo, default_branch)

            status = ci.get("status", "CI_NEVER_STARTED")
            if status == "CI_NEVER_STARTED" and wf_runs:
                completed = all(r.get("status") == "completed" for r in wf_runs)
                passed = all(r.get("conclusion") == "success" for r in wf_runs)
                if completed and passed:
                    status = "PASSING"
                elif not completed:
                    status = "IN_PROGRESS"
                else:
                    status = "FAILED"
            elif status == "CI_NEVER_STARTED":
                status = "NO_CI_DETECTED"

            return {
                "status": status,
                "head_sha": head_sha,
                "check_runs": ci.get("check_runs", []),
                "commit_statuses": ci.get("commit_statuses", []),
                "workflow_runs": wf_runs,
                "total_checks": ci.get("total_count", 0) + len(wf_runs),
            }
        except Exception as e:
            return {
                "status": "UNKNOWN",
                "head_sha": None,
                "check_runs": [],
                "commit_statuses": [],
                "workflow_runs": [],
                "error": str(e),
            }

    async def poll_check_runs(
        self,
        owner: str,
        repo: str,
        commit_ref: str,
        max_attempts: int = 5,
        initial_delay: float = 1.0,
        backoff_factor: float = 1.5,
        max_delay: float = 8.0,
    ) -> Dict[str, Any]:
        """
        Polls combined CI status (check-runs + commit statuses) with exponential backoff and a cap.
        """
        import asyncio
        delay = initial_delay
        last_summary: Dict[str, Any] = {
            "total_count": 0,
            "all_completed": False,
            "all_passed": False,
            "check_runs": [],
            "commit_statuses": [],
            "status": "PENDING_OR_QUEUED",
        }

        for attempt in range(max_attempts):
            try:
                ci = await self.get_combined_ci_status(owner, repo, commit_ref)
                last_summary = ci
                if ci["total_count"] > 0 and ci["all_completed"]:
                    return last_summary
            except Exception:
                pass

            if attempt < max_attempts - 1:
                await asyncio.sleep(delay)
                delay = min(delay * backoff_factor, max_delay)

        return last_summary

    async def get_default_branch_ci_status(
        self,
        owner: str,
        repo: str,
        default_branch: str,
    ) -> str:
        """Captures the baseline CI status string of the default branch's latest commit."""
        details = await self.get_default_branch_ci_details(owner, repo, default_branch)
        return details.get("status", "UNKNOWN")

    async def mark_pr_ready_for_review(self, node_id: str) -> bool:
        """
        Marks a draft pull request as ready for review via GitHub GraphQL API.
        (The REST API cannot perform this action).
        """
        url = "https://api.github.com/graphql"
        query = """
        mutation MarkReady($pullRequestId: ID!) {
          markPullRequestReadyForReview(input: {pullRequestId: $pullRequestId}) {
            pullRequest {
              id
              isDraft
            }
          }
        }
        """
        payload = {
            "query": query,
            "variables": {"pullRequestId": node_id},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, headers=self.headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            if "errors" in data and data["errors"]:
                return False
            pr_data = data.get("data", {}).get("markPullRequestReadyForReview", {}).get("pullRequest", {})
            return not pr_data.get("isDraft", True)
