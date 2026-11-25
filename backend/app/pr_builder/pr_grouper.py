from typing import List, Dict, Any, Tuple
from app.planner.schema import UnifiedFinding, Category, FixClass


def group_fixes_by_pr(
    verified_fixes: List[UnifiedFinding],
) -> Dict[str, Dict[str, Any]]:
    """
    Groups verified fixes into separate PR batches:
    1. Dependencies (minor/patch): sphere/fix-dependencies
    2. Dependencies (major): sphere/fix-dependencies-major (SEPARATE DRAFT PR)
    3. Dockerfile fixes: sphere/fix-docker
    4. Workflow fixes: sphere/fix-workflows
    5. Code / Semgrep fixes: sphere/fix-code (DRAFT PR ONLY)
    """
    groups: Dict[str, Dict[str, Any]] = {
        "dependencies_minor": {
            "key": "dependencies_minor",
            "branch": "sphere/fix-dependencies-patch",
            "title": "fix(deps): automated dependency security upgrades (patch/minor)",
            "category_label": "Dependencies (Patch/Minor)",
            "draft_pr_only": True,  # Initially opened as draft until CI passes
            "is_major_pr": False,
            "fixes": [],
        },
        "dependencies_major": {
            "key": "dependencies_major",
            "branch": "sphere/fix-dependencies-major",
            "title": "fix(deps)!: major dependency upgrades (manual review required)",
            "category_label": "Dependencies (Major Breaking)",
            "draft_pr_only": True,  # Major bumps are strictly draft PR
            "is_major_pr": True,
            "fixes": [],
        },
        "docker": {
            "key": "docker",
            "branch": "sphere/fix-docker",
            "title": "fix(docker): container hardening and hadolint remediations",
            "category_label": "Docker Container Hardening",
            "draft_pr_only": True,
            "is_major_pr": False,
            "fixes": [],
        },
        "workflows": {
            "key": "workflows",
            "branch": "sphere/fix-workflows",
            "title": "fix(workflows): action commit SHA pinning & least-privilege permissions",
            "category_label": "GitHub Actions & Workflows",
            "draft_pr_only": True,
            "is_major_pr": False,
            "fixes": [],
        },
        "code": {
            "key": "code",
            "branch": "sphere/fix-code",
            "title": "fix(code): SAST and code security remediations",
            "category_label": "Code / Semgrep Remediations",
            "draft_pr_only": True,  # Semgrep/LLM code patches are always draft-only
            "is_major_pr": False,
            "fixes": [],
        },
    }

    for f in verified_fixes:
        cat = f.category if isinstance(f.category, str) else f.category.value

        if cat == Category.DEPENDENCY.value or cat == Category.DEPENDENCY:
            if getattr(f, "is_major_bump", False):
                groups["dependencies_major"]["fixes"].append(f)
            else:
                groups["dependencies_minor"]["fixes"].append(f)

        elif cat == Category.DOCKER.value or cat == Category.DOCKER:
            groups["docker"]["fixes"].append(f)

        elif cat in (Category.WORKFLOW.value, Category.WORKFLOW, Category.HYGIENE.value, Category.HYGIENE):
            groups["workflows"]["fixes"].append(f)

        elif cat == Category.CODE.value or cat == Category.CODE:
            groups["code"]["fixes"].append(f)

        else:
            groups["code"]["fixes"].append(f)

    # Return only groups that have at least one verified fix
    return {k: v for k, v in groups.items() if v["fixes"]}


def build_pr_body(
    group_info: Dict[str, Any],
    verification_label: str = "STATIC-VERIFIED (tests not run)",
    default_branch_ci: str = "PASSING",
    branch_ci_status: str = "PENDING_CI",
    commits_list: List[Dict[str, str]] = None,
) -> str:
    """
    Constructs a comprehensive, compliant Pull Request description:
    - Applied changes
    - Resolved findings & CVE table
    - Verification label (STATIC-VERIFIED or UNVERIFIED)
    - Default branch CI baseline comparison & branch CI status
    - Risk level and breaking change notices
    - Revert instructions
    - Documented fine-grained PAT permissions
    """
    fixes: List[UnifiedFinding] = group_info["fixes"]
    is_major = group_info.get("is_major_pr", False)
    is_code = group_info.get("key") == "code"

    # Risk level calculation
    if is_major:
        risk_level = "HIGH (Major version upgrades may introduce breaking API changes)"
    elif is_code:
        risk_level = "MEDIUM (Code modifications require automated GitHub Actions CI verification)"
    else:
        risk_level = "LOW (Automated static verification clean)"

    body_lines = [
        f"## 🛡️ Sphere Automated Security Remediations",
        "",
        f"**Target Category**: `{group_info['category_label']}`  ",
        f"**Verification Status**: `{verification_label}`  ",
        f"**Default Branch Baseline CI**: `{default_branch_ci}`  ",
        f"**Current Branch CI Status**: `{branch_ci_status}`  ",
        f"**Risk Level**: **{risk_level}**  ",
        "",
    ]

    if is_major:
        body_lines.extend([
            "> [!WARNING]",
            "> **Major Version Bumps Detected**: This Pull Request contains major version upgrades that may contain breaking API changes.",
            "> It is opened as a **Draft Pull Request** to allow thorough review and manual testing before merge.",
            "",
        ])
    elif is_code:
        body_lines.extend([
            "> [!NOTE]",
            "> **Code Remediations**: Code-level patches are submitted as a **Draft Pull Request**.",
            "> Once GitHub Actions CI completes successfully, this PR will automatically transition to Ready for Review.",
            "",
        ])

    # Table of Resolved Findings
    body_lines.extend([
        "### 📋 Resolved Security Findings",
        "",
        "| ID | Tool | Rule | File | Severity | Resolved Issues |",
        "|---|---|---|---|---|---|",
    ])

    for f in fixes:
        sev = f.severity if isinstance(f.severity, str) else f.severity.value
        body_lines.append(
            f"| `{f.id}` | {f.tool} | `{f.rule_id}` | `{f.file}` | **{sev}** | {f.resolved_issue_count} issue(s) |"
        )

    body_lines.extend(["", "### 🔧 Applied Commits", ""])
    if commits_list:
        for c in commits_list:
            sha = c.get("sha", "")[:7]
            msg = c.get("message", "").split("\n")[0]
            body_lines.append(f"- `{sha}` - {msg}")
    else:
        for f in fixes:
            body_lines.append(f"- Fix for `{f.rule_id}` in `{f.file}` ({f.suggested_fix})")

    # Revert Steps
    body_lines.extend([
        "",
        "### ↩️ How to Revert",
        "If any regression occurs after merging, you can revert cleanly using:",
        "```bash",
        "# To revert all commits in this branch:",
        f"git revert --no-edit HEAD~{len(fixes)}..HEAD",
        "",
        "# Or revert individual fix commits by SHA shown above:",
        "git revert <commit-sha>",
        "```",
        "",
        "### 🔑 Required GitHub Personal Access Token (PAT) Permissions",
        "Sphere operates using minimal least-privilege fine-grained PAT permissions:",
        "- **Contents**: `Read and write` (to query file blob SHAs, create Git tree blobs, and commit verified fixes)",
        "- **Pull requests**: `Read and write` (to open Draft PRs and mutate draft status via GraphQL)",
        "- **Workflows**: `Read and write` (to pin action SHAs and configure least-privilege workflow permissions)",
        "- **Checks**: `Read-only` (to inspect GitHub Actions check runs status)",
        "",
        "---",
        "*Automated with ❤️ by [Sphere](https://github.com/shrinithisk/Sphere)*",
    ])

    return "\n".join(body_lines)
