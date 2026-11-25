import os
import shutil
import tempfile
import git
import re
import json
from typing import Optional, List, Dict, Any, Tuple
from app.planner.schema import UnifiedFinding
from app.verifier.syntax_checker import reconcile_npm_lockfile, clean_sandbox_package_manager_configs


def resolve_sandbox_file(sandbox_root: str, file_path: str) -> str:
    """
    Requirement B6 & 6: Resolve finding.file and verify it stays inside the sandbox root using realpath.
    Blocks directory traversal attempts (e.g., ../../etc/passwd) and symlink escapes.
    """
    if not sandbox_root or not os.path.isdir(sandbox_root):
        raise ValueError(f"Invalid sandbox root directory: {sandbox_root}")

    clean = str(file_path).strip().replace("\\", "/")
    if clean.startswith("/") or clean.startswith("..") or any(part == ".." for part in clean.split("/")):
        raise ValueError(f"Path traversal detected: '{file_path}' attempts to traverse outside sandbox.")

    root_real = os.path.realpath(sandbox_root)
    full_path = os.path.realpath(os.path.join(sandbox_root, clean))

    if not (full_path == root_real or full_path.startswith(root_real + os.sep)):
        raise ValueError(f"Path traversal detected: '{file_path}' resolves outside sandbox root.")

    return full_path


class RepoSandbox:
    """
    Isolated copy of a target repository for applying, testing, and verifying fixes.
    Guarantees the user's original directory is NEVER modified.
    
    Security & Isolation guarantees:
    - Never follows symlinks (skips symlinks to prevent reading/writing outside repository).
    - Fresh git init with core.hooksPath=/dev/null and core.fsmonitor=false.
    - Commits with --no-verify.
    - Always cleans up temp directory in finally / __exit__.
    - Strictly resolves and validates all file paths against sandbox boundary.
    """

    def __init__(self, source_repo_path: str):
        self.source_repo_path = os.path.realpath(source_repo_path)
        self.sandbox_path: Optional[str] = None
        self.repo: Optional[git.Repo] = None
        self.baseline_commit_sha: Optional[str] = None
        self.active_branch: str = "sphere/verify-fixes"

    def __enter__(self):
        self.sandbox_path = os.path.realpath(tempfile.mkdtemp(prefix="sphere_sandbox_"))

        try:
            # Copy repository files into the isolated sandbox
            # Requirement B5: Never follow symlinks (skip symlinks without dereferencing)
            def ignore_patterns(path, names):
                ignored = set()
                for name in names:
                    full = os.path.join(path, name)
                    # Ignore .git and transient directories
                    if name in (".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"):
                        ignored.add(name)
                    # Skip symlinks completely without dereferencing
                    elif os.path.islink(full):
                        ignored.add(name)
                return ignored

            shutil.copytree(
                self.source_repo_path,
                self.sandbox_path,
                dirs_exist_ok=True,
                symlinks=False,  # Combined with ignore_patterns skipping symlinks, nothing is followed
                ignore=ignore_patterns,
            )

            # Requirement 3: Delete .npmrc and .yarnrc* from sandbox
            clean_sandbox_package_manager_configs(self.sandbox_path)

            # Initialize clean isolated Git repository in sandbox
            self.repo = git.Repo.init(self.sandbox_path)

            # Requirement B5: disable core.hooksPath and core.fsmonitor=false
            self.repo.git.config("user.name", "Sphere AI Sandbox")
            self.repo.git.config("user.email", "sphere-sandbox@sphere.dev")
            self.repo.git.config("core.hooksPath", "/dev/null")
            self.repo.git.config("core.fsmonitor", "false")

            # Create baseline commit with --no-verify
            self.repo.git.add(A=True)
            try:
                self.repo.git.commit("-m", "chore: baseline repository state before fixes", "--no-verify")
                self.baseline_commit_sha = self.repo.head.commit.hexsha
            except git.GitCommandError:
                # Empty repo
                pass

            # Switch to feature verification branch
            try:
                self.repo.git.checkout("-b", self.active_branch)
            except Exception:
                pass

            return self
        except Exception:
            self.cleanup()
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self) -> None:
        """Requirement B5: Always clean up the temp dir."""
        if self.sandbox_path and os.path.exists(self.sandbox_path):
            try:
                shutil.rmtree(self.sandbox_path)
            except Exception as e:
                print(f"Warning: Failed to clean up sandbox directory {self.sandbox_path}: {e}")
            finally:
                self.sandbox_path = None
                self.repo = None

    def apply_patch(self, finding: UnifiedFinding) -> Tuple[bool, Optional[str]]:
        """
        Applies a unified finding's patch inside the isolated sandbox.
        Returns (success, error_message).
        """
        if not self.sandbox_path:
            return False, "Sandbox not initialized."

        # Requirement B6: Verify finding.file stays inside sandbox root
        try:
            target_full = resolve_sandbox_file(self.sandbox_path, finding.file)
        except ValueError as ve:
            return False, f"Path traversal attempt blocked: {str(ve)}"

        if not os.path.exists(target_full):
            # Create if it's a workflow or config insert
            os.makedirs(os.path.dirname(target_full), exist_ok=True)
            with open(target_full, "w", encoding="utf-8") as f:
                f.write("")

        orig_block = finding.original_block
        patch_block = finding.patched_block

        if not patch_block and finding.fixed_version:
            if target_full.endswith(".json"):
                patch_block = f'"{finding.package}": "{finding.fixed_version}"'
            else:
                patch_block = f"{finding.package}=={finding.fixed_version}"

        if not patch_block:
            return False, f"No patch block provided for finding {finding.id}."

        # Item 4: Reject any patch that contains the redaction marker
        if "[REDACTED]" in patch_block or "[REDACTED_PRIVATE_KEY]" in patch_block:
            return False, f"Patch rejected for {finding.id}: suggested patch contains '[REDACTED]' marker, which would corrupt source code."

        try:
            with open(target_full, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            new_content = None

            # 1. Exact string match
            if orig_block and orig_block in content:
                new_content = content.replace(orig_block, patch_block, 1)

            # 2. Stripped whitespace match
            elif orig_block and orig_block.strip() in content:
                new_content = content.replace(orig_block.strip(), patch_block.strip(), 1)

            # 3. Targeted line-level replacement (e.g. for dependencies or single-line fixes)
            elif finding.package:
                lines = content.splitlines(True)
                new_lines = []
                replaced = False
                pkg_lower = finding.package.lower()

                for line in lines:
                    if not replaced and pkg_lower in line.lower():
                        formatted_patch = patch_block if patch_block.endswith("\n") else patch_block + "\n"
                        new_lines.append(formatted_patch)
                        replaced = True
                    else:
                        new_lines.append(line)

                if replaced:
                    new_content = "".join(new_lines)

            # 4. Fallback: file-level replacement if original block matches entire file
            elif orig_block and content.strip() == orig_block.strip():
                new_content = patch_block

            # 5. Append if not found and is config insertion
            elif finding.fix_type == "config_insert":
                new_content = content.rstrip() + "\n\n" + patch_block + "\n"

            # 6. Transitive dependency handling (Item 5):
            # If finding.package was not found directly in file:
            if (new_content is None or new_content == content) and finding.package:
                base_name = os.path.basename(target_full)
                if base_name == "package.json":
                    try:
                        pkg_json = json.loads(content)
                        in_deps = finding.package in pkg_json.get("dependencies", {})
                        in_dev = finding.package in pkg_json.get("devDependencies", {})
                        if not in_deps and not in_dev:
                            # It is a transitive dependency! Apply npm override
                            if "overrides" not in pkg_json:
                                pkg_json["overrides"] = {}
                            ver_val = finding.fixed_version or (finding.patched_block or "").replace('"', '').strip()
                            pkg_json["overrides"][finding.package] = ver_val
                            new_content = json.dumps(pkg_json, indent=2) + "\n"
                    except Exception:
                        pass
                elif "requirements" in base_name and base_name.endswith(".txt"):
                    ver_val = finding.fixed_version or "latest"
                    new_content = content.rstrip() + f"\n{finding.package}=={ver_val}  # Transitive dependency pinned for security\n"

            if new_content is None or new_content == content:
                return False, f"Could not locate matching target code for '{finding.package or finding.file}' to apply patch."

            # Write updated content
            with open(target_full, "w", encoding="utf-8") as f:
                f.write(new_content)

            # If package.json was updated, reconcile npm lockfile with --ignore-scripts
            if os.path.basename(target_full) == "package.json":
                reconcile_npm_lockfile(self.sandbox_path)

            return True, None
        except Exception as e:
            return False, f"Exception while applying patch to {finding.file}: {str(e)}"

    def revert_patch(self, finding: UnifiedFinding) -> None:
        """
        Reverts any uncommitted changes to the specified file in the sandbox.
        Restores it cleanly to the last committed git state.
        """
        if not self.repo or not self.sandbox_path:
            return
        try:
            target_full = resolve_sandbox_file(self.sandbox_path, finding.file)
            target_rel = os.path.relpath(target_full, os.path.realpath(self.sandbox_path))
            self.repo.git.checkout("HEAD", "--", target_rel)
            # If lockfile was modified, revert lockfile too
            if os.path.basename(target_rel) == "package.json":
                try:
                    self.repo.git.checkout("HEAD", "--", "package-lock.json")
                except Exception:
                    pass
        except Exception as e:
            print(f"Warning: Failed to checkout reverted file {finding.file}: {e}")

    def commit_fix(self, finding: UnifiedFinding) -> str:
        """
        Creates an individual atomic Git commit in the sandbox for a verified fix.
        Requirement B5: Commits with --no-verify.
        Returns the new commit SHA.
        """
        if not self.repo:
            raise RuntimeError("Sandbox git repo not available.")

        # Stage all changes (including reconciled lockfiles)
        self.repo.git.add(A=True)

        cat = finding.category if isinstance(finding.category, str) else finding.category.value
        pkg_or_rule = finding.package or finding.rule_id
        commit_msg = f"fix({cat}): resolve {pkg_or_rule} in {finding.file}\n\nFinding ID: {finding.id}\nResolved Issues: {finding.resolved_issue_count}"

        # Requirement B5: Commit with --no-verify
        self.repo.git.commit("-m", commit_msg, "--no-verify")
        return self.repo.head.commit.hexsha

    def get_diff(self, against_baseline: bool = True) -> str:
        """Returns the unified diff of changes made in the sandbox."""
        if not self.repo:
            return ""
        try:
            ref = self.baseline_commit_sha if (against_baseline and self.baseline_commit_sha) else "HEAD~1"
            return self.repo.git.diff(ref)
        except Exception:
            return ""

    def get_commit_count(self) -> int:
        """Returns number of fix commits made after the baseline."""
        if not self.repo or not self.baseline_commit_sha:
            return 0
        try:
            commits = list(self.repo.iter_commits(f"{self.baseline_commit_sha}..HEAD"))
            return len(commits)
        except Exception:
            return 0
