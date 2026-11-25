import ast
import json
import os
import shutil
import re
from typing import Tuple, Optional
from app.verifier.subprocess_runner import safe_subprocess_run


def check_python_syntax(full_path: str) -> Tuple[bool, Optional[str]]:
    """Validates Python syntax using ast.parse without executing code."""
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        ast.parse(code, filename=full_path)
        return True, None
    except SyntaxError as se:
        return False, f"Python SyntaxError at line {se.lineno}: {se.msg} (text: {se.text})"
    except Exception as e:
        return False, f"Python code validation error: {str(e)}"


def check_json_syntax(full_path: str) -> Tuple[bool, Optional[str]]:
    """Validates JSON structure."""
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            json.load(f)
        return True, None
    except Exception as e:
        return False, f"JSON parse error: {str(e)}"


def check_yaml_syntax(full_path: str) -> Tuple[bool, Optional[str]]:
    """Validates YAML syntax safely."""
    try:
        import yaml
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            yaml.safe_load(f)
        return True, None
    except Exception as e:
        return False, f"YAML parse error: {str(e)}"


def check_workflow_actionlint(full_path: str, repo_path: str) -> Tuple[bool, Optional[str]]:
    """Runs actionlint on a workflow file if actionlint is installed."""
    if not shutil.which("actionlint"):
        # Fall back to yaml safe_load
        return check_yaml_syntax(full_path)

    # First check basic yaml syntax
    valid_yaml, yaml_err = check_yaml_syntax(full_path)
    if not valid_yaml:
        return False, yaml_err

    rel_file = os.path.relpath(full_path, repo_path)
    code, stdout, stderr = safe_subprocess_run(
        ["actionlint", "-oneline", rel_file],
        cwd=repo_path,
        timeout=15,
    )
    if code != 0 and stdout.strip():
        return False, f"Actionlint error: {stdout.strip()}"
    return True, None


def check_dockerfile_hadolint(full_path: str) -> Tuple[bool, Optional[str]]:
    """Validates Dockerfile directives and checks for fatal syntax errors."""
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        has_from = any(line.strip().upper().startswith("FROM ") for line in lines)
        if not has_from:
            return False, "Dockerfile missing mandatory 'FROM' instruction."
    except Exception as e:
        return False, f"Dockerfile read error: {str(e)}"

    if shutil.which("hadolint"):
        code, stdout, stderr = safe_subprocess_run(
            ["hadolint", "--format", "json", full_path],
            timeout=15,
        )
        if stdout.strip():
            try:
                issues = json.loads(stdout.strip())
                errors = [i for i in issues if i.get("level") == "error"]
                if errors:
                    err_msg = "; ".join(f"Line {e.get('line')}: {e.get('message')}" for e in errors)
                    return False, f"Hadolint fatal error: {err_msg}"
            except Exception:
                pass

    return True, None


def clean_sandbox_package_manager_configs(repo_path: str) -> None:
    """
    Requirement 3: Delete .npmrc and .yarnrc* from the sandbox before any package-manager command,
    since npm_config_userconfig does not cover project-level .npmrc / .yarnrc files.
    """
    if not repo_path or not os.path.isdir(repo_path):
        return
    for item in os.listdir(repo_path):
        if item == ".npmrc" or item.startswith(".yarnrc"):
            target = os.path.join(repo_path, item)
            try:
                if os.path.isfile(target) or os.path.islink(target):
                    os.remove(target)
                elif os.path.isdir(target):
                    shutil.rmtree(target)
            except Exception as e:
                print(f"Warning: Failed to remove {target}: {e}")


def reconcile_npm_lockfile(repo_path: str) -> Tuple[bool, Optional[str]]:
    """
    Safely reconciles npm package-lock.json using --package-lock-only and --ignore-scripts.
    NEVER runs install or postinstall scripts.
    Uses sanitized minimal environment and npm configs.
    Requirement 3: Deletes project-level .npmrc and .yarnrc* first.
    """
    if not shutil.which("npm"):
        return True, None

    pkg_json = os.path.join(repo_path, "package.json")
    if not os.path.isfile(pkg_json):
        return True, None

    # Requirement 3: Delete .npmrc / .yarnrc* before executing npm
    clean_sandbox_package_manager_configs(repo_path)

    code, stdout, stderr = safe_subprocess_run(
        ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
        cwd=repo_path,
        timeout=30,
    )
    if code != 0:
        return False, f"Lockfile update failed: {stderr.strip() or stdout.strip()}"
    return True, None


def check_requirements_syntax(file_path: str) -> Tuple[bool, Optional[str]]:
    """
    Validates static requirement lines in requirements.txt without running pip.
    Never executes install scripts on host.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                # Reject forbidden characters or shell injection attempts
                if any(c in stripped for c in [";", "&", "|", "`", "$"]):
                    return False, f"Invalid requirement syntax on line {idx}: forbidden shell characters in '{stripped}'"
                # Check package specification basic regex
                if not re.match(r'^[a-zA-Z0-9_\-\.\[\]]+(\s*(?:==|>=|<=|>|<|~=|!=)\s*[0-9a-zA-Z\.\-\*\+]+)?.*$', stripped):
                    return False, f"Invalid requirement format on line {idx}: '{stripped}'"
        return True, None
    except Exception as e:
        return False, f"Error validating requirements.txt: {str(e)}"


def check_file_static_syntax(file_path: str, repo_path: str) -> Tuple[bool, Optional[str]]:
    """
    Dispatcher for static syntax and compile validation.
    Returns (is_valid, error_message).
    """
    full_path = os.path.abspath(os.path.join(repo_path, file_path))
    if not os.path.isfile(full_path):
        return False, f"Target file '{file_path}' does not exist in sandbox."

    lower = file_path.lower()
    if lower.endswith(".py"):
        return check_python_syntax(full_path)
    elif lower.endswith(".json"):
        return check_json_syntax(full_path)
    elif "requirements" in lower and lower.endswith(".txt"):
        return check_requirements_syntax(full_path)
    elif lower.startswith(".github/workflows/") and (lower.endswith(".yml") or lower.endswith(".yaml")):
        return check_workflow_actionlint(full_path, repo_path)
    elif lower.endswith(".yml") or lower.endswith(".yaml"):
        return check_yaml_syntax(full_path)
    elif "dockerfile" in lower:
        return check_dockerfile_hadolint(full_path)

    return True, None
