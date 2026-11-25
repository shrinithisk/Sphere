import os
import subprocess
import shutil
from typing import Dict, List, Optional, Tuple

# Sensitive environment variables that must NEVER leak to child processes
SENSITIVE_ENV_KEYS = {
    "GEMINI_API_KEY",
    "GROQ_API_KEY",
    "DATABASE_URL",
    "JWT_SECRET_KEY",
    "GITHUB_TOKEN",
    "GITHUB_PAT",
    "PAT",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "SECRET_KEY",
    "PASSWORD",
    "API_KEY",
    "TOKEN",
}

# Strict allowlist of environment keys permitted for child processes (Requirement 6)
ALLOWED_ENV_KEYS = frozenset({
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "USER",
    "SHELL",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
})

DEFAULT_SUBPROCESS_TIMEOUT = 30  # seconds
MAX_OUTPUT_BYTES = 100 * 1024     # 100 KB output cap


def get_scrubbed_env() -> Dict[str, str]:
    """
    Constructs a minimal, sanitized environment dictionary for child processes.
    Requirement 6: Strict allowlist only.
    - Strips all API keys, DB credentials, JWT secrets, and PAT tokens.
    - Disables terminal prompts (GIT_TERMINAL_PROMPT=0).
    - Ignores repo-level and user-level .npmrc configurations to prevent credential harvesting.
    """
    clean_env: Dict[str, str] = {}

    for k in ALLOWED_ENV_KEYS:
        if k in os.environ:
            clean_env[k] = os.environ[k]

    # Fallback default PATH if missing
    if "PATH" not in clean_env:
        clean_env["PATH"] = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

    # Strict isolation and security overrides
    clean_env["GIT_TERMINAL_PROMPT"] = "0"
    clean_env["CI"] = "1"
    
    # npm clean isolation: ignore local and user .npmrc files
    clean_env["npm_config_userconfig"] = "/dev/null"
    clean_env["npm_config_globalconfig"] = "/dev/null"
    clean_env["npm_config_audit"] = "false"
    clean_env["npm_config_fund"] = "false"

    # Explicitly ensure no sensitive variables exist
    for sensitive_key in SENSITIVE_ENV_KEYS:
        clean_env.pop(sensitive_key, None)

    return clean_env


def safe_subprocess_run(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout: int = DEFAULT_SUBPROCESS_TIMEOUT,
    max_bytes: int = MAX_OUTPUT_BYTES,
) -> Tuple[int, str, str]:
    """
    Executes a subprocess with:
    1. Scrubbed minimal environment (no secrets/PATs).
    2. Strict execution timeout.
    3. Output capping to prevent memory exhaustion.
    
    Returns (exit_code, stdout, stderr).
    """
    env = get_scrubbed_env()

    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=timeout,
            text=True,
            errors="replace",
        )
        stdout = proc.stdout[:max_bytes] if proc.stdout else ""
        stderr = proc.stderr[:max_bytes] if proc.stderr else ""
        return proc.returncode, stdout, stderr

    except subprocess.TimeoutExpired as te:
        stdout = te.stdout[:max_bytes] if (te.stdout and isinstance(te.stdout, str)) else ""
        stderr = te.stderr[:max_bytes] if (te.stderr and isinstance(te.stderr, str)) else ""
        return -1, stdout, f"Execution timed out after {timeout}s: {stderr}"

    except Exception as e:
        return -1, "", f"Failed to execute process: {str(e)}"
