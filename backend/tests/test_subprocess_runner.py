import os
import sys
import pytest
from app.verifier.subprocess_runner import safe_subprocess_run, get_scrubbed_env, SENSITIVE_ENV_KEYS


def test_gemini_api_key_not_visible_to_child_processes():
    # Requirement B8 & 6: Extend env test to GROQ_API_KEY and the JWT secret
    os.environ["GEMINI_API_KEY"] = "super-secret-gemini-key-9999"
    os.environ["GROQ_API_KEY"] = "super-secret-groq-key-8888"
    os.environ["JWT_SECRET_KEY"] = "secret-jwt-token-signing-key"
    os.environ["GITHUB_TOKEN"] = "ghp_leakedtoken12345"
    os.environ["DATABASE_URL"] = "postgres://user:pass@db.example.com/dbname"

    try:
        # Run a child process executing python and querying os.environ
        python_bin = sys.executable
        code, stdout, stderr = safe_subprocess_run(
            [python_bin, "-c", "import os; print('GEMINI=' + str(os.environ.get('GEMINI_API_KEY'))); print('GROQ=' + str(os.environ.get('GROQ_API_KEY'))); print('JWT=' + str(os.environ.get('JWT_SECRET_KEY'))); print('GITHUB=' + str(os.environ.get('GITHUB_TOKEN'))); print('DB=' + str(os.environ.get('DATABASE_URL')) )"],
        )

        assert code == 0
        assert "GEMINI=None" in stdout
        assert "GROQ=None" in stdout
        assert "JWT=None" in stdout
        assert "GITHUB=None" in stdout
        assert "DB=None" in stdout
        assert "super-secret-gemini-key" not in stdout
        assert "super-secret-groq-key" not in stdout
        assert "secret-jwt-token-signing-key" not in stdout
        assert "ghp_leakedtoken" not in stdout
    finally:
        os.environ.pop("GEMINI_API_KEY", None)
        os.environ.pop("GROQ_API_KEY", None)
        os.environ.pop("JWT_SECRET_KEY", None)
        os.environ.pop("GITHUB_TOKEN", None)
        os.environ.pop("DATABASE_URL", None)


def test_scrubbed_env_npm_clean_isolation():
    # Requirement B8: clean config that ignores repo's .npmrc
    env = get_scrubbed_env()
    assert env.get("npm_config_userconfig") == "/dev/null"
    assert env.get("npm_config_globalconfig") == "/dev/null"
    assert env.get("GIT_TERMINAL_PROMPT") == "0"
    assert env.get("CI") == "1"

    # Verify no sensitive keys present
    for key in SENSITIVE_ENV_KEYS:
        assert key not in env


def test_subprocess_timeout():
    # Requirement B8: Timeout handling
    python_bin = sys.executable
    code, stdout, stderr = safe_subprocess_run(
        [python_bin, "-c", "import time; time.sleep(5)"],
        timeout=1,
    )
    assert code == -1
    assert "timed out" in stderr.lower()


def test_subprocess_output_cap():
    # Requirement B8: Output capping
    python_bin = sys.executable
    code, stdout, stderr = safe_subprocess_run(
        [python_bin, "-c", "print('X' * 5000)"],
        max_bytes=100,
    )
    assert code == 0
    assert len(stdout) == 100
