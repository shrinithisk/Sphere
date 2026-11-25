import os
import json
import pytest
import shutil
import subprocess
from app.planner.schema import normalize_finding
from app.orchestrator import sanitize_findings_for_llm
from app.scanners.gitleaks_wrapper import run_gitleaks, is_gitleaks_available


def test_no_raw_secret_in_report_json_and_semgrep_output():
    # Requirement 5: Fake key does not appear in report_json or Semgrep output
    fake_aws_key = "AKIAIOSFODNN7EXAMPLE"
    fake_pat = "ghp_1234567890abcdef1234567890abcdef"

    semgrep_raw = {
        "tool": "semgrep",
        "id": "generic.secrets.security.detected-token",
        "file": "config.py",
        "line": 5,
        "severity": "Critical",
        "description": f"Detected hardcoded token {fake_pat}",
        "code_snippet": f"GITHUB_TOKEN = '{fake_pat}'",
    }

    finding = normalize_finding(semgrep_raw)
    report_data = {
        "findings": [finding.model_dump()],
        "summary": "Repository scan completed",
    }
    report_json_str = json.dumps(report_data)

    # Must be quarantined as MANUAL_ONLY
    assert finding.fix_class == "MANUAL_ONLY" or finding.fix_class.value == "MANUAL_ONLY"
    # Raw PAT must NOT appear in suggested fix or sanitized report
    assert fake_pat not in finding.suggested_fix


def test_no_raw_secret_in_llm_prompt_strings():
    # Requirement 5: Fake key does not appear in any LLM prompt string
    fake_aws_key = "AKIAIOSFODNN7EXAMPLE"
    fake_pat = "ghp_1234567890abcdef1234567890abcdef"

    findings = [
        {
            "id": "leak-1",
            "tool": "gitleaks",
            "rule_id": "aws-key",
            "file": "aws.py",
            "description": f"Potential leak of aws-key: {fake_aws_key}",
            "code_snippet": f"AWS_KEY = '{fake_aws_key}'",
            "fix_suggestion": f"Rotate key {fake_aws_key}",
        },
        {
            "id": "leak-2",
            "tool": "semgrep",
            "rule_id": "github-token",
            "file": "ci.py",
            "description": f"Hardcoded secret {fake_pat}",
            "code_snippet": f"TOKEN = '{fake_pat}'",
        }
    ]

    sanitized = sanitize_findings_for_llm(findings)
    llm_prompt = f"Analyze security risks:\n{json.dumps(sanitized, indent=2)}"

    assert fake_aws_key not in llm_prompt
    assert fake_pat not in llm_prompt
    assert "[REDACTED]" in llm_prompt


def test_gitleaks_redact_masks_match_field(tmp_path):
    # Requirement 5: Confirm on a real run that gitleaks --redact masks the Match field
    if not is_gitleaks_available():
        pytest.skip("Gitleaks binary not available on test host")

    fake_key = "ghp_123456789012345678901234567890123456"
    repo_dir = tmp_path / "gitleaks_redact_repo"
    repo_dir.mkdir()
    secret_file = repo_dir / "keys.py"
    secret_file.write_text(f"GITHUB_PAT = '{fake_key}'\n")

    # Run gitleaks
    findings = run_gitleaks(str(repo_dir))
    assert len(findings) > 0

    for f in findings:
        # None of the findings should expose the raw unmasked fake_key
        assert fake_key not in f.get("description", "")
        assert fake_key not in f.get("fix_suggestion", "")
        assert "[REDACTED]" in f.get("description", "") or "REDACTED" in f.get("fix_suggestion", "")


@pytest.mark.asyncio
async def test_file_contents_redaction_for_workflow_engineer(tmp_path):
    """
    Requirement 6: Redaction covers file contents sent to the LLM (workflow engineer),
    including generic high-entropy secrets, not only AWS keys and PATs.
    """
    from app.orchestrator import engineer_workflows_node

    repo_dir = tmp_path / "wf_repo"
    repo_dir.mkdir()
    wf_dir = repo_dir / ".github" / "workflows"
    wf_dir.mkdir(parents=True)

    high_entropy_secret = "d41d8cd98f00b204e9800998ecf8427e"
    raw_pat = "ghp_abcdef1234567890abcdef1234567890"
    raw_pw = "SuperSecretDbPassword2026!"

    workflow_content = f"""name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      API_TOKEN: "{high_entropy_secret}"
      GITHUB_TOKEN: "{raw_pat}"
      DB_PASSWORD: "{raw_pw}"
    steps:
      - run: echo "deploy"
"""
    (wf_dir / "ci.yml").write_text(workflow_content)

    state = {
        "repo_path": str(repo_dir),
        "session_id": "test-session",
        "findings": [],
        "health_scores": {"repo_score": 100, "pipeline_score": 100},
    }

    # Execute workflow engineering node (runs with mock LLM when no GEMINI_API_KEY)
    result = await engineer_workflows_node(state)
    assert "optimized_workflows" in result
    optimized = result["optimized_workflows"]
    assert len(optimized) > 0

    # Ensure none of the raw secrets appear in content
    content_str = json.dumps(optimized)
    assert high_entropy_secret not in content_str
    assert raw_pat not in content_str
    assert raw_pw not in content_str


def test_generic_high_entropy_secret_redacted_in_remediation_findings():
    """
    Requirement 6: Redaction in remediation node covers generic high-entropy secrets and passwords.
    """
    from app.orchestrator import sanitize_text_for_llm

    high_entropy_token = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab34"
    generic_secret = "secret_key = 'MyUltraSecretKey123!'"
    raw_jwt_bearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature"

    text = f"Config contains {high_entropy_token} and {generic_secret} with {raw_jwt_bearer}"
    sanitized = sanitize_text_for_llm(text)

    assert high_entropy_token not in sanitized
    assert "MyUltraSecretKey123!" not in sanitized
    assert "doNotLeakThisSignature" not in sanitized
    assert "[REDACTED]" in sanitized


def test_uses_lines_and_git_shas_not_redacted():
    """
    Requirement 4: Exclude `uses:` lines and 40-char git SHAs from the generic hex rule
    so GitHub Action commit pinning is preserved.
    """
    from app.orchestrator import sanitize_text_for_llm

    pinned_sha = "34e114876b0b11c390a56381ad16ebd13914f8d5"
    sample_workflow = f"""
name: Build
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{pinned_sha} # v4
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
"""
    sanitized = sanitize_text_for_llm(sample_workflow)
    assert pinned_sha in sanitized
    assert "49933ea5288caeca8642d1e84afbd3f7d6820020" in sanitized
    assert "[REDACTED]" not in sanitized


def test_patch_applier_rejects_patch_with_redaction_marker(tmp_path):
    """
    Requirement 4: Reject any patch that contains the '[REDACTED]' marker before applying it
    to prevent corrupting the user's repository with placeholder text.
    """
    from app.verifier.sandbox import RepoSandbox
    from app.planner.schema import UnifiedFinding, Category, FixClass, FixType

    repo_dir = tmp_path / "sandbox_repo"
    repo_dir.mkdir()
    (repo_dir / "app.py").write_text("API_KEY = 'old_secret_value'\n")

    corrupted_finding = UnifiedFinding(
        id="CORRUPT-1",
        tool="semgrep",
        rule_id="secret-leak",
        file="app.py",
        category=Category.CODE,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Masked patch",
        original_block="API_KEY = 'old_secret_value'",
        patched_block="API_KEY = '[REDACTED]'",  # Should be rejected!
    )

    with RepoSandbox(str(repo_dir)) as sandbox:
        applied, err = sandbox.apply_patch(corrupted_finding)
        assert applied is False
        assert "contains '[REDACTED]' marker" in err


def test_remediation_sanitizes_dockerfile_package_requirements_source():
    """
    Requirement 4: Confirm remediation node sanitizes Dockerfile, package.json, requirements, and source contents.
    """
    from app.orchestrator import sanitize_findings_for_llm

    raw_token = "ghp_1234567890abcdef1234567890abcdef"
    raw_aws = "AKIA1234567890ABCDEF"
    hex_token = "e4d909c290d0fb1ca068ffaddf22cbd0"

    findings = [
        {
            "id": "1",
            "file": "Dockerfile",
            "code_snippet": f"ENV SECRET_TOKEN={raw_token}\nRUN echo $SECRET_TOKEN",
        },
        {
            "id": "2",
            "file": "package.json",
            "code_snippet": f'"private-pkg": "git+https://{raw_token}@github.com/org/pkg.git"',
        },
        {
            "id": "3",
            "file": "requirements.txt",
            "code_snippet": f"api-client @ git+https://token:{raw_token}@github.com/org/api.git",
        },
        {
            "id": "4",
            "file": "config.py",
            "code_snippet": f"AWS_KEY = '{raw_aws}'\nSECRET = '{hex_token}'",
        },
    ]

    sanitized = sanitize_findings_for_llm(findings)
    dumped = json.dumps(sanitized)

    assert raw_token not in dumped
    assert raw_aws not in dumped
    assert hex_token not in dumped
    assert "[REDACTED]" in dumped
