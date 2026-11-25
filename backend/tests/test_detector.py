import os
import json
import pytest
from app.verifier.detector import detect_project_profile, generate_minimal_ci_workflow


def test_detect_python_project_with_tests(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.25.1\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_sample.py").write_text("def test_ok(): pass\n")

    profile = detect_project_profile(str(tmp_path))
    assert "python" in profile.ecosystems
    assert profile.has_tests is True
    assert profile.test_command == "pytest"
    # Requirement B1: Detector must NOT set STATIC-VERIFIED. Remains UNVERIFIED.
    assert profile.verification_label == "UNVERIFIED"
    assert profile.tests_detected is True
    assert profile.static_checks_passed is False
    # Requirement B2: Semgrep/LLM code patches are always draft-only until GitHub CI passes
    assert profile.can_auto_pr_code_patches is False


def test_detect_node_project_with_ci(tmp_path):
    pkg_data = {
        "name": "demo-app",
        "scripts": {
            "build": "vite build",
            "test": "vitest run"
        }
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg_data))
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("name: CI\n")

    profile = detect_project_profile(str(tmp_path))
    assert "node" in profile.ecosystems
    assert profile.has_tests is True
    assert profile.has_ci is True
    assert "ci.yml" in profile.ci_workflows
    assert profile.build_command == "npm run build"
    assert profile.test_command == "npm test"
    # Requirement B1: Remains UNVERIFIED until static checks pass
    assert profile.verification_label == "UNVERIFIED"
    assert profile.tests_detected is True
    assert profile.static_checks_passed is False
    # Requirement B2: draft-pr only
    assert profile.can_auto_pr_code_patches is False


def test_detect_empty_or_untested_project(tmp_path):
    (tmp_path / "notes.txt").write_text("Just notes\n")

    profile = detect_project_profile(str(tmp_path))
    assert profile.has_tests is False
    assert profile.tests_detected is False
    assert profile.static_checks_passed is False
    assert profile.has_ci is False
    assert profile.verification_label == "UNVERIFIED"
    assert profile.can_auto_pr_code_patches is False
    # Offers minimal CI workflow
    assert profile.recommended_ci_workflow is not None


def test_minimal_ci_workflow_generation():
    py_wf = generate_minimal_ci_workflow("python")
    assert "setup-python@" in py_wf
    assert "pytest" in py_wf
    assert "permissions:\n  contents: read" in py_wf
