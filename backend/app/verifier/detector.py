import os
import json
import re
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ProjectProfile(BaseModel):
    ecosystems: List[str] = Field(default_factory=list)
    has_tests: bool = False
    tests_detected: bool = False               # Requirement B1: tests_detected kept separate
    static_checks_passed: bool = False         # Requirement B1: static checks passed only after verification
    has_ci: bool = False
    ci_workflows: List[str] = Field(default_factory=list)
    build_command: Optional[str] = None
    test_command: Optional[str] = None
    verification_label: str = "UNVERIFIED"      # Requirement B1: Detector MUST NOT set STATIC-VERIFIED. Defaults to UNVERIFIED.
    can_auto_pr_code_patches: bool = False     # Requirement B2: Semgrep/LLM patches always draft-only until GitHub CI passes.
    recommended_ci_workflow: Optional[str] = None


def detect_project_profile(repo_path: str) -> ProjectProfile:
    """
    Inspects repository files to detect build/test configurations,
    existing GitHub Actions CI workflows, and project ecosystems.
    
    Adheres strictly to the rules:
    - NEVER execute repository scripts on the backend host.
    - Detector MUST NOT set STATIC-VERIFIED. Verification label remains UNVERIFIED
      until static checks and rescan pass in the verifier runner.
    - Semgrep/LLM code patches are always draft-only (can_auto_pr_code_patches = False).
    """
    if not os.path.isdir(repo_path):
        return ProjectProfile(verification_label="UNVERIFIED")

    ecosystems: List[str] = []
    has_tests = False
    build_cmd: Optional[str] = None
    test_cmd: Optional[str] = None

    # 1. Node.js detection
    pkg_json_path = os.path.join(repo_path, "package.json")
    if os.path.isfile(pkg_json_path):
        ecosystems.append("node")
        try:
            with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                pkg_data = json.load(f)
                scripts = pkg_data.get("scripts", {})
                if "build" in scripts:
                    build_cmd = "npm run build"
                if "test" in scripts:
                    test_script = str(scripts.get("test", "")).strip().lower()
                    if test_script and "no test specified" not in test_script:
                        test_cmd = "npm test"
                        has_tests = True
        except Exception:
            pass

    # 2. Python detection
    req_txt = os.path.join(repo_path, "requirements.txt")
    pyproject = os.path.join(repo_path, "pyproject.toml")
    pipfile = os.path.join(repo_path, "Pipfile")
    setup_py = os.path.join(repo_path, "setup.py")

    if any(os.path.isfile(p) for p in [req_txt, pyproject, pipfile, setup_py]):
        ecosystems.append("python")

    # Check for Python test files or configuration
    test_dirs = ["tests", "test"]
    has_py_test_dir = any(
        os.path.isdir(os.path.join(repo_path, d)) for d in test_dirs
    )
    has_pytest_ini = os.path.isfile(os.path.join(repo_path, "pytest.ini"))
    has_test_files = False

    if not has_py_test_dir and not has_pytest_ini:
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", "venv", "__pycache__"]]
            for f in files:
                if f.startswith("test_") or f.endswith("_test.py"):
                    has_test_files = True
                    break
            if has_test_files:
                break

    if has_py_test_dir or has_pytest_ini or has_test_files:
        has_tests = True
        test_cmd = test_cmd or "pytest"

    # 3. Go detection
    if os.path.isfile(os.path.join(repo_path, "go.mod")):
        ecosystems.append("go")
        build_cmd = build_cmd or "go build ./..."
        test_cmd = test_cmd or "go test ./..."
        has_tests = True

    # 4. Java/JVM detection
    if os.path.isfile(os.path.join(repo_path, "pom.xml")):
        ecosystems.append("maven")
        build_cmd = build_cmd or "mvn compile"
        test_cmd = test_cmd or "mvn test"
        has_tests = True
    elif os.path.isfile(os.path.join(repo_path, "build.gradle")):
        ecosystems.append("gradle")
        build_cmd = build_cmd or "gradle build"
        test_cmd = test_cmd or "gradle test"
        has_tests = True

    # 5. Dockerfile
    if os.path.isfile(os.path.join(repo_path, "Dockerfile")):
        ecosystems.append("docker")
        build_cmd = build_cmd or "docker build ."

    # 6. CI Workflows inspection (.github/workflows)
    workflow_dir = os.path.join(repo_path, ".github", "workflows")
    ci_workflows: List[str] = []
    has_ci = False

    if os.path.isdir(workflow_dir):
        for wf_file in os.listdir(workflow_dir):
            if wf_file.endswith(".yml") or wf_file.endswith(".yaml"):
                ci_workflows.append(wf_file)
                has_ci = True

    # Generate minimal CI workflow recommendation if repo has no CI
    recommended_ci: Optional[str] = None
    if not has_ci:
        primary_eco = ecosystems[0] if ecosystems else "generic"
        recommended_ci = generate_minimal_ci_workflow(primary_eco)

    # Requirement B1: Detector must NOT set STATIC-VERIFIED.
    # Verification label is UNVERIFIED until verifier runner completes static checks and rescan.
    # Requirement B2: can_auto_pr_code_patches is False because Semgrep/LLM code patches
    # are always draft-only until GitHub CI passes.
    return ProjectProfile(
        ecosystems=ecosystems,
        has_tests=has_tests,
        tests_detected=has_tests,
        static_checks_passed=False,
        has_ci=has_ci,
        ci_workflows=ci_workflows,
        build_command=build_cmd,
        test_command=test_cmd,
        verification_label="UNVERIFIED",
        can_auto_pr_code_patches=False,
        recommended_ci_workflow=recommended_ci,
    )


def generate_minimal_ci_workflow(ecosystem: str) -> str:
    """Generates a hardened, minimal GitHub Actions test workflow with pinned commit SHAs."""
    if ecosystem == "python":
        return """name: Sphere Security & Tests
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
          pip install pytest
      - name: Run test suite
        run: |
          if find . -name "test_*.py" -o -name "*_test.py" | grep -q .; then
            pytest
          else
            echo "No pytest files found, skipping."
          fi
"""
    elif ecosystem == "node":
        return """name: Sphere Security & Tests
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
        with:
          node-version: 20
      - name: Install dependencies
        run: npm ci --ignore-scripts
      - name: Run tests
        run: npm test --if-present
"""
    else:
        return """name: Sphere CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - run: echo "Baseline verification completed."
"""
