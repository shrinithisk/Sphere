import os
import json
import pytest
from unittest.mock import patch

from app.verifier.sandbox import RepoSandbox
from app.verifier.syntax_checker import check_requirements_syntax
from app.planner.schema import UnifiedFinding, Category, FixType, FixClass


def test_transitive_dependency_applies_npm_override(tmp_path):
    """
    Requirement 5: If the vulnerable package is transitive,
    Sphere injects an 'overrides' block into package.json so that
    npm --package-lock-only can resolve and lock it cleanly.
    """
    repo_dir = tmp_path / "node_repo"
    repo_dir.mkdir()

    # package.json only contains direct parent 'express'
    pkg_content = {
        "name": "transitive-test",
        "version": "1.0.0",
        "dependencies": {
            "express": "4.17.1"
        }
    }
    (repo_dir / "package.json").write_text(json.dumps(pkg_content, indent=2))
    (repo_dir / "package-lock.json").write_text(json.dumps({"name": "transitive-test", "lockfileVersion": 3}, indent=2))

    # Transitive vulnerable finding for 'qs' (a subdependency of express)
    finding = UnifiedFinding(
        id="OSV-qs-1",
        tool="osv",
        rule_id="GHSA-hrpp-h998-j3pp",
        file="package.json",
        line=1,
        category=Category.DEPENDENCY,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        package="qs",
        current_version="6.7.0",
        fixed_version="6.7.3",
        suggested_fix="Bump qs to 6.7.3",
    )

    with RepoSandbox(str(repo_dir)) as sandbox:
        with patch("app.verifier.syntax_checker.safe_subprocess_run", return_value=(0, "reconciled lockfile", "")):
            applied_ok, err = sandbox.apply_patch(finding)
            assert applied_ok is True
            assert err is None

            # Read back package.json
            with open(os.path.join(sandbox.sandbox_path, "package.json"), "r") as fp:
                updated_pkg = json.load(fp)

            # Assert overrides block was created and contains qs: 6.7.3
            assert "overrides" in updated_pkg
            assert updated_pkg["overrides"]["qs"] == "6.7.3"
            # Assert express direct dependency is untouched
            assert updated_pkg["dependencies"]["express"] == "4.17.1"


def test_requirements_txt_syntax_validation(tmp_path):
    """
    Requirement 5: Static syntax checker for requirements.txt.
    Accepts standard requirement lines and rejects shell characters.
    """
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("""
# Core dependencies
flask==2.3.2
requests>=2.28.0
urllib3~=1.26.15
pytest
""")
    valid, err = check_requirements_syntax(str(req_file))
    assert valid is True
    assert err is None

    # Test rejecting shell injection characters
    bad_req = tmp_path / "bad_requirements.txt"
    bad_req.write_text("flask==2.3.2; rm -rf /\n")
    valid, err = check_requirements_syntax(str(bad_req))
    assert valid is False
    assert "forbidden shell characters" in err


def test_transitive_dependency_in_requirements_txt(tmp_path):
    """
    Requirement 5: When a transitive Python dependency is fixed,
    an explicit pinned requirement entry is added.
    """
    repo_dir = tmp_path / "python_repo"
    repo_dir.mkdir()

    req_file = repo_dir / "requirements.txt"
    req_file.write_text("requests==2.25.1\n")

    # Transitive subdependency 'certifi'
    finding = UnifiedFinding(
        id="OSV-certifi-1",
        tool="osv",
        rule_id="CVE-2022-23491",
        file="requirements.txt",
        line=1,
        category=Category.DEPENDENCY,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        package="certifi",
        current_version="2020.12.5",
        fixed_version="2022.12.7",
        suggested_fix="Pin certifi to 2022.12.7",
    )

    with RepoSandbox(str(repo_dir)) as sandbox:
        applied_ok, err = sandbox.apply_patch(finding)
        assert applied_ok is True
        assert err is None

        with open(os.path.join(sandbox.sandbox_path, "requirements.txt"), "r") as fp:
            content = fp.read()

        assert "certifi==2022.12.7" in content
        assert "requests==2.25.1" in content
