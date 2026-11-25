import os
import json
import pytest
from unittest.mock import patch

from app.verifier.sandbox import RepoSandbox
from app.verifier.syntax_checker import reconcile_npm_lockfile
from app.planner.schema import UnifiedFinding, Category, FixClass, FixType


def test_dependency_fix_updates_both_package_and_lockfile(tmp_path):
    """
    Requirement 5: Show how dependency fixes update lockfiles
    (--package-lock-only --ignore-scripts, clean config), and verify that
    package.json and package-lock.json both change and are committed together.
    """
    src_dir = tmp_path / "node_repo"
    src_dir.mkdir()

    # Initial package.json
    pkg_json_content = {
        "name": "sphere-demo-node",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.15"
        }
    }
    (src_dir / "package.json").write_text(json.dumps(pkg_json_content, indent=2))

    # Initial package-lock.json
    lock_json_content = {
        "name": "sphere-demo-node",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "sphere-demo-node",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.15"
                }
            },
            "node_modules/lodash": {
                "version": "4.17.15"
            }
        }
    }
    (src_dir / "package-lock.json").write_text(json.dumps(lock_json_content, indent=2))

    finding = UnifiedFinding(
        id="OSV-lodash-1",
        tool="osv",
        rule_id="CVE-2020-8203",
        file="package.json",
        line=4,
        category=Category.DEPENDENCY,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        package="lodash",
        current_version="4.17.15",
        fixed_version="4.17.21",
        suggested_fix="Bump lodash to 4.17.21",
        original_block='"lodash": "4.17.15"',
        patched_block='"lodash": "4.17.21"',
    )

    with RepoSandbox(str(src_dir)) as sandbox:
        # Mock safe_subprocess_run for npm execution so test runs deterministically
        def mock_npm_run(cmd, cwd=None, timeout=30):
            # Verify required security flags are passed
            assert "install" in cmd
            assert "--package-lock-only" in cmd
            assert "--ignore-scripts" in cmd
            assert "--no-audit" in cmd
            assert "--no-fund" in cmd
            # Simulate lockfile update by npm
            lock_path = os.path.join(cwd, "package-lock.json")
            with open(lock_path, "r") as fp:
                data = json.load(fp)
            data["packages"][""]["dependencies"]["lodash"] = "4.17.21"
            data["packages"]["node_modules/lodash"]["version"] = "4.17.21"
            with open(lock_path, "w") as fp:
                json.dump(data, fp, indent=2)
            return 0, "updated 1 package in 0.4s", ""

        with patch("app.verifier.syntax_checker.safe_subprocess_run", side_effect=mock_npm_run):
            applied_ok, err = sandbox.apply_patch(finding)
            assert applied_ok is True
            assert err is None

            commit_sha = sandbox.commit_fix(finding)
            assert commit_sha is not None

            # 1. Assert package.json has 4.17.21
            sandbox_pkg = os.path.join(sandbox.sandbox_path, "package.json")
            pkg_data = json.loads(open(sandbox_pkg).read())
            assert pkg_data["dependencies"]["lodash"] == "4.17.21"

            # 2. Assert package-lock.json has 4.17.21
            sandbox_lock = os.path.join(sandbox.sandbox_path, "package-lock.json")
            lock_data = json.loads(open(sandbox_lock).read())
            assert lock_data["packages"]["node_modules/lodash"]["version"] == "4.17.21"

            # 3. Assert git diff includes changes to BOTH package.json and package-lock.json
            diff = sandbox.get_diff(against_baseline=True)
            assert "diff --git a/package.json b/package.json" in diff
            assert '"lodash": "4.17.21"' in diff
            assert "diff --git a/package-lock.json b/package-lock.json" in diff
            assert '"version": "4.17.21"' in diff
