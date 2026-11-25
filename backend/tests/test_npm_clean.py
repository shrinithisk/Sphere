import os
import pytest
from app.verifier.syntax_checker import clean_sandbox_package_manager_configs, reconcile_npm_lockfile
from app.verifier.sandbox import RepoSandbox


def test_clean_sandbox_package_manager_configs(tmp_path):
    # Requirement 3: delete .npmrc / .yarnrc* from the sandbox
    npmrc = tmp_path / ".npmrc"
    npmrc.write_text("//registry.npmjs.org/:_authToken=SUPER_SECRET_NPM_TOKEN\n")
    yarnrc = tmp_path / ".yarnrc.yml"
    yarnrc.write_text("npmAuthToken: SECRET_YARN_TOKEN\n")
    yarnrc_old = tmp_path / ".yarnrc"
    yarnrc_old.write_text("registry https://registry.yarnpkg.com\n")
    other_file = tmp_path / "package.json"
    other_file.write_text('{"name": "test"}\n')

    assert os.path.exists(str(npmrc))
    assert os.path.exists(str(yarnrc))
    assert os.path.exists(str(yarnrc_old))

    # Execute cleaner
    clean_sandbox_package_manager_configs(str(tmp_path))

    # .npmrc and .yarnrc* must be deleted
    assert not os.path.exists(str(npmrc))
    assert not os.path.exists(str(yarnrc))
    assert not os.path.exists(str(yarnrc_old))
    # Non-npmrc files remain intact
    assert os.path.exists(str(other_file))


def test_sandbox_automatically_removes_npmrc_on_entry(tmp_path):
    # Requirement 3: Sandbox automatically deletes .npmrc / .yarnrc* on initialization
    src_dir = tmp_path / "src_with_npmrc"
    src_dir.mkdir()
    (src_dir / ".npmrc").write_text("secret_token=12345\n")
    (src_dir / "index.js").write_text("console.log('hi');\n")

    with RepoSandbox(str(src_dir)) as sandbox:
        sandbox_npmrc = os.path.join(sandbox.sandbox_path, ".npmrc")
        assert not os.path.exists(sandbox_npmrc)
        assert os.path.exists(os.path.join(sandbox.sandbox_path, "index.js"))
