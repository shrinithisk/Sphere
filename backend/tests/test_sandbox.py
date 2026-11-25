import os
import hashlib
import pytest
from app.verifier.sandbox import RepoSandbox, resolve_sandbox_file
from app.planner.schema import UnifiedFinding, Category, FixClass, FixType


def compute_directory_file_hashes(dir_path: str) -> dict:
    """Computes a mapping of relative file paths to SHA256 hex digests."""
    hashes = {}
    for root, dirs, files in os.walk(dir_path):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, dir_path)
            with open(full, "rb") as fp:
                hashes[rel] = hashlib.sha256(fp.read()).hexdigest()
    return hashes


def test_sandbox_isolation_and_patching(tmp_path):
    # Setup mock source repository
    src_dir = tmp_path / "source_repo"
    src_dir.mkdir()
    app_file = src_dir / "app.py"
    app_file.write_text("import os\n\ndef run():\n    return 'old_value'\n")

    finding = UnifiedFinding(
        id="TEST-1",
        tool="semgrep",
        rule_id="test-rule",
        file="app.py",
        line=4,
        category=Category.CODE,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Update return value",
        original_block="return 'old_value'",
        patched_block="return 'secured_value'",
    )

    with RepoSandbox(str(src_dir)) as sandbox:
        assert sandbox.sandbox_path is not None
        assert os.path.exists(sandbox.sandbox_path)
        assert sandbox.sandbox_path != str(src_dir)

        # 1. Apply patch in sandbox
        applied, err = sandbox.apply_patch(finding)
        assert applied is True
        assert err is None

        # Verify content changed in sandbox
        sandbox_app = os.path.join(sandbox.sandbox_path, "app.py")
        with open(sandbox_app, "r") as f:
            sandbox_content = f.read()
        assert "secured_value" in sandbox_content

        # Verify ORIGINAL source repo was NEVER touched
        with open(str(app_file), "r") as f:
            orig_content = f.read()
        assert "old_value" in orig_content
        assert "secured_value" not in orig_content

        # 2. Revert patch
        sandbox.revert_patch(finding)
        with open(sandbox_app, "r") as f:
            reverted_content = f.read()
        assert "old_value" in reverted_content

        # 3. Apply again and commit
        sandbox.apply_patch(finding)
        sha = sandbox.commit_fix(finding)
        assert isinstance(sha, str)
        assert len(sha) == 40


def test_path_traversal_blocked(tmp_path):
    # Requirement B6: Resolve finding.file and verify it stays inside the sandbox root
    src_dir = tmp_path / "source_repo"
    src_dir.mkdir()
    (src_dir / "main.py").write_text("print('test')")

    with RepoSandbox(str(src_dir)) as sandbox:
        # Direct helper check
        with pytest.raises(ValueError, match="traversal"):
            resolve_sandbox_file(sandbox.sandbox_path, "../../etc/passwd")

        with pytest.raises(ValueError, match="traversal"):
            resolve_sandbox_file(sandbox.sandbox_path, "../../../shadow")

        # apply_patch check
        malicious_finding = UnifiedFinding(
            id="TRAVERSAL-1",
            tool="semgrep",
            rule_id="traversal",
            file="../../etc/passwd",
            line=1,
            category=Category.CODE,
            fix_type=FixType.LINE_REPLACE,
            fix_class=FixClass.AUTO_VERIFIED,
            suggested_fix="Escape sandbox",
            original_block="root:x",
            patched_block="root:hacked",
        )
        applied, err = sandbox.apply_patch(malicious_finding)
        assert applied is False
        assert "blocked" in err.lower() or "traversal" in err.lower()


def test_symlinks_never_followed(tmp_path):
    # Requirement B5: Never follow symlinks (skip or recreate without dereferencing)
    outside_file = tmp_path / "outside_secret.txt"
    outside_file.write_text("SUPER_SECRET_HOST_KEY")

    src_dir = tmp_path / "symlink_repo"
    src_dir.mkdir()
    (src_dir / "regular.txt").write_text("regular data")

    # Create symlink pointing outside
    symlink_path = src_dir / "leak_link.txt"
    try:
        os.symlink(str(outside_file), str(symlink_path))
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this filesystem")

    with RepoSandbox(str(src_dir)) as sandbox:
        sandbox_link = os.path.join(sandbox.sandbox_path, "leak_link.txt")
        # Symlink must NOT be copied or dereferenced
        assert not os.path.exists(sandbox_link)
        assert os.path.exists(os.path.join(sandbox.sandbox_path, "regular.txt"))


def test_git_init_hooks_disabled_and_no_fsmonitor(tmp_path):
    # Requirement B5: fresh git init with core.hooksPath disabled and core.fsmonitor=false
    src_dir = tmp_path / "hooks_repo"
    src_dir.mkdir()
    (src_dir / "README.md").write_text("# Test Repo")

    with RepoSandbox(str(src_dir)) as sandbox:
        hooks_path = sandbox.repo.git.config("core.hooksPath")
        fsmonitor = sandbox.repo.git.config("core.fsmonitor")
        assert hooks_path == "/dev/null"
        assert fsmonitor == "false"


def test_source_directory_unchanged_hash_comparison(tmp_path):
    # Requirement B9: Original source directory is unchanged (compare hashes)
    src_dir = tmp_path / "hash_repo"
    src_dir.mkdir()
    (src_dir / "file1.py").write_text("def a(): return 1\n")
    (src_dir / "file2.json").write_text('{"name": "test"}\n')
    sub = src_dir / "sub"
    sub.mkdir()
    (sub / "nested.txt").write_text("nested content\n")

    # Compute baseline hashes of all files in original directory
    before_hashes = compute_directory_file_hashes(str(src_dir))

    finding = UnifiedFinding(
        id="HASH-1",
        tool="semgrep",
        rule_id="r1",
        file="file1.py",
        line=1,
        category=Category.CODE,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="fix a",
        original_block="def a(): return 1",
        patched_block="def a(): return 999",
    )

    with RepoSandbox(str(src_dir)) as sandbox:
        sandbox.apply_patch(finding)
        sandbox.commit_fix(finding)
        sandbox.revert_patch(finding)

    # Compute hashes after all sandbox actions
    after_hashes = compute_directory_file_hashes(str(src_dir))
    assert before_hashes == after_hashes


def test_breaking_patch_revert_restores_exact_file_content(tmp_path):
    # Requirement B9: breaking patch -> revert restores the exact file content
    src_dir = tmp_path / "revert_repo"
    src_dir.mkdir()
    target_file = src_dir / "service.py"
    initial_content = "def calculate_tax(rate):\n    # Core business logic\n    return 100 * rate\n"
    target_file.write_text(initial_content)

    breaking_finding = UnifiedFinding(
        id="BREAK-1",
        tool="semgrep",
        rule_id="syntax-breaker",
        file="service.py",
        line=2,
        category=Category.CODE,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Inject syntax error",
        original_block="return 100 * rate",
        patched_block="return 100 * (def syntax_error:",  # Corrupt syntax
    )

    with RepoSandbox(str(src_dir)) as sandbox:
        sandbox_file = os.path.join(sandbox.sandbox_path, "service.py")
        applied, _ = sandbox.apply_patch(breaking_finding)
        assert applied is True
        assert "syntax_error" in open(sandbox_file).read()

        # Revert
        sandbox.revert_patch(breaking_finding)
        reverted_content = open(sandbox_file).read()

        # Assert byte-for-byte equality with initial state
        assert reverted_content == initial_content


def test_patch_conflict_handling_does_not_corrupt_file(tmp_path):
    # Requirement B9: Patch conflict handling
    src_dir = tmp_path / "conflict_repo"
    src_dir.mkdir()
    target_file = src_dir / "config.py"
    initial_content = "PORT = 8080\nDEBUG = True\n"
    target_file.write_text(initial_content)

    conflict_finding = UnifiedFinding(
        id="CONFLICT-1",
        tool="semgrep",
        rule_id="conflict-rule",
        file="config.py",
        line=1,
        category=Category.CODE,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix="Fix non-existent block",
        original_block="NON_EXISTENT_PORT = 9999",  # Does not match file content
        patched_block="PORT = 443",
    )

    with RepoSandbox(str(src_dir)) as sandbox:
        sandbox_file = os.path.join(sandbox.sandbox_path, "config.py")
        applied, err = sandbox.apply_patch(conflict_finding)
        assert applied is False
        assert "could not locate matching target code" in err.lower()
        # Verify file content is completely intact and uncorrupted
        assert open(sandbox_file).read() == initial_content


def test_sandbox_temp_dir_cleaned_up_in_finally(tmp_path):
    # Requirement B5: always clean up the temp dir in finally
    src_dir = tmp_path / "cleanup_repo"
    src_dir.mkdir()
    (src_dir / "test.txt").write_text("data")

    created_sandbox_path = None
    try:
        with RepoSandbox(str(src_dir)) as sandbox:
            created_sandbox_path = sandbox.sandbox_path
            assert os.path.exists(created_sandbox_path)
            # Simulate exception during execution
            raise RuntimeError("Unexpected pipeline crash")
    except RuntimeError:
        pass

    assert created_sandbox_path is not None
    # Sandbox directory must be cleaned up / removed from disk
    assert not os.path.exists(created_sandbox_path)
