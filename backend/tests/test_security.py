import os
import io
import stat
import zipfile
import pytest
from app.security import validate_github_url, extract_zip_safely, mask_pat


class TestGitHubUrlValidation:
    def test_valid_github_urls(self):
        assert validate_github_url("https://github.com/shrinithisk/Sphere") == "https://github.com/shrinithisk/Sphere"
        assert validate_github_url("https://github.com/shrinithisk/Sphere.git") == "https://github.com/shrinithisk/Sphere"
        assert validate_github_url("  https://github.com/torvalds/linux/  ") == "https://github.com/torvalds/linux"
        assert validate_github_url("https://github.com/org-name/repo_name.v2") == "https://github.com/org-name/repo_name.v2"

    def test_reject_insecure_http(self):
        with pytest.raises(ValueError, match="must use the 'https' protocol"):
            validate_github_url("http://github.com/owner/repo")

    def test_reject_non_github_host(self):
        with pytest.raises(ValueError, match="Only 'github.com' repositories are allowed"):
            validate_github_url("https://gitlab.com/owner/repo")
        with pytest.raises(ValueError, match="Only 'github.com' repositories are allowed"):
            validate_github_url("https://evil-github.com/owner/repo")

    def test_reject_internal_and_ssrf_ips(self):
        with pytest.raises(ValueError):
            validate_github_url("https://127.0.0.1/owner/repo")
        with pytest.raises(ValueError):
            validate_github_url("https://169.254.169.254/latest/meta-data")
        with pytest.raises(ValueError):
            validate_github_url("https://localhost/owner/repo")

    def test_reject_embedded_credentials(self):
        with pytest.raises(ValueError, match="must not contain embedded user credentials"):
            validate_github_url("https://user:token@github.com/owner/repo")

    def test_reject_path_traversal(self):
        with pytest.raises(ValueError):
            validate_github_url("https://github.com/owner/repo/../../etc/passwd")
        with pytest.raises(ValueError):
            validate_github_url("https://github.com/../evil")

    def test_reject_malformed_paths(self):
        with pytest.raises(ValueError):
            validate_github_url("https://github.com/single-segment")
        with pytest.raises(ValueError):
            validate_github_url("")
        with pytest.raises(ValueError):
            validate_github_url(None)


class TestSafeZipExtraction:
    def test_safe_zip_extracts_cleanly(self, tmp_path):
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("app/main.py", "print('hello world')")
            zf.writestr("README.md", "# Sample Repo")

        zip_file = tmp_path / "valid.zip"
        zip_file.write_bytes(zip_buf.getvalue())

        dest_dir = tmp_path / "extracted"
        result_dir = extract_zip_safely(str(zip_file), str(dest_dir))

        assert os.path.exists(os.path.join(result_dir, "app", "main.py"))
        assert os.path.exists(os.path.join(result_dir, "README.md"))

    def test_zip_slip_parent_traversal_blocked(self, tmp_path):
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            # Dangerous path traversal member
            zf.writestr("../../evil.sh", "malicious payload")

        zip_file = tmp_path / "slip.zip"
        zip_file.write_bytes(zip_buf.getvalue())

        dest_dir = tmp_path / "dest"
        with pytest.raises(ValueError, match="Zip Slip"):
            extract_zip_safely(str(zip_file), str(dest_dir))

    def test_zip_slip_embedded_traversal_blocked(self, tmp_path):
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("subfolder/../../escaped.txt", "payload")

        zip_file = tmp_path / "slip2.zip"
        zip_file.write_bytes(zip_buf.getvalue())

        dest_dir = tmp_path / "dest2"
        with pytest.raises(ValueError, match="Zip Slip"):
            extract_zip_safely(str(zip_file), str(dest_dir))

    def test_symlink_rejection(self, tmp_path):
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zinfo = zipfile.ZipInfo("symlink_entry")
            zinfo.create_system = 3  # Unix
            zinfo.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(zinfo, "/etc/passwd")

        zip_file = tmp_path / "symlink.zip"
        zip_file.write_bytes(zip_buf.getvalue())

        dest_dir = tmp_path / "dest3"
        with pytest.raises(ValueError, match="Symlinks are disallowed"):
            extract_zip_safely(str(zip_file), str(dest_dir))

    def test_file_count_limit(self, tmp_path):
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            for i in range(15):
                zf.writestr(f"file_{i}.txt", "data")

        zip_file = tmp_path / "many_files.zip"
        zip_file.write_bytes(zip_buf.getvalue())

        dest_dir = tmp_path / "dest4"
        with pytest.raises(ValueError, match="exceeding limit"):
            extract_zip_safely(str(zip_file), str(dest_dir), max_file_count=10)

    def test_uncompressed_size_limit(self, tmp_path):
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("large.txt", "A" * 2000)

        zip_file = tmp_path / "large.zip"
        zip_file.write_bytes(zip_buf.getvalue())

        dest_dir = tmp_path / "dest5"
        with pytest.raises(ValueError, match="uncompressed size exceeds limit"):
            extract_zip_safely(str(zip_file), str(dest_dir), max_uncompressed_bytes=1000)

    def test_single_file_size_limit(self, tmp_path):
        # Requirement A7: Single-file size limit test
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("large_single_file.bin", b"0" * 5000)

        zip_file = tmp_path / "single_file_large.zip"
        zip_file.write_bytes(zip_buf.getvalue())

        dest_dir = tmp_path / "dest6"
        with pytest.raises(ValueError, match="exceeds single file size limit"):
            extract_zip_safely(str(zip_file), str(dest_dir), max_single_file_bytes=2000)

    def test_compression_ratio_limit(self, tmp_path):
        # Requirement A7: Compression ratio limit test (Zip Bomb protection)
        # Highly repetitive data compresses extremely well
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.txt", "0" * 100000)

        zip_file = tmp_path / "ratio_bomb.zip"
        zip_file.write_bytes(zip_buf.getvalue())

        dest_dir = tmp_path / "dest7"
        # Set max_ratio to 5.0 and min_bytes_for_ratio to 500
        with pytest.raises(ValueError, match="Suspicious compression ratio"):
            extract_zip_safely(str(zip_file), str(dest_dir), max_ratio=5.0, min_bytes_for_ratio=500)


class TestPatMasking:
    def test_mask_pat(self):
        token = "ghp_1234567890abcdef1234567890abcdef"
        masked = mask_pat(token)
        assert masked.startswith("ghp_")
        assert masked.endswith("cdef")
        assert "1234567890" not in masked
        assert "*" in masked

    def test_mask_short_or_none(self):
        assert mask_pat("") == ""
        assert mask_pat(None) == ""
        assert mask_pat("short") == "********"
