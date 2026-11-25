import os
import re
import stat
import zipfile
from urllib.parse import urlparse
from typing import Optional

# Maximum resource limits for archive extraction
MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024  # 250 MB
MAX_SINGLE_FILE_BYTES = 50 * 1024 * 1024    # 50 MB
MAX_FILE_COUNT = 5000
MAX_COMPRESSION_RATIO = 100.0


def validate_github_url(url: str) -> str:
    """
    Strictly validates and normalizes a GitHub repository URL to prevent SSRF,
    internal network probing, or malicious schemes.
    
    Allowed format: https://github.com/<owner>/<repo>[.git]
    """
    if not url or not isinstance(url, str):
        raise ValueError("Repository URL must be a non-empty string.")

    cleaned = url.strip()

    # Ensure no embedded user credentials (e.g. https://user:pass@github.com)
    if "@" in cleaned:
        raise ValueError("Repository URL must not contain embedded user credentials.")

    parsed = urlparse(cleaned)
    if parsed.scheme.lower() != "https":
        raise ValueError("Repository URL must use the 'https' protocol.")

    host = (parsed.hostname or "").lower()
    if host != "github.com":
        raise ValueError(f"Invalid host '{host}'. Only 'github.com' repositories are allowed.")

    # Port must either be None or 443
    if parsed.port and parsed.port != 443:
        raise ValueError("Invalid port. Standard HTTPS (443) only.")

    # Validate path strictly matches /owner/repo (allowing letters, digits, _, -, .)
    path = parsed.path.strip("/")
    pattern = r"^[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+$"
    if not re.match(pattern, path):
        raise ValueError(
            "Invalid GitHub repository path. Expected format: https://github.com/<owner>/<repo>"
        )

    parts = path.split("/")
    owner, repo = parts[0], parts[1]

    # Disallow relative traversal segment names
    if owner in (".", "..") or repo in (".", ".."):
        raise ValueError("Path traversal sequences are not allowed in repository URL.")

    clean_repo = repo[:-4] if repo.endswith(".git") else repo
    return f"https://github.com/{owner}/{clean_repo}"


def extract_zip_safely(
    zip_path: str,
    extract_to: str,
    max_uncompressed_bytes: int = MAX_UNCOMPRESSED_BYTES,
    max_single_file_bytes: int = MAX_SINGLE_FILE_BYTES,
    max_file_count: int = MAX_FILE_COUNT,
    max_ratio: float = MAX_COMPRESSION_RATIO,
    min_bytes_for_ratio: int = 1024,
) -> str:
    """
    Extracts a ZIP archive while protecting against Zip Slip path traversal,
    zip bombs, symlink attacks, and excessive resource consumption.
    
    Returns the effective root directory containing the project files.
    """
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"ZIP file not found at: {zip_path}")

    target_dir = os.path.abspath(extract_to)
    os.makedirs(target_dir, exist_ok=True)

    total_uncompressed = 0
    file_count = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        infolist = zf.infolist()
        if len(infolist) > max_file_count:
            raise ValueError(
                f"Archive contains {len(infolist)} files, exceeding limit of {max_file_count}."
            )

        # First pass: pre-inspection of metadata and limits
        for member in infolist:
            file_count += 1
            if file_count > max_file_count:
                raise ValueError(f"Exceeded maximum file count ({max_file_count}).")

            # Check individual and cumulative sizes
            if member.file_size > max_single_file_bytes:
                raise ValueError(
                    f"File '{member.filename}' exceeds single file size limit ({max_single_file_bytes} bytes)."
                )

            total_uncompressed += member.file_size
            if total_uncompressed > max_uncompressed_bytes:
                raise ValueError(
                    f"Archive uncompressed size exceeds limit of {max_uncompressed_bytes // (1024*1024)}MB."
                )

            # Check compression ratio for zip bomb defense
            if member.compress_size > 0 and member.file_size >= min_bytes_for_ratio:
                ratio = member.file_size / member.compress_size
                if ratio > max_ratio:
                    raise ValueError(
                        f"Suspicious compression ratio ({ratio:.1f}x) detected for '{member.filename}' (potential zip bomb)."
                    )

            # Path traversal / Zip Slip validation
            norm_name = os.path.normpath(member.filename)
            if norm_name.startswith("..") or norm_name.startswith("/") or "\\.." in norm_name:
                raise ValueError(f"Zip Slip attempt detected in member: '{member.filename}'")

            dest_path = os.path.abspath(os.path.join(target_dir, norm_name))
            if not (dest_path == target_dir or dest_path.startswith(target_dir + os.sep)):
                raise ValueError(f"Illegal path traversal detected: '{member.filename}'")

            # Check for symlink flags in external attributes
            is_symlink = (member.external_attr >> 16) & stat.S_IFLNK == stat.S_IFLNK
            if is_symlink:
                raise ValueError(f"Symlinks are disallowed in uploaded archives: '{member.filename}'")

        # Second pass: extract files safely
        for member in infolist:
            norm_name = os.path.normpath(member.filename)
            dest_path = os.path.abspath(os.path.join(target_dir, norm_name))

            if member.is_dir():
                os.makedirs(dest_path, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with zf.open(member) as source, open(dest_path, "wb") as target:
                    # Stream chunks rather than reading all at once
                    while True:
                        chunk = source.read(64 * 1024)
                        if not chunk:
                            break
                        target.write(chunk)

    # Determine effective root folder (in case archive wraps everything in a single directory)
    entries = os.listdir(target_dir)
    if len(entries) == 1:
        single_path = os.path.join(target_dir, entries[0])
        if os.path.isdir(single_path):
            return single_path

    return target_dir


def mask_pat(token: Optional[str]) -> str:
    """Masks a GitHub Personal Access Token for safe logging/display."""
    if not token or not isinstance(token, str):
        return ""
    token = token.strip()
    if len(token) <= 8:
        return "********"
    prefix = token[:4]
    suffix = token[-4:]
    return f"{prefix}{'*' * (len(token) - 8)}{suffix}"
