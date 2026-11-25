import re
import hashlib
from typing import Optional


def compute_finding_fingerprint(
    rule_id: str,
    file_path: str,
    snippet: Optional[str] = None,
    tool: Optional[str] = None,
    package: Optional[str] = None,
    line_text: Optional[str] = None,
) -> str:
    """
    Computes a stable, line-number-independent fingerprint for a finding.
    
    Requirement 4:
    - For OSV (or tools with no snippet): package + advisory id + manifest file
    - For linters with no snippet: normalized line text
    - Normalization: collapse all whitespace (\\s+ -> ' '), trim, lowercase
    """
    norm_file = re.sub(r"^(?:\.\./|\./|/)+", "", str(file_path).strip().replace("\\", "/")).lower()
    norm_rule = str(rule_id).strip().lower()
    norm_tool = str(tool or "").strip().lower()
    norm_pkg = str(package or "").strip().lower()

    # Whitespace normalization helper
    def normalize_ws(s: Optional[str]) -> str:
        if not s:
            return ""
        return re.sub(r"\s+", " ", str(s)).strip().lower()

    clean_snippet = normalize_ws(snippet)
    clean_line_text = normalize_ws(line_text)

    # 1. OSV / Dependency findings without snippet: package + advisory_id + manifest file
    if norm_tool == "osv" or (norm_pkg and not clean_snippet and not clean_line_text):
        raw_sig = f"osv:{norm_pkg}:{norm_rule}:{norm_file}"
        return hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()

    # 2. If snippet or line text exists, use normalized text
    effective_text = clean_snippet if clean_snippet else clean_line_text
    if effective_text:
        raw_sig = f"{norm_rule}:{norm_file}:{effective_text}"
    else:
        # 3. Linter fallback when no line text or snippet is available
        raw_sig = f"{norm_rule}:{norm_file}"

    return hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()
