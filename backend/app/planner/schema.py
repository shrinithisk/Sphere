import re
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from app.verifier.fingerprint import compute_finding_fingerprint


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Category(str, Enum):
    SECRET = "secret"
    DEPENDENCY = "dependency"
    CODE = "code"
    DOCKER = "docker"
    WORKFLOW = "workflow"
    HYGIENE = "hygiene"


class FixType(str, Enum):
    VERSION_BUMP = "version_bump"
    LINE_REPLACE = "line_replace"
    FILE_REPLACE = "file_replace"
    CONFIG_INSERT = "config_insert"
    MANUAL = "manual"


class FixClass(str, Enum):
    MANUAL_ONLY = "MANUAL_ONLY"      # Leaked secrets, auth/logic flaws. Never auto-fix.
    AUTO_VERIFIED = "AUTO_VERIFIED"  # Dependency bumps, Dockerfile, code patches.
    SAFE_AUTO = "SAFE_AUTO"          # Action SHA pinning, permissions, Dependabot/SECURITY.md.


class FixStatus(str, Enum):
    PENDING = "PENDING"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    REVERTED = "REVERTED"
    MANUAL = "MANUAL"


class UnifiedFinding(BaseModel):
    id: str
    tool: str                          # "gitleaks", "hadolint", "actionlint", "semgrep", "osv"
    rule_id: str
    file: str
    line: Optional[int] = None
    severity: Severity = Severity.MEDIUM
    category: Category = Category.CODE
    fix_type: FixType = FixType.MANUAL
    fix_class: FixClass = FixClass.MANUAL_ONLY
    suggested_fix: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)

    # Additional contextual fields
    cve: Optional[str] = None
    package: Optional[str] = None
    current_version: Optional[str] = None
    fixed_version: Optional[str] = None
    is_major_bump: bool = False
    draft_pr_only: bool = False
    commit: Optional[str] = None
    is_history_leak: bool = False
    fingerprint: Optional[str] = None

    original_block: Optional[str] = None
    patched_block: Optional[str] = None
    code_snippet: Optional[str] = None
    description: Optional[str] = None
    resolved_issue_ids: List[str] = Field(default_factory=list)
    resolved_issue_count: int = 1
    status: FixStatus = FixStatus.PENDING
    verification_log: Optional[str] = None
    fixed: bool = False
    pr_url: Optional[str] = None
    branch_name: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)

    def __init__(self, **data):
        super().__init__(**data)
        if not self.fingerprint:
            self.fingerprint = compute_finding_fingerprint(
                rule_id=self.rule_id,
                file_path=self.file,
                snippet=self.code_snippet,
                tool=self.tool,
                package=self.package,
                line_text=self.description,
            )


def normalize_severity(sev_str: Any) -> Severity:
    if not sev_str:
        return Severity.MEDIUM
    s = str(sev_str).strip().capitalize()
    if s in ("Critical", "Crit"):
        return Severity.CRITICAL
    if s in ("High", "Error"):
        return Severity.HIGH
    if s in ("Medium", "Warning", "Warn"):
        return Severity.MEDIUM
    if s in ("Low", "Info", "Style"):
        return Severity.LOW
    return Severity.MEDIUM


def clean_file_path(path: Any) -> str:
    if not path:
        return ""
    p = str(path).strip().replace("\\", "/")
    return re.sub(r"^(?:\.\./|\./|/)+", "", p)


def parse_semver_major(v_str: Any) -> int:
    if not v_str:
        return 0
    cleaned = re.sub(r"[^0-9\.]", "", str(v_str))
    parts = cleaned.split(".")
    return int(parts[0]) if parts and parts[0].isdigit() else 0


def normalize_gitleaks_finding(raw: Dict[str, Any]) -> UnifiedFinding:
    rule_id = raw.get("rule_id") or raw.get("id") or "gitleaks-secret"
    file_path = clean_file_path(raw.get("file"))
    line = int(raw.get("line")) if raw.get("line") is not None else None
    commit_sha = raw.get("commit")
    is_history = bool(raw.get("is_history_leak") or (commit_sha and not str(commit_sha).startswith("0000000")))

    finding_id = f"GITLEAKS-{rule_id}-{file_path}-{line or 'hist'}"

    if is_history and commit_sha:
        short_sha = str(commit_sha)[:7]
        rotation_instructions = (
            f"MANUAL ROTATION REQUIRED: Secret found in commit {short_sha}. "
            "Revoke and rotate this credential immediately at its provider. "
            "Removing it from code does NOT purge it from Git history; use `git-filter-repo` or BFG to permanently scrub commits."
        )
        desc = f"Potential leak of {rule_id} found in commit {short_sha}. Secret rotation required immediately."
    else:
        rotation_instructions = (
            "MANUAL ROTATION REQUIRED: This credential must be revoked and rotated immediately at its provider. "
            "Removing it from code does NOT purge it from Git history; use `git-filter-repo` or BFG to permanently scrub commits."
        )
        desc = raw.get("description", f"Exposed secret ({rule_id}) [REDACTED]")

    # Redact any accidental raw secrets in description
    desc_redacted = re.sub(r'Secret:.*', 'Secret: [REDACTED]', desc)

    return UnifiedFinding(
        id=finding_id,
        tool="gitleaks",
        rule_id=rule_id,
        file=file_path,
        line=line,
        severity=Severity.CRITICAL,
        category=Category.SECRET,
        fix_type=FixType.MANUAL,
        fix_class=FixClass.MANUAL_ONLY,
        suggested_fix=rotation_instructions,
        confidence=0.95,
        cve="N/A",
        description=desc_redacted,
        code_snippet=raw.get("code_snippet"),
        commit=str(commit_sha) if commit_sha else None,
        is_history_leak=is_history,
        resolved_issue_ids=[rule_id],
        resolved_issue_count=1,
    )


def normalize_hadolint_finding(raw: Dict[str, Any]) -> UnifiedFinding:
    rule_id = raw.get("id") or "DL0000"
    file_path = clean_file_path(raw.get("file", "Dockerfile"))
    line = int(raw.get("line")) if raw.get("line") is not None else 1
    finding_id = f"HADOLINT-{rule_id}-{file_path}-{line}"
    
    suggestion = raw.get("fix_suggestion") or f"Follow Hadolint guidance for {rule_id}: https://github.com/hadolint/hadolint/wiki/{rule_id}"
    
    return UnifiedFinding(
        id=finding_id,
        tool="hadolint",
        rule_id=rule_id,
        file=file_path,
        line=line,
        severity=normalize_severity(raw.get("severity", "Medium")),
        category=Category.DOCKER,
        fix_type=FixType.LINE_REPLACE,
        fix_class=FixClass.AUTO_VERIFIED,
        suggested_fix=suggestion,
        confidence=0.90,
        cve="N/A",
        description=raw.get("description", f"Dockerfile linter issue: {rule_id}"),
        code_snippet=raw.get("code_snippet"),
        original_block=raw.get("original_block"),
        patched_block=raw.get("patched_block"),
        resolved_issue_ids=[rule_id],
        resolved_issue_count=1,
    )


def normalize_actionlint_finding(raw: Dict[str, Any]) -> UnifiedFinding:
    rule_id = raw.get("id") or "actionlint-check"
    file_path = clean_file_path(raw.get("file", ""))
    line = int(raw.get("line")) if raw.get("line") is not None else 1
    finding_id = f"ACTIONLINT-{rule_id}-{file_path}-{line}"
    
    desc = raw.get("description", "")
    if any(k in desc.lower() for k in ("pin", "sha", "permission", "permissions")):
        fix_class = FixClass.SAFE_AUTO
        fix_type = FixType.CONFIG_INSERT
    else:
        fix_class = FixClass.AUTO_VERIFIED
        fix_type = FixType.LINE_REPLACE
        
    suggestion = raw.get("fix_suggestion") or f"Harden GitHub Actions workflow according to rule {rule_id}"
    
    return UnifiedFinding(
        id=finding_id,
        tool="actionlint",
        rule_id=rule_id,
        file=file_path,
        line=line,
        severity=normalize_severity(raw.get("severity", "Medium")),
        category=Category.WORKFLOW,
        fix_type=fix_type,
        fix_class=fix_class,
        suggested_fix=suggestion,
        confidence=0.88,
        cve="N/A",
        description=desc,
        code_snippet=raw.get("code_snippet"),
        original_block=raw.get("original_block"),
        patched_block=raw.get("patched_block"),
        resolved_issue_ids=[rule_id],
        resolved_issue_count=1,
    )


def normalize_semgrep_finding(raw: Dict[str, Any]) -> UnifiedFinding:
    rule_id = raw.get("id") or "semgrep-rule"
    file_path = clean_file_path(raw.get("file", ""))
    line = int(raw.get("line")) if raw.get("line") is not None else 1
    finding_id = f"SEMGREP-{rule_id}-{file_path}-{line}"
    
    desc = raw.get("description", "")
    rule_lower = rule_id.lower()
    
    # If semgrep caught an exposed secret or auth bypass logic, mark MANUAL_ONLY
    if any(k in rule_lower or k in desc.lower() for k in ("secret", "token", "password", "api_key", "credential", "private-key")):
        category = Category.SECRET
        fix_class = FixClass.MANUAL_ONLY
        fix_type = FixType.MANUAL
        suggestion = "MANUAL ROTATION REQUIRED: Revoke and rotate this exposed secret immediately. Scrub Git history."
        draft_only = False
    else:
        category = Category.CODE
        fix_class = FixClass.AUTO_VERIFIED
        fix_type = FixType.LINE_REPLACE
        suggestion = raw.get("fix_suggestion") or f"Remediate SAST flaw ({rule_id})"
        # Requirement B2: Semgrep/LLM code patches are always draft-only until GitHub CI passes
        draft_only = True

    return UnifiedFinding(
        id=finding_id,
        tool="semgrep",
        rule_id=rule_id,
        file=file_path,
        line=line,
        severity=normalize_severity(raw.get("severity", "Medium")),
        category=category,
        fix_type=fix_type,
        fix_class=fix_class,
        draft_pr_only=draft_only,
        suggested_fix=suggestion,
        confidence=0.85,
        cve=raw.get("cve", "N/A"),
        description=desc,
        code_snippet=raw.get("code_snippet"),
        original_block=raw.get("original_block"),
        patched_block=raw.get("patched_block"),
        resolved_issue_ids=[rule_id],
        resolved_issue_count=1,
    )


def normalize_osv_finding(raw: Dict[str, Any]) -> UnifiedFinding:
    pkg = raw.get("package") or "unknown-package"
    rule_id = raw.get("id") or f"OSV-{pkg}"
    file_path = clean_file_path(raw.get("file", "requirements.txt"))
    finding_id = f"OSV-{pkg}-{file_path}"
    
    fixed_ver = raw.get("fixed_version")
    curr_ver = raw.get("current_version")
    
    is_major = False
    if fixed_ver and fixed_ver != "Check advisory" and curr_ver:
        suggestion = f"Upgrade '{pkg}' from {curr_ver} to {fixed_ver} in {file_path}"
        fix_class = FixClass.AUTO_VERIFIED
        fix_type = FixType.VERSION_BUMP
        is_major = parse_semver_major(fixed_ver) > parse_semver_major(curr_ver)
    else:
        suggestion = f"Vulnerability advisory for '{pkg}'. No automatic safe version fix published; manual review required."
        fix_class = FixClass.MANUAL_ONLY
        fix_type = FixType.MANUAL

    cve_val = raw.get("cve", "N/A")
    cve_list = [c.strip() for c in cve_val.split(",") if c.strip()] if cve_val else [rule_id]

    return UnifiedFinding(
        id=finding_id,
        tool="osv",
        rule_id=rule_id,
        file=file_path,
        line=raw.get("line"),
        severity=normalize_severity(raw.get("severity", "High")),
        category=Category.DEPENDENCY,
        fix_type=fix_type,
        fix_class=fix_class,
        is_major_bump=is_major,
        suggested_fix=suggestion,
        confidence=0.92,
        cve=cve_val,
        package=pkg,
        current_version=curr_ver,
        fixed_version=fixed_ver,
        original_block=raw.get("original_block"),
        patched_block=raw.get("patched_block"),
        description=raw.get("description", f"Dependency vulnerability in {pkg}"),
        code_snippet=raw.get("code_snippet"),
        resolved_issue_ids=cve_list,
        resolved_issue_count=len(cve_list),
    )


def normalize_finding(raw: Dict[str, Any]) -> UnifiedFinding:
    """Normalizes any scanner raw dictionary into a UnifiedFinding instance."""
    tool = str(raw.get("tool", "")).lower()
    if tool == "gitleaks":
        return normalize_gitleaks_finding(raw)
    elif tool == "hadolint":
        return normalize_hadolint_finding(raw)
    elif tool == "actionlint":
        return normalize_actionlint_finding(raw)
    elif tool == "semgrep":
        return normalize_semgrep_finding(raw)
    elif tool == "osv":
        return normalize_osv_finding(raw)
    else:
        file_path = clean_file_path(raw.get("file", ""))
        desc = raw.get("description", "")
        if "secret" in desc.lower() or "token" in desc.lower():
            cat = Category.SECRET
            fclass = FixClass.MANUAL_ONLY
        elif "package" in desc.lower() or "cve" in desc.lower():
            cat = Category.DEPENDENCY
            fclass = FixClass.AUTO_VERIFIED
        elif "docker" in file_path.lower():
            cat = Category.DOCKER
            fclass = FixClass.AUTO_VERIFIED
        elif ".github/workflows" in file_path:
            cat = Category.WORKFLOW
            fclass = FixClass.SAFE_AUTO
        else:
            cat = Category.CODE
            fclass = FixClass.AUTO_VERIFIED
            
        return UnifiedFinding(
            id=raw.get("id", f"CUSTOM-{file_path}-{raw.get('line', 1)}"),
            tool=tool or "unknown",
            rule_id=raw.get("rule_id") or raw.get("id") or "generic-rule",
            file=file_path,
            line=raw.get("line"),
            severity=normalize_severity(raw.get("severity", "Medium")),
            category=cat,
            fix_type=FixType.LINE_REPLACE,
            fix_class=fclass,
            suggested_fix=raw.get("fix_suggestion", "Review code security"),
            description=desc,
            code_snippet=raw.get("code_snippet"),
            cve=raw.get("cve", "N/A"),
            package=raw.get("package"),
            current_version=raw.get("current_version"),
            fixed_version=raw.get("fixed_version"),
            original_block=raw.get("original_block"),
            patched_block=raw.get("patched_block"),
            resolved_issue_ids=[raw.get("id", "issue")],
            resolved_issue_count=1,
        )
