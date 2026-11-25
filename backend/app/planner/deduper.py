import re
from typing import List, Dict, Any, Tuple
from app.planner.schema import (
    UnifiedFinding,
    Severity,
    Category,
    FixClass,
    FixType,
    normalize_finding,
)
from app.verifier.dependency import select_version_fixing_all_advisories

SEVERITY_WEIGHTS = {
    Severity.CRITICAL.value: 25,
    Severity.HIGH.value: 15,
    Severity.MEDIUM.value: 5,
    Severity.LOW.value: 1,
}

SEVERITY_RANK = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
}

FIX_CLASS_STRICTNESS = {
    FixClass.MANUAL_ONLY.value: 0,   # Strictest: Manual only always wins
    FixClass.AUTO_VERIFIED.value: 1,
    FixClass.SAFE_AUTO.value: 2,
}


def parse_semver_tuple(v_str: Any) -> Tuple[int, int, int]:
    """Helper to parse a version string into a comparable (major, minor, patch) integer tuple."""
    if not v_str:
        return (0, 0, 0)
    cleaned = re.sub(r"[^0-9\.]", "", str(v_str))
    parts = []
    for part in cleaned.split("."):
        if part.isdigit():
            parts.append(int(part))
        else:
            break
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def calculate_health_score(findings: List[UnifiedFinding]) -> Dict[str, Any]:
    """Computes mathematical deduction score from unified findings."""
    severity_counts = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
    }
    for f in findings:
        sev = f.severity if isinstance(f.severity, str) else f.severity.value
        if sev in severity_counts:
            severity_counts[sev] += 1

    deduction = sum(SEVERITY_WEIGHTS[k] * severity_counts[k] for k in severity_counts)
    repo_score = max(0, 100 - deduction)

    return {
        "repo_score": repo_score,
        "deduction": deduction,
        "counts": severity_counts,
        "total": len(findings),
    }


def deduplicate_and_group(
    raw_or_unified_findings: List[Any],
) -> Tuple[List[UnifiedFinding], Dict[str, Any]]:
    """
    1. Normalizes all findings to UnifiedFinding schema.
    2. Groups multi-CVE package dependencies so 1 fix resolves N issues, setting is_major_bump.
    3. Merges overlapping findings sharing exact (file, line), where strictest fix_class wins (MANUAL_ONLY > AUTO_VERIFIED).
    4. Recalculates repo health score and returns deduplicated list and score breakdown.
    """
    if not raw_or_unified_findings:
        return [], calculate_health_score([])

    # Ensure all items are UnifiedFinding instances
    normalized: List[UnifiedFinding] = []
    for item in raw_or_unified_findings:
        if isinstance(item, UnifiedFinding):
            normalized.append(item)
        elif isinstance(item, dict):
            normalized.append(normalize_finding(item))

    # --- Step A: Group Dependency Findings by (file, package) ---
    dep_groups: Dict[Tuple[str, str], List[UnifiedFinding]] = {}
    other_findings: List[UnifiedFinding] = []

    for f in normalized:
        if f.category == Category.DEPENDENCY.value or f.category == Category.DEPENDENCY:
            pkg_key = (f.file.lower(), (f.package or f.rule_id).lower())
            if pkg_key not in dep_groups:
                dep_groups[pkg_key] = []
            dep_groups[pkg_key].append(f)
        else:
            other_findings.append(f)

    consolidated_deps: List[UnifiedFinding] = []
    for (fpath, pkg_name), group in dep_groups.items():
        if len(group) == 1:
            consolidated_deps.append(group[0])
            continue

        # Find version that fixes ALL advisories in the group (Requirement B7)
        max_fix = None
        highest_sev = Severity.LOW
        all_cves: List[str] = []
        all_ids: List[str] = []
        descriptions: List[str] = []

        curr_ver = group[0].current_version
        orig_block = group[0].original_block

        for item in group:
            all_ids.append(item.id)
            if item.cve and item.cve != "N/A":
                for c in item.cve.split(","):
                    c_clean = c.strip()
                    if c_clean and c_clean not in all_cves:
                        all_cves.append(c_clean)

            # Keep highest severity
            item_sev_val = item.severity if isinstance(item.severity, str) else item.severity.value
            if SEVERITY_RANK.get(item_sev_val, 4) < SEVERITY_RANK.get(highest_sev.value, 4):
                highest_sev = Severity(item_sev_val)

            if item.description:
                descriptions.append(item.description)

        # Requirement B7: Choose smallest version that fixes ALL advisories in group
        fixed_version_specs = [
            item.fixed_version for item in group if item.fixed_version and item.fixed_version != "Check advisory"
        ]
        max_fix = select_version_fixing_all_advisories(curr_ver, fixed_version_specs)

        real_pkg = group[0].package or pkg_name
        issue_count = len(group)
        cve_summary = ", ".join(all_cves[:4]) if all_cves else f"{issue_count} security advisories"
        if len(all_cves) > 4:
            cve_summary += f" (+{len(all_cves) - 4} more)"

        # Requirement A4: Check if grouped dependency update is a major bump
        is_major = False
        if max_fix and curr_ver:
            is_major = parse_semver_tuple(max_fix)[0] > parse_semver_tuple(curr_ver)[0]

        if max_fix:
            suggested_fix = f"Upgrade '{real_pkg}' from {curr_ver} to {max_fix} (1 fix resolves {issue_count} issues: {cve_summary})"
            patched_block = f"{real_pkg}=={max_fix}" if "requirements" in fpath else f'"{real_pkg}": "{max_fix}"'
            fclass = FixClass.AUTO_VERIFIED
            ftype = FixType.VERSION_BUMP
        else:
            suggested_fix = f"Review advisories for '{real_pkg}' (1 fix resolves {issue_count} issues: {cve_summary}). No auto-patch published."
            patched_block = None
            fclass = FixClass.MANUAL_ONLY
            ftype = FixType.MANUAL

        combined_desc = (
            f"**1 fix resolves {issue_count} issues** in `{real_pkg}` ({cve_summary}).\n\n"
            + "\n".join(f"* {d}" for d in descriptions[:5])
        )

        grouped_finding = UnifiedFinding(
            id=f"OSV-{real_pkg}-{fpath}-grouped",
            tool="osv",
            rule_id=f"GROUPED-{real_pkg}",
            file=group[0].file,
            line=group[0].line,
            severity=highest_sev,
            category=Category.DEPENDENCY,
            fix_type=ftype,
            fix_class=fclass,
            is_major_bump=is_major,
            suggested_fix=suggested_fix,
            confidence=0.95,
            cve=", ".join(all_cves) if all_cves else "Grouped Advisories",
            package=real_pkg,
            current_version=curr_ver,
            fixed_version=max_fix or "Check advisory",
            original_block=orig_block,
            patched_block=patched_block,
            description=combined_desc,
            resolved_issue_ids=all_ids,
            resolved_issue_count=issue_count,
        )
        consolidated_deps.append(grouped_finding)

    # --- Step B: Deduplicate Overlapping (file, line) Findings Across Linters ---
    combined = consolidated_deps + other_findings
    seen_locations: Dict[Tuple[str, Optional[int]], UnifiedFinding] = {}
    deduped: List[UnifiedFinding] = []

    for f in combined:
        loc_key = (f.file.strip().lower(), f.line)

        # Non-line findings (or dependencies) don't get merged by line alone
        if f.line is None or f.category in (Category.DEPENDENCY.value, Category.DEPENDENCY):
            deduped.append(f)
            continue

        if loc_key not in seen_locations:
            seen_locations[loc_key] = f
            deduped.append(f)
        else:
            existing = seen_locations[loc_key]
            # If same tool and rule, skip duplicate
            if existing.tool == f.tool and existing.rule_id == f.rule_id:
                continue

            # Requirement A1: Strictest fix_class ALWAYS wins (MANUAL_ONLY > AUTO_VERIFIED > SAFE_AUTO)
            f_fc = f.fix_class if isinstance(f.fix_class, str) else f.fix_class.value
            exist_fc = existing.fix_class if isinstance(existing.fix_class, str) else existing.fix_class.value

            if FIX_CLASS_STRICTNESS.get(f_fc, 1) < FIX_CLASS_STRICTNESS.get(exist_fc, 1):
                existing.fix_class = FixClass(f_fc)
                existing.category = f.category
                existing.suggested_fix = f.suggested_fix

            # Severity: Highest severity wins
            f_sev_val = f.severity if isinstance(f.severity, str) else f.severity.value
            exist_sev_val = existing.severity if isinstance(existing.severity, str) else existing.severity.value

            if SEVERITY_RANK.get(f_sev_val, 4) < SEVERITY_RANK.get(exist_sev_val, 4):
                existing.severity = Severity(f_sev_val)

            existing.description = f"{existing.description} | Also flagged by {f.tool} ({f.rule_id})"
            existing.resolved_issue_ids.append(f.id)
            existing.resolved_issue_count += 1

    # --- Step C: Final Score Calculation ---
    score_summary = calculate_health_score(deduped)
    return deduped, score_summary
