import re
from typing import Optional, List, Tuple, Dict, Any, Union


def parse_version_tuple(v_str: Any) -> Tuple[int, int, int]:
    """Extracts (major, minor, patch) integer tuple from a version string."""
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


def classify_version_bump(current_version: str, target_version: str) -> Dict[str, Any]:
    """
    Classifies a version bump as 'patch', 'minor', or 'major'.
    Major version bumps are flagged so they can be partitioned into separate draft PRs.
    """
    curr = parse_version_tuple(current_version)
    target = parse_version_tuple(target_version)

    curr_maj, curr_min, curr_pat = curr
    targ_maj, targ_min, targ_pat = target

    if targ_maj > curr_maj:
        return {
            "bump_type": "major",
            "is_major": True,
            "risk_level": "high",
            "description": f"Major version bump: {current_version} -> {target_version} (May introduce breaking API changes)",
        }
    elif targ_min > curr_min:
        return {
            "bump_type": "minor",
            "is_major": False,
            "risk_level": "medium",
            "description": f"Minor version bump: {current_version} -> {target_version}",
        }
    else:
        return {
            "bump_type": "patch",
            "is_major": False,
            "risk_level": "low",
            "description": f"Patch version bump: {current_version} -> {target_version}",
        }


def select_minimal_fixed_version(
    current_version: str,
    available_fixed_versions: List[str],
) -> Optional[str]:
    """
    Selects the minimal safe fixed version that resolves the vulnerability,
    rather than blindly upgrading to the latest release.
    """
    if not available_fixed_versions:
        return None

    curr_tuple = parse_version_tuple(current_version)

    eligible = []
    for v in available_fixed_versions:
        if not v or v == "Check advisory":
            continue
        v_tuple = parse_version_tuple(v)
        if v_tuple > curr_tuple:
            eligible.append((v_tuple, v))

    if not eligible:
        return None

    # Smallest version strictly greater than current
    eligible.sort(key=lambda x: x[0])
    return eligible[0][1]


def select_version_fixing_all_advisories(
    current_version: str,
    advisories_fixed_versions: List[Union[str, List[str]]],
) -> Optional[str]:
    """
    Requirement B7: Choose the smallest version that fixes ALL advisories in the group,
    aware of per-branch fixed versions.
    
    Example:
      fixes at 2.1.0 and 2.3.0 -> 2.3.0
      fixes at ["1.2.5", "2.1.0"] and ["1.2.8"] -> 1.2.8 (same branch, fixes both)
    """
    if not advisories_fixed_versions:
        return None

    curr_tuple = parse_version_tuple(current_version)
    curr_major = curr_tuple[0]

    # Normalize input: each advisory has a list of candidate fixed versions
    normalized_advisories: List[List[Tuple[Tuple[int, int, int], str]]] = []
    all_candidate_versions: List[Tuple[Tuple[int, int, int], str]] = []

    for item in advisories_fixed_versions:
        candidates = []
        if isinstance(item, (list, tuple)):
            v_list = item
        elif isinstance(item, str):
            v_list = [v.strip() for v in item.split(",") if v.strip()]
        else:
            continue

        for v in v_list:
            if not v or v == "Check advisory":
                continue
            v_t = parse_version_tuple(v)
            if v_t > curr_tuple:
                candidates.append((v_t, v))
                all_candidate_versions.append((v_t, v))

        if candidates:
            # Sort candidates ascending
            candidates.sort(key=lambda x: x[0])
            normalized_advisories.append(candidates)

    if not normalized_advisories:
        return None

    # Deduplicate all candidates and sort ascending
    unique_candidates = sorted(list({v_str: v_t for v_t, v_str in all_candidate_versions}.items()), key=lambda x: x[1])

    def candidate_fixes_advisory(cand_tuple: Tuple[int, int, int], adv_candidates: List[Tuple[Tuple[int, int, int], str]]) -> bool:
        # A candidate version C fixes an advisory if there exists a fixed version F in adv_candidates
        # such that C >= F and C is in the same major branch as F (or higher major branch)
        for f_tuple, _ in adv_candidates:
            if cand_tuple >= f_tuple:
                # If candidate is >= fixed version in the same major release or later, advisory is resolved
                if cand_tuple[0] == f_tuple[0] or cand_tuple[0] > f_tuple[0]:
                    return True
        return False

    # First pass: try to find the smallest candidate in the SAME major branch as current_version
    same_branch_candidates = [
        (v_str, v_t) for v_str, v_t in unique_candidates if v_t[0] == curr_major
    ]
    for v_str, v_t in same_branch_candidates:
        if all(candidate_fixes_advisory(v_t, adv) for adv in normalized_advisories):
            return v_str

    # Second pass: if no same-branch candidate fixes all, pick the minimal candidate across all branches
    for v_str, v_t in unique_candidates:
        if all(candidate_fixes_advisory(v_t, adv) for adv in normalized_advisories):
            return v_str

    # Fallback: if no candidate universally satisfies (e.g. disjoint version bounds), pick the highest minimum
    highest_tuple = (0, 0, 0)
    highest_str = None
    for adv in normalized_advisories:
        if adv:
            v_t, v_str = adv[-1]
            if v_t > highest_tuple:
                highest_tuple = v_t
                highest_str = v_str

    return highest_str
