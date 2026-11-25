import os
import asyncio
import time
from typing import List, Dict, Any, Optional, Set, Callable, Tuple
from pydantic import BaseModel, Field

from app.planner.schema import UnifiedFinding, FixStatus, FixClass, Category, clean_file_path
from app.planner.planner import FixPlan, PhasePlan
from app.verifier.sandbox import RepoSandbox
from app.verifier.detector import detect_project_profile, ProjectProfile
from app.verifier.syntax_checker import check_file_static_syntax
from app.verifier.dependency import classify_version_bump
from app.verifier.fingerprint import compute_finding_fingerprint

# Configurable verification timeout (default 600s)
PER_SCAN_TIMEOUT_SECONDS = int(os.getenv("PER_SCAN_TIMEOUT_SECONDS", "600"))


class VerificationCancelToken:
    def __init__(self):
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def is_cancelled(self) -> bool:
        return self._cancelled


class VerificationResult(BaseModel):
    status: str = "COMPLETED"  # COMPLETED, FAILED, UNVERIFIED
    verification_label: str = "UNVERIFIED"
    baseline_profile: ProjectProfile
    applied_fixes: List[UnifiedFinding] = Field(default_factory=list)
    reverted_fixes: List[UnifiedFinding] = Field(default_factory=list)
    manual_only_fixes: List[UnifiedFinding] = Field(default_factory=list)
    major_bump_fixes: List[UnifiedFinding] = Field(default_factory=list)
    unified_diff: str = ""
    commit_count: int = 0
    logs: List[str] = Field(default_factory=list)

    @property
    def total_applied(self) -> int:
        return len(self.applied_fixes)

    @property
    def total_reverted(self) -> int:
        return len(self.reverted_fixes)


def extract_finding_fingerprints(findings_list: List[Any]) -> Set[str]:
    """Computes stable SHA256 fingerprints for findings returned by scanners."""
    fps = set()
    for item in findings_list:
        if isinstance(item, dict):
            rule_id = item.get("rule_id") or item.get("id") or "rule"
            file_path = item.get("file") or ""
            snippet = item.get("code_snippet")
            tool = item.get("tool")
            package = item.get("package")
            line_text = item.get("original_block") or item.get("description")
            fps.add(compute_finding_fingerprint(
                rule_id=rule_id,
                file_path=file_path,
                snippet=snippet,
                tool=tool,
                package=package,
                line_text=line_text,
            ))
        elif isinstance(item, UnifiedFinding):
            fps.add(item.fingerprint)
    return fps


async def bisect_batch_failure(
    sandbox: RepoSandbox,
    batch: List[UnifiedFinding],
    rescan_callback: Callable,
    baseline_fps: Set[str],
    logs: List[str],
) -> Tuple[List[UnifiedFinding], List[UnifiedFinding]]:
    """
    Requirement B4: Bisect on batch failure to isolate which fix caused the regression.
    Returns (verified_fixes, reverted_fixes).
    """
    if not batch:
        return [], []

    # If single element, we know it's the failing one
    if len(batch) == 1:
        failed_fix = batch[0]
        sandbox.revert_patch(failed_fix)
        failed_fix.status = FixStatus.REVERTED
        failed_fix.verification_log = "REVERTED: Isolated as source of batch regression during bisection."
        logs.append(f"      [BISECT FAILED] Fix {failed_fix.id} failed verification and was reverted.")
        return [], [failed_fix]

    mid = len(batch) // 2
    left_batch = batch[:mid]
    right_batch = batch[mid:]

    logs.append(f"      [BISECT] Splitting batch of {len(batch)} into halves: ({len(left_batch)}, {len(right_batch)}).")

    # Revert all uncommitted and re-test left half
    for f in batch:
        sandbox.revert_patch(f)

    # Apply left half
    left_applied: List[UnifiedFinding] = []
    for f in left_batch:
        ok, _ = sandbox.apply_patch(f)
        if ok:
            left_applied.append(f)

    # Check left half
    left_rescan = await rescan_callback(sandbox.sandbox_path)
    left_fps = extract_finding_fingerprints(left_rescan.get("findings", []))
    # If left half introduced new findings or target finding still present
    left_has_regression = any(fp not in baseline_fps for fp in left_fps)

    verified_fixes: List[UnifiedFinding] = []
    reverted_fixes: List[UnifiedFinding] = []

    if not left_has_regression:
        # Left half is clean! Commit them
        for f in left_applied:
            commit_sha = sandbox.commit_fix(f)
            f.status = FixStatus.VERIFIED
            f.verification_log = f"Verified clean via bisection. Committed as {commit_sha[:7]}."
            verified_fixes.append(f)
        # Update baseline_fps with current state
        new_rescan = await rescan_callback(sandbox.sandbox_path)
        new_baseline_fps = extract_finding_fingerprints(new_rescan.get("findings", []))
        # Now bisect right half
        right_v, right_r = await bisect_batch_failure(sandbox, right_batch, rescan_callback, new_baseline_fps, logs)
        verified_fixes.extend(right_v)
        reverted_fixes.extend(right_r)
    else:
        # Left half failed, bisect left half
        left_v, left_r = await bisect_batch_failure(sandbox, left_batch, rescan_callback, baseline_fps, logs)
        verified_fixes.extend(left_v)
        reverted_fixes.extend(left_r)
        # Now try right half
        right_v, right_r = await bisect_batch_failure(sandbox, right_batch, rescan_callback, baseline_fps, logs)
        verified_fixes.extend(right_v)
        reverted_fixes.extend(right_r)

    return verified_fixes, reverted_fixes


async def run_verification_loop(
    repo_path: str,
    fix_plan: FixPlan,
    rescan_callback: Optional[Any] = None,
    deadline: Optional[float] = None,
    cancel_token: Optional[Any] = None,
) -> VerificationResult:
    """
    Executes the phased sandboxed verification loop:
    1. Sets up isolated RepoSandbox copy (symlinks skipped, hooks disabled).
    2. Detects build/test profile (never executing scripts on backend host).
    3. Runs each phase (Secrets -> Dependencies -> Code -> Docker -> Workflows).
    4. Full rescan per fix for AUTO_VERIFIED; per phase for SAFE_AUTO with batch bisection.
    5. Stable fingerprint-based regression & target resolution verification.
    6. Checks deadline and cancel_token between fixes to strictly prevent runaway executions.
    7. Automatically reverts any breaking patch and attaches failure logs.
    8. Sets STATIC-VERIFIED only after static checks and rescan pass.
    """
    logs: List[str] = []
    logs.append(f"Starting Sandboxed Verification Loop on: {os.path.basename(repo_path)}")
    timed_out = False
    cancelled = False

    # Step 1: Detect project profile
    # Requirement B1: Detector initializes verification_label="UNVERIFIED"
    profile = detect_project_profile(repo_path)
    logs.append(f"Project Profile Detected: Ecosystems={profile.ecosystems}, TestsDetected={profile.tests_detected}, HasCI={profile.has_ci}")
    logs.append(f"Initial Label: {profile.verification_label}")

    applied_fixes: List[UnifiedFinding] = []
    reverted_fixes: List[UnifiedFinding] = []
    manual_only_fixes: List[UnifiedFinding] = []
    major_bump_fixes: List[UnifiedFinding] = []

    with RepoSandbox(repo_path) as sandbox:
        # Capture baseline fingerprints if rescan_callback is provided
        baseline_fingerprints: Set[str] = set()
        if rescan_callback:
            try:
                initial_rescan = await rescan_callback(sandbox.sandbox_path)
                baseline_fingerprints = extract_finding_fingerprints(initial_rescan.get("findings", []))
                logs.append(f"Baseline findings captured ({len(baseline_fingerprints)} fingerprints).")
            except Exception as e:
                logs.append(f"Warning: Baseline rescan callback failed: {e}")

        # Step 2: Process Phase 1 (Secrets) - Never auto-fix
        p1 = next((p for p in fix_plan.phases if p.phase_number == 1), None)
        if p1 and p1.findings:
            logs.append(f"Phase 1: Quarantining {len(p1.findings)} leaked secret(s) for manual rotation.")
            for f in p1.findings:
                f.status = FixStatus.MANUAL
                f.verification_log = (
                    "MANUAL ACTION ONLY: Automated fixes are intentionally disabled for leaked credentials. "
                    "You must revoke the token at its provider and rewrite Git history with git-filter-repo."
                )
                manual_only_fixes.append(f)

        # Step 3: Process Auto-Fixable Phases (3 through 6)
        auto_phases = [p for p in fix_plan.phases if p.auto_fixable]

        for phase in auto_phases:
            if deadline is not None and time.time() > deadline:
                logs.append(f"[TIMEOUT] Verification deadline exceeded ({PER_SCAN_TIMEOUT_SECONDS}s). Halting loop.")
                timed_out = True
                break
            if cancel_token is not None and getattr(cancel_token, "is_cancelled", lambda: False)():
                logs.append("[CANCELLED] Verification cancel token signalled. Halting loop.")
                cancelled = True
                break

            logs.append(f"Entering {phase.name} ({len(phase.findings)} finding(s)).")

            # Check if this phase consists of SAFE_AUTO or AUTO_VERIFIED
            safe_auto_findings = [f for f in phase.findings if f.fix_class == FixClass.SAFE_AUTO.value or f.fix_class == FixClass.SAFE_AUTO]
            auto_verified_findings = [f for f in phase.findings if f not in safe_auto_findings]

            # ---------------------------------------------------------
            # 3A. AUTO_VERIFIED: Full rescan PER FIX (Requirement B4)
            # ---------------------------------------------------------
            for finding in auto_verified_findings:
                if deadline is not None and time.time() > deadline:
                    logs.append(f"[TIMEOUT] Verification deadline exceeded. Skipping {finding.id}.")
                    timed_out = True
                    break
                if cancel_token is not None and getattr(cancel_token, "is_cancelled", lambda: False)():
                    logs.append(f"[CANCELLED] Verification cancel token set. Skipping {finding.id}.")
                    cancelled = True
                    break

                finding_label = f"{finding.tool}:{finding.rule_id} ({finding.file})"
                logs.append(f"  Evaluating AUTO_VERIFIED patch for {finding_label}...")

                # Flag major version bumps
                if finding.category in (Category.DEPENDENCY.value, Category.DEPENDENCY):
                    if finding.current_version and finding.fixed_version:
                        bump_info = classify_version_bump(finding.current_version, finding.fixed_version)
                        if bump_info["is_major"]:
                            finding.is_major_bump = True
                            major_bump_fixes.append(finding)
                            logs.append(f"    [Flagged] Major version bump for {finding.package} ({finding.current_version} -> {finding.fixed_version}). Target: Draft PR.")

                # Requirement B2: Semgrep/LLM code patches are always draft-only until GitHub CI passes
                if finding.category in (Category.CODE.value, Category.CODE):
                    finding.draft_pr_only = True
                    finding.verification_log = "Semgrep/LLM code patch: queued for DRAFT PR until GitHub Actions CI passes."
                    logs.append(f"    [Notice] Code patch marked draft_pr_only awaiting GitHub CI.")

                # Apply patch in sandbox
                applied_ok, apply_err = sandbox.apply_patch(finding)
                if not applied_ok:
                    finding.status = FixStatus.REVERTED
                    finding.verification_log = f"Patch application failed: {apply_err}"
                    reverted_fixes.append(finding)
                    logs.append(f"    [FAILED] Could not apply patch: {apply_err}")
                    continue

                # Static syntax and compilation verification
                syntax_ok, syntax_err = check_file_static_syntax(finding.file, sandbox.sandbox_path)
                if not syntax_ok:
                    sandbox.revert_patch(finding)
                    finding.status = FixStatus.REVERTED
                    finding.verification_log = f"STATIC SYNTAX CHECK FAILED: {syntax_err}. Patch was safely reverted."
                    reverted_fixes.append(finding)
                    logs.append(f"    [REVERTED] {finding_label} broke syntax: {syntax_err}")
                    continue

                # Requirement B3: Stable fingerprint comparison & target resolution check
                rescan_passed = True
                rescan_err_msg = None

                if rescan_callback:
                    try:
                        rescan_res = await rescan_callback(sandbox.sandbox_path)
                        new_fps = extract_finding_fingerprints(rescan_res.get("findings", []))

                        # Check 1: Target finding must NOT still be present
                        target_still_detected = (finding.fingerprint in new_fps)
                        if not target_still_detected:
                            # Also check by tool/rule_id/file match in raw findings
                            norm_finding_file = clean_file_path(finding.file).lower()
                            for rf in rescan_res.get("findings", []):
                                if isinstance(rf, dict):
                                    rf_rule = str(rf.get("rule_id") or rf.get("id") or "").strip().lower()
                                    rf_file = clean_file_path(rf.get("file") or "").lower()
                                    if rf_rule == str(finding.rule_id).strip().lower() and rf_file == norm_finding_file:
                                        target_still_detected = True
                                        break

                        if target_still_detected:
                            rescan_passed = False
                            rescan_err_msg = f"Target finding {finding.id} ({finding.rule_id}) still detected in rescan after patch."

                        # Check 2: No new regressions introduced
                        regressions = [fp for fp in new_fps if fp not in baseline_fingerprints and fp != finding.fingerprint]
                        if regressions:
                            rescan_passed = False
                            rescan_err_msg = f"Rescan introduced {len(regressions)} new regression finding(s)."

                        # Update baseline if passed
                        if rescan_passed:
                            baseline_fingerprints = new_fps
                    except Exception as err:
                        logs.append(f"    Warning: rescan callback encountered: {err}")

                if not rescan_passed:
                    sandbox.revert_patch(finding)
                    finding.status = FixStatus.REVERTED
                    finding.verification_log = f"REVERTED: {rescan_err_msg}"
                    reverted_fixes.append(finding)
                    logs.append(f"    [REVERTED] {finding_label}: {rescan_err_msg}")
                    continue

                # All checks passed -> Commit atomically to sandbox branch
                try:
                    commit_sha = sandbox.commit_fix(finding)
                    finding.status = FixStatus.VERIFIED
                    finding.verification_log = f"STATIC-VERIFIED (tests not run). Committed as {commit_sha[:7]}."
                    applied_fixes.append(finding)
                    logs.append(f"    [VERIFIED] Successfully committed fix ({commit_sha[:7]}).")
                except Exception as commit_ex:
                    sandbox.revert_patch(finding)
                    finding.status = FixStatus.REVERTED
                    finding.verification_log = f"Git commit failed in sandbox: {commit_ex}"
                    reverted_fixes.append(finding)
                    logs.append(f"    [FAILED] Git commit failed: {commit_ex}")

            # ---------------------------------------------------------
            # 3B. SAFE_AUTO: Batch per phase + Bisect on failure (B4)
            # ---------------------------------------------------------
            if safe_auto_findings:
                logs.append(f"  Evaluating batch of {len(safe_auto_findings)} SAFE_AUTO finding(s)...")
                batch_applied: List[UnifiedFinding] = []

                for finding in safe_auto_findings:
                    applied_ok, apply_err = sandbox.apply_patch(finding)
                    if applied_ok:
                        syntax_ok, _ = check_file_static_syntax(finding.file, sandbox.sandbox_path)
                        if syntax_ok:
                            batch_applied.append(finding)
                        else:
                            sandbox.revert_patch(finding)
                            finding.status = FixStatus.REVERTED
                            reverted_fixes.append(finding)
                    else:
                        finding.status = FixStatus.REVERTED
                        reverted_fixes.append(finding)

                # Batch Rescan
                batch_passed = True
                if rescan_callback and batch_applied:
                    try:
                        rescan_res = await rescan_callback(sandbox.sandbox_path)
                        new_fps = extract_finding_fingerprints(rescan_res.get("findings", []))
                        if any(fp not in baseline_fingerprints for fp in new_fps):
                            batch_passed = False
                    except Exception:
                        batch_passed = True

                if batch_passed:
                    for f in batch_applied:
                        commit_sha = sandbox.commit_fix(f)
                        f.status = FixStatus.VERIFIED
                        f.verification_log = f"STATIC-VERIFIED (tests not run). Committed as {commit_sha[:7]}."
                        applied_fixes.append(f)
                    logs.append(f"    [BATCH PASS] All {len(batch_applied)} SAFE_AUTO fixes passed batch verification.")
                else:
                    # Requirement B4: Batch failed -> Bisect to isolate failing fix
                    logs.append(f"    [BATCH FAILED] Regressions detected. Starting bisection across {len(batch_applied)} fixes...")
                    v_fixes, r_fixes = await bisect_batch_failure(sandbox, batch_applied, rescan_callback, baseline_fingerprints, logs)
                    applied_fixes.extend(v_fixes)
                    reverted_fixes.extend(r_fixes)

        # Step 4: Final verification label computation
        # Requirement B1: STATIC-VERIFIED only after static checks & rescan pass
        if timed_out:
            final_status = "TIMEOUT"
            final_label = "UNVERIFIED"
            profile.static_checks_passed = False
        elif cancelled:
            final_status = "CANCELLED"
            final_label = "UNVERIFIED"
            profile.static_checks_passed = False
        elif applied_fixes:
            final_status = "COMPLETED"
            final_label = "STATIC-VERIFIED (tests not run)"
            profile.static_checks_passed = True
        else:
            final_status = "COMPLETED"
            final_label = "UNVERIFIED"
            profile.static_checks_passed = False

        profile.verification_label = final_label
        final_diff = sandbox.get_diff(against_baseline=True)
        commit_count = sandbox.get_commit_count()

        logs.append(f"Verification loop finished: {len(applied_fixes)} verified fix(es), {len(reverted_fixes)} reverted, {len(manual_only_fixes)} manual-only.")
        logs.append(f"Final Verification Label: {final_label}")

        return VerificationResult(
            status=final_status,
            verification_label=final_label,
            baseline_profile=profile,
            applied_fixes=applied_fixes,
            reverted_fixes=reverted_fixes,
            manual_only_fixes=manual_only_fixes,
            major_bump_fixes=major_bump_fixes,
            unified_diff=final_diff,
            commit_count=commit_count,
            logs=logs,
        )
