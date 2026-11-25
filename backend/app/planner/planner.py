from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.planner.schema import (
    UnifiedFinding,
    Category,
    FixClass,
    FixStatus,
)


class PhaseNumber(int, Enum):
    PHASE_1_SECRETS = 1
    PHASE_2_BASELINE = 2
    PHASE_3_DEPENDENCIES = 3
    PHASE_4_CODE = 4
    PHASE_5_DOCKER = 5
    PHASE_6_WORKFLOWS = 6


class PhasePlan(BaseModel):
    phase_number: int
    name: str
    description: str
    category: str
    auto_fixable: bool
    fix_class_default: str
    findings: List[UnifiedFinding] = Field(default_factory=list)
    status: str = "PENDING"  # PENDING, IN_PROGRESS, COMPLETED, SKIPPED

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class FixPlan(BaseModel):
    phases: List[PhasePlan]
    total_findings: int
    auto_fixable_count: int
    manual_only_count: int
    baseline_status: str = "PENDING"  # PENDING, STATIC-VERIFIED, UNVERIFIED, FAILED
    summary: str


def create_fix_plan(
    findings: List[UnifiedFinding],
    baseline_status: str = "PENDING",
) -> FixPlan:
    """
    Constructs a strictly sequenced 6-Phase Fix Plan:
      Phase 1: Secrets (Flag for rotation, no auto-fix, MANUAL_ONLY)
      Phase 2: Baseline Capture (Build/test environment validation)
      Phase 3: Dependencies (Minimal version bumps, lockfile sync)
      Phase 4: Code Issues (Semgrep SAST remediations)
      Phase 5: Dockerfile (Hadolint container hardening)
      Phase 6: Workflows & Repo Hygiene (Actionlint, pinned SHAs, permissions)
    """
    p1_secrets: List[UnifiedFinding] = []
    p3_deps: List[UnifiedFinding] = []
    p4_code: List[UnifiedFinding] = []
    p5_docker: List[UnifiedFinding] = []
    p6_workflows: List[UnifiedFinding] = []

    for f in findings:
        cat = f.category if isinstance(f.category, str) else f.category.value
        fclass = f.fix_class if isinstance(f.fix_class, str) else f.fix_class.value

        if cat == Category.SECRET.value or fclass == FixClass.MANUAL_ONLY.value:
            # Secrets and any manual-only findings MUST be triaged in Phase 1
            f.status = FixStatus.MANUAL
            p1_secrets.append(f)
        elif cat == Category.DEPENDENCY.value:
            p3_deps.append(f)
        elif cat == Category.CODE.value:
            p4_code.append(f)
        elif cat == Category.DOCKER.value:
            p5_docker.append(f)
        elif cat in (Category.WORKFLOW.value, Category.HYGIENE.value):
            p6_workflows.append(f)
        else:
            p4_code.append(f)

    phases = [
        PhasePlan(
            phase_number=1,
            name="Phase 1: Secrets & Leaked Credentials",
            description="Flagged credentials and tokens. NEVER auto-fixed. Requires manual revocation, provider rotation, and git-history purge.",
            category=Category.SECRET.value,
            auto_fixable=False,
            fix_class_default=FixClass.MANUAL_ONLY.value,
            findings=p1_secrets,
            status="COMPLETED" if not p1_secrets else "PENDING",
        ),
        PhasePlan(
            phase_number=2,
            name="Phase 2: Baseline Environment Capture",
            description="Captures build, syntax, and test status of untouched repository before applying automated changes.",
            category="baseline",
            auto_fixable=False,
            fix_class_default="BASELINE",
            findings=[],
            status=baseline_status if baseline_status != "PENDING" else "PENDING",
        ),
        PhasePlan(
            phase_number=3,
            name="Phase 3: Dependencies & Package Vulnerabilities",
            description="Updates outdated/vulnerable packages to minimal safe fixed versions with lockfile reconciliation.",
            category=Category.DEPENDENCY.value,
            auto_fixable=True,
            fix_class_default=FixClass.AUTO_VERIFIED.value,
            findings=p3_deps,
            status="COMPLETED" if not p3_deps else "PENDING",
        ),
        PhasePlan(
            phase_number=4,
            name="Phase 4: Code & SAST Remediations",
            description="Fixes static application security flaws (Semgrep) in source files.",
            category=Category.CODE.value,
            auto_fixable=True,
            fix_class_default=FixClass.AUTO_VERIFIED.value,
            findings=p4_code,
            status="COMPLETED" if not p4_code else "PENDING",
        ),
        PhasePlan(
            phase_number=5,
            name="Phase 5: Dockerfile Hardening",
            description="Resolves Hadolint warnings, non-root USER execution, and base image pinning.",
            category=Category.DOCKER.value,
            auto_fixable=True,
            fix_class_default=FixClass.AUTO_VERIFIED.value,
            findings=p5_docker,
            status="COMPLETED" if not p5_docker else "PENDING",
        ),
        PhasePlan(
            phase_number=6,
            name="Phase 6: CI/CD Workflows & Hygiene",
            description="Hardens GitHub Actions workflows (Actionlint), pins commit SHAs, configures least-privilege permissions.",
            category=Category.WORKFLOW.value,
            auto_fixable=True,
            fix_class_default=FixClass.SAFE_AUTO.value,
            findings=p6_workflows,
            status="COMPLETED" if not p6_workflows else "PENDING",
        ),
    ]

    auto_fixable = sum(len(p.findings) for p in phases if p.auto_fixable)
    manual_only = len(p1_secrets)

    summary = (
        f"Generated 6-Phase Fix Plan for {len(findings)} findings: "
        f"{auto_fixable} auto-fixable candidate(s), {manual_only} manual-only secret(s)/auth issue(s)."
    )

    return FixPlan(
        phases=phases,
        total_findings=len(findings),
        auto_fixable_count=auto_fixable,
        manual_only_count=manual_only,
        baseline_status=baseline_status,
        summary=summary,
    )
