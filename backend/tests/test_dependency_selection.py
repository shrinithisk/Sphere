import pytest
from app.verifier.dependency import (
    classify_version_bump,
    select_minimal_fixed_version,
    select_version_fixing_all_advisories,
    parse_version_tuple,
)


def test_classify_version_bump():
    # Patch bump
    patch = classify_version_bump("1.2.3", "1.2.4")
    assert patch["bump_type"] == "patch"
    assert patch["is_major"] is False
    assert patch["risk_level"] == "low"

    # Minor bump
    minor = classify_version_bump("1.2.3", "1.3.0")
    assert minor["bump_type"] == "minor"
    assert minor["is_major"] is False
    assert minor["risk_level"] == "medium"

    # Major bump
    major = classify_version_bump("1.2.3", "2.0.0")
    assert major["bump_type"] == "major"
    assert major["is_major"] is True
    assert major["risk_level"] == "high"


def test_select_minimal_fixed_version():
    current = "2.11.3"
    # Available fixed versions across multiple releases
    available = ["2.11.4", "3.0.1", "3.1.2"]

    # Must select 2.11.4 (minimal safe version that fixes flaw)
    selected = select_minimal_fixed_version(current, available)
    assert selected == "2.11.4"


def test_select_minimal_fixed_version_when_only_major_available():
    current = "0.19.0"
    available = ["1.0.0", "2.0.0"]
    selected = select_minimal_fixed_version(current, available)
    assert selected == "1.0.0"


def test_select_version_fixing_all_advisories_basic():
    # Requirement B7: fixes at 2.1.0 and 2.3.0 -> 2.3.0
    current = "2.0.0"
    advisories = ["2.1.0", "2.3.0"]
    selected = select_version_fixing_all_advisories(current, advisories)
    assert selected == "2.3.0"


def test_select_version_fixing_all_advisories_per_branch_same_branch():
    # Requirement B7: aware of per-branch fixed versions
    # Current version is in 1.x line (1.14.0)
    # Advisory 1 fixed at 1.14.2 or 2.1.0
    # Advisory 2 fixed at 1.14.8 or 2.2.0
    # Smallest version fixing all advisories staying in 1.x is 1.14.8
    current = "1.14.0"
    advisories = [["1.14.2", "2.1.0"], ["1.14.8", "2.2.0"]]
    selected = select_version_fixing_all_advisories(current, advisories)
    assert selected == "1.14.8"


def test_select_version_fixing_all_advisories_forced_major_jump():
    # Advisory 1 fixed at 1.14.2
    # Advisory 2 only fixed in 2.3.0
    # Both advisories resolved only by jumping to 2.3.0
    current = "1.14.0"
    advisories = [["1.14.2"], ["2.3.0"]]
    selected = select_version_fixing_all_advisories(current, advisories)
    assert selected == "2.3.0"


def test_select_version_fixing_all_advisories_three_advisories():
    current = "1.0.0"
    advisories = ["1.5.0", "2.1.0", "2.3.0"]
    selected = select_version_fixing_all_advisories(current, advisories)
    assert selected == "2.3.0"
