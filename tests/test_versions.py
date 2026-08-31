"""Ordering of version strings.

Every version string exercised here is one the lab indexer actually emitted
(SPEC-02 section 5); none is invented to make the comparator look good.
"""

from __future__ import annotations

import pytest

from vulnfold.versions import compare_versions, max_target_version

#: The six real suffix shapes SPEC-02 section 5 names, in the order this
#: module claims for them.
MEASURED_VERSIONS = [
    "0:2.52.3-0ubuntu0.24.04.1",
    "3.5.1+dfsg1-0ubuntu1.2",
    "6.12.74-2",
    "6.12.100-1",
    "6.14.0-37.37~24.04.1",
    "6.17.0-1020.20",
]


def test_max_target_version_picks_the_highest_of_the_measured_versions() -> None:
    highest = max_target_version(list(reversed(MEASURED_VERSIONS)))

    assert highest == "6.17.0-1020.20"


@pytest.mark.parametrize(
    ("lower", "higher"),
    list(zip(MEASURED_VERSIONS, MEASURED_VERSIONS[1:], strict=False)),
)
def test_measured_versions_order_as_a_chain(lower: str, higher: str) -> None:
    assert compare_versions(lower, higher) < 0
    assert compare_versions(higher, lower) > 0


def test_digit_runs_compare_numerically_not_as_text() -> None:
    # "6.12.100-1" < "6.12.74-2" as text, because '1' < '7'.
    assert compare_versions("6.12.74-2", "6.12.100-1") < 0
    assert max_target_version(["6.12.100-1", "6.12.74-2"]) == "6.12.100-1"


def test_tilde_sorts_below_the_end_of_the_string() -> None:
    assert compare_versions("6.14.0-37.37~24.04.1", "6.14.0-37.37") < 0
    assert max_target_version(["6.14.0-37.37~24.04.1", "6.14.0-37.37"]) == "6.14.0-37.37"


def test_tilde_sorts_below_any_other_character() -> None:
    assert compare_versions("6.14~rc1", "6.14-rc1") < 0
    assert compare_versions("6.14~rc1", "6.14.1") < 0


def test_a_longer_version_outranks_the_prefix_it_extends() -> None:
    assert compare_versions("6.12.74", "6.12.74-2") < 0


def test_versions_differing_only_in_leading_zeros_order_equal() -> None:
    assert compare_versions("1.0", "1.00") == 0


def test_ties_resolve_to_the_lexicographically_greater_string() -> None:
    assert max_target_version(["1.0", "1.00"]) == "1.00"
    assert max_target_version(["1.00", "1.0"]) == "1.00"


def test_a_single_candidate_is_its_own_maximum() -> None:
    assert max_target_version(["6.12.100-1"]) == "6.12.100-1"


def test_surrounding_whitespace_does_not_change_the_ordering() -> None:
    assert compare_versions(" 6.12.100-1 ", "6.12.100-1") == 0


def test_max_target_version_rejects_an_empty_candidate_list() -> None:
    with pytest.raises(ValueError, match="empty candidate list"):
        max_target_version([])


def test_max_target_version_rejects_a_candidate_that_is_not_a_version() -> None:
    """SPEC-03 section 3: the guard names the string that should not be here."""
    with pytest.raises(ValueError, match="'or equal to 1.114.4' is not a version string"):
        max_target_version(["1.114.3", "or equal to 1.114.4"])


def test_the_guard_accepts_a_debian_epoch() -> None:
    assert max_target_version(["0:2.52.3-0ubuntu0.24.04.1"]) == "0:2.52.3-0ubuntu0.24.04.1"
