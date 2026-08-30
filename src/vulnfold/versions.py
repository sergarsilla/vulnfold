"""Ordering for version strings, used to pick a package's highest target.

This is a **heuristic ordering, not a Debian version comparator**. It exists to
answer one narrow question: when one installed version of a package carries
several ``Package less than X`` conditions, which ``X`` is the furthest ahead?
Those candidates come from the same package's own release series, so they share
a shape, and comparing runs of digits numerically resolves them.

It deliberately does not implement Debian semantics. Epochs are compared as
ordinary leading numbers rather than as a separate namespace, and ``+dfsg``,
``+deb13u1`` and ``ubuntu`` suffixes are compared as text. Getting those subtly
wrong across unrelated packages would be worse than not attempting them, and
implementing them correctly is a project of its own (SPEC-02 section 5).

One Debian rule *is* honoured: a tilde sorts before everything, including the
end of the string, so ``6.14.0-37.37~24.04.1`` sorts below ``6.14.0-37.37``.
Backport suffixes of that shape are ubiquitous in the measured data, and
ignoring the rule inverts the order of real versions.
"""

from __future__ import annotations

import re
from functools import cmp_to_key

#: Splits a version into alternating (non-digit, digit) parts, always starting
#: with the non-digit one so that two versions' parts line up like with like.
_PART = re.compile(r"(\D*)(\d*)")

#: Sort value of a tilde, and of the end of a string. Every other character
#: keeps its code point, which is positive, so both sort below all of them and
#: the tilde sorts below the end of the string.
_TILDE_ORDER = -1
_END_ORDER = 0
_TILDE = "~"


def max_target_version(candidates: list[str]) -> str:
    """Pick the furthest-ahead version among a package's target versions.

    Args:
        candidates: Target versions, at least one, as the conditions carried
            them.

    Returns:
        The greatest under this module's ordering. Candidates that order equal
        resolve to the lexicographically greater string, so the result is
        deterministic.

    Raises:
        ValueError: ``candidates`` is empty. Only fixable buckets reach here and
            every one of them carries a target version, so an empty list is a
            defect in the caller rather than a runtime condition.
    """
    if not candidates:
        raise ValueError(
            "Cannot choose a target version from an empty candidate list. Only "
            "findings that name a fixed version become remediation actions, so "
            "this list is never empty in a correct call."
        )
    ordering = cmp_to_key(compare_versions)
    # The string itself breaks ties: two spellings of one version order equal,
    # and max() would otherwise return whichever the caller listed first.
    return max(candidates, key=lambda candidate: (ordering(candidate), candidate))


def compare_versions(left: str, right: str) -> int:
    """Order two version strings.

    Args:
        left: One version string.
        right: The other.

    Returns:
        A negative number when ``left`` sorts first, a positive number when
        ``right`` does, and zero when they order equal. Equal ordering does not
        mean the strings match: ``1.0`` and ``1.00`` compare equal here.
    """
    left_parts = _split(left)
    right_parts = _split(right)
    for index in range(max(len(left_parts), len(right_parts))):
        left_text, left_number = left_parts[index] if index < len(left_parts) else ("", 0)
        right_text, right_number = right_parts[index] if index < len(right_parts) else ("", 0)

        text_order = _compare_text(left_text, right_text)
        if text_order != 0:
            return text_order
        if left_number != right_number:
            return left_number - right_number
    return 0


def _split(version: str) -> list[tuple[str, int]]:
    """Break a version into (separator, number) parts, in order.

    Anchoring every part on a non-digit run — empty when the version starts
    with a digit — keeps the two operands aligned: part *n* of one version is
    always compared against part *n* of the other, text against text and number
    against number.
    """
    parts = [
        (match.group(1), int(match.group(2)) if match.group(2) else 0)
        for match in _PART.finditer(version.strip())
        if match.group(0)
    ]
    return parts or [("", 0)]


def _compare_text(left: str, right: str) -> int:
    """Compare two separator runs, with the tilde sorting below everything."""
    for index in range(max(len(left), len(right))):
        left_order = _character_order(left, index)
        right_order = _character_order(right, index)
        if left_order != right_order:
            return left_order - right_order
    return 0


def _character_order(text: str, index: int) -> int:
    if index >= len(text):
        return _END_ORDER
    character = text[index]
    return _TILDE_ORDER if character == _TILDE else ord(character)
