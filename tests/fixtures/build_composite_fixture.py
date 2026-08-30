"""Shape the recorded Wazuh response into the pages of a composite walk.

``wazuh_composite_sample.json`` is a real ``composite`` aggregation over
``wazuh-states-vulnerabilities-*`` on a Wazuh 4.14.7 indexer (15-agent lab),
recorded on 2026-08-30 and reduced to the measured values: one entry per
``(package, version, condition)`` bucket carrying its finding count, its agent
counts, its severity counts and its CVE cardinality. This script wraps those
entries back into the response envelope the client parses and splits them into
pages, then refuses to write anything that stopped reconciling with the fleet
numbers the specifications were measured against.

**Everything in the fixture is recorded. Nothing is synthesized.** That is a
change from the first version of this script, which derived per-bucket agents,
CVE cardinality and severity from a ``multi_terms`` response that carried no
sub-aggregations at all. SPEC-02 ended that: it accepts against 1,322 fixable
criticals and 1,170 with no vendor fix, and severity is not independent of
fixability in real data. Apportioning severity in proportion to finding counts,
as the derivation did, puts 1,041 criticals in the fixable half — so the
fixture would have been fabricating the very numbers the acceptance criteria
check. Recording the sub-aggregations settles it. ``wazuh_sample.json`` is that
earlier ``multi_terms`` recording, kept as the provenance of the fleet figures
CONTEXT.md quotes; nothing reads it any more.

Re-record it against a lab indexer with a read-only account. Any transport
works; the point is that the body is the query vulnfold itself builds, so run
it through whatever reaches the indexer:

    POST <indexer>/wazuh-states-vulnerabilities-*/_search
    <body of vulnfold.mapping.build_composite_query, walked to exhaustion>

Then reduce each bucket to the keys listed above. The recording must carry no
credentials and no hostname; agent ids are the only fleet identifiers in it,
and they are already what the plan is about.

Run from the repository root:

    python tests/fixtures/build_composite_fixture.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).resolve().parent
SOURCE = FIXTURES / "wazuh_composite_sample.json"
TARGET = FIXTURES / "aggregation_response.json"

#: Small enough that the recorded fleet spans several pages, so a fixture-driven
#: test exercises ``after_key`` paging rather than a single response.
PAGE_SIZE = 248

#: The fleet as measured, and as CONTEXT.md and both specifications quote it.
#: SPEC-02 section 0 supplies the fixability split.
MEASURED_FINDINGS = 32_718
MEASURED_AGENTS = 15
MEASURED_DISTINCT_CVES = 5_950
MEASURED_DISTINCT_PACKAGES = 554
MEASURED_SEVERITIES = {
    "High": 12_158,
    "Medium": 10_295,
    "-": 7_287,
    "Critical": 2_492,
    "Low": 484,
    "None": 2,
}
MEASURED_FIXABLE_FINDINGS = 13_664
MEASURED_FIXABLE_CRITICALS = 1_322
MEASURED_NO_FIX_FINDINGS = 19_039
MEASURED_NO_FIX_CRITICALS = 1_170
MEASURED_UNKNOWN_FINDINGS = 15

# The marker strings the recorded deployment emits. They live in
# ``mappings/wazuh-4.x.yaml`` for the production code; this script restates them
# because it verifies the recording, and a verifier that read its expectations
# from the thing under test would verify nothing.
NO_FIX_CONDITION = "package default status"
FIXED_VERSION_PREFIX = "package less than "

CRITICAL = "Critical"


def main() -> None:
    """Write the composite fixture from the recorded response."""
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    entries: list[dict[str, Any]] = source["buckets"]

    _verify(entries, source["totals"])

    pages = _paginate([_bucket(entry) for entry in entries], source["totals"])
    TARGET.write_text(json.dumps(pages, indent=1) + "\n", encoding="utf-8")
    findings = sum(entry["doc_count"] for entry in entries)
    print(f"{TARGET.name}: {len(pages)} pages, {len(entries)} buckets, {findings:,} findings")


def _bucket(entry: dict[str, Any]) -> dict[str, Any]:
    """Wrap one recorded entry in the response shape the client parses."""
    return {
        "key": {"pkg": entry["pkg"], "ver": entry["ver"], "cond": entry["cond"]},
        "doc_count": entry["doc_count"],
        "agents": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [
                {"key": agent, "doc_count": count} for agent, count in entry["agents"].items()
            ],
        },
        "agent_cardinality": {"value": entry["agent_cardinality"]},
        "severity": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [
                {"key": label, "doc_count": count} for label, count in entry["severity"].items()
            ],
        },
        "cves": {"value": entry["cves"]},
    }


def _paginate(buckets: list[dict[str, Any]], totals: dict[str, int]) -> list[dict[str, Any]]:
    """Split the buckets into composite pages, ending with the empty page.

    A composite aggregation keeps answering with an ``after_key`` until a page
    comes back with no buckets, so the transcript of a full walk includes that
    final empty response.
    """
    pages: list[dict[str, Any]] = []
    for offset in range(0, len(buckets), PAGE_SIZE):
        page = buckets[offset : offset + PAGE_SIZE]
        aggregations: dict[str, Any] = {}
        if offset == 0:
            aggregations["total_agents"] = {"value": totals["agents"]}
            aggregations["total_cves"] = {"value": totals["distinct_cves"]}
            aggregations["total_packages"] = {"value": totals["distinct_packages"]}
        aggregations["actions"] = {"after_key": page[-1]["key"], "buckets": page}
        pages.append(_response(aggregations))
    pages.append(_response({"actions": {"buckets": []}}))
    return pages


def _response(aggregations: dict[str, Any]) -> dict[str, Any]:
    return {
        "took": 12,
        "timed_out": False,
        "_shards": {"total": 2, "successful": 2, "skipped": 0, "failed": 0},
        "hits": {"max_score": None, "hits": []},
        "aggregations": aggregations,
    }


def _verify(entries: list[dict[str, Any]], totals: dict[str, int]) -> None:
    """Fail loudly if the recording stopped reconciling with the measurements."""
    _expect(sum(entry["doc_count"] for entry in entries), MEASURED_FINDINGS, "findings")
    _expect(totals["findings"], MEASURED_FINDINGS, "recorded finding total")
    _expect(totals["agents"], MEASURED_AGENTS, "agents")
    _expect(totals["distinct_cves"], MEASURED_DISTINCT_CVES, "distinct CVEs")
    _expect(totals["distinct_packages"], MEASURED_DISTINCT_PACKAGES, "distinct packages")

    for label, measured in MEASURED_SEVERITIES.items():
        counted = sum(entry["severity"].get(label, 0) for entry in entries)
        _expect(counted, measured, f"findings of severity {label!r}")

    for entry in entries:
        if sum(entry["severity"].values()) != entry["doc_count"]:
            raise RuntimeError(
                f"Severity counts for {entry['pkg']} {entry['ver']} do not sum to "
                f"its {entry['doc_count']} findings."
            )

    classes = {"fixable": 0, "no_fix": 0, "unknown": 0}
    criticals = {"fixable": 0, "no_fix": 0, "unknown": 0}
    for entry in entries:
        name = _classify(entry["cond"])
        classes[name] += entry["doc_count"]
        criticals[name] += entry["severity"].get(CRITICAL, 0)

    _expect(classes["fixable"], MEASURED_FIXABLE_FINDINGS, "fixable findings")
    _expect(criticals["fixable"], MEASURED_FIXABLE_CRITICALS, "fixable criticals")
    _expect(classes["no_fix"], MEASURED_NO_FIX_FINDINGS, "findings with no vendor fix")
    _expect(criticals["no_fix"], MEASURED_NO_FIX_CRITICALS, "criticals with no vendor fix")
    _expect(classes["unknown"], MEASURED_UNKNOWN_FINDINGS, "findings of unrecognised fixability")

    agents = {agent for entry in entries for agent in entry["agents"]}
    _expect(len(agents), MEASURED_AGENTS, "agents carrying a finding")


def _classify(condition: str | None) -> str:
    folded = (condition or "").strip().casefold()
    if folded == NO_FIX_CONDITION:
        return "no_fix"
    if folded.startswith(FIXED_VERSION_PREFIX) and folded[len(FIXED_VERSION_PREFIX) :].strip():
        return "fixable"
    return "unknown"


def _expect(counted: int, measured: int, what: str) -> None:
    if counted != measured:
        raise RuntimeError(f"Recorded {counted:,} {what}, measured {measured:,}.")


if __name__ == "__main__":
    main()
