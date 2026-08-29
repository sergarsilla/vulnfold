"""Derive the composite-shaped fixture from the recorded Wazuh response.

``wazuh_sample.json`` is a real ``multi_terms`` response from a Wazuh 4.14.7
indexer (15-agent lab). SPEC-01 mandates a ``composite`` aggregation instead,
and that response carries no per-bucket sub-aggregations at all: its buckets
hold ``key`` and ``doc_count`` and nothing else.

So this script keeps every measured number and synthesizes only what was never
recorded. Measured, copied verbatim:

    32,718 findings, 744 (package, version) buckets, 554 distinct packages,
    5,950 distinct CVEs, 15 agents, and the severity distribution
    High 12,158 / Medium 10,295 / "-" 7,287 / Critical 2,492 / Low 484 /
    "None" 2.

Synthesized, deterministically, from the bucket key alone:

    per-bucket agent lists      A kernel version sits on exactly one host, since
                                each host runs its own build. Other packages
                                spread over up to five hosts, choosing a host
                                count that divides the bucket's finding count.
    per-bucket CVE cardinality  findings / hosts. A finding is one
                                (CVE, package, agent) tuple, so this identity
                                holds by construction; it also reproduces the
                                5,155 CVEs CONTEXT.md reports for the largest
                                kernel bucket.
    per-bucket severity counts  Apportioned in proportion to the measured
                                fleet distribution, so that every row sums to
                                its bucket's finding count and every column
                                sums to the measured fleet total, exactly.

Severity is apportioned proportionally and not jittered on purpose. The
recorded response holds no per-bucket severity at all, so any variation would
be invented, and inventing it fabricates an ordering: ranking puts criticals
first, so a jittered mix reorders buckets against the one ordering the source
data does support, that the seven largest buckets are the kernels. Proportional
apportionment assumes nothing the measurements do not already say. Behaviour
that depends on severity varying between packages is covered by purpose-built
buckets in test_collapse.py, which is where it belongs.

Run from the repository root:

    python tests/fixtures/build_composite_fixture.py
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).resolve().parent
SOURCE = FIXTURES / "wazuh_sample.json"
TARGET = FIXTURES / "aggregation_response.json"

# Aggregation names inside the recorded response, which was written by hand
# against the lab indexer. They are external data keys, not vulnfold's
# vocabulary: the derived fixture this script writes is named in English.
SOURCE_ACTIONS_AGG = "acciones_reales"
SOURCE_SEVERITY_AGG = "por_severidad"
SOURCE_AGENTS_AGG = "agentes"
SOURCE_CVES_AGG = "cves_distintos"
SOURCE_PACKAGES_AGG = "paquetes_distintos"

PAGE_SIZE = 248
AGENT_IDS: tuple[str, ...] = tuple(f"{number:03d}" for number in range(1, 16))
MAX_HOSTS_PER_PACKAGE = 5
# Coprime with len(AGENT_IDS), so stepping never revisits an agent.
AGENT_STEPS = (1, 2, 4, 7, 8, 11, 13, 14)
KERNEL_PREFIXES = ("linux-", "kernel-")


def main() -> None:
    """Write the composite fixture derived from the recorded response."""
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    aggregations = source["aggregations"]

    keys = _sorted_keys(aggregations[SOURCE_ACTIONS_AGG]["buckets"])
    severity_targets = _severity_targets(aggregations[SOURCE_SEVERITY_AGG]["buckets"])
    severities = _apportion_severities(keys, severity_targets)
    hosts = [_hosts_for(index, name, version, count) for index, (name, version, count) in enumerate(keys)]

    _verify(keys, severity_targets, severities, hosts)

    buckets = [
        _bucket(name, version, count, hosts[index], severities[index])
        for index, (name, version, count) in enumerate(keys)
    ]
    pages = _paginate(
        buckets,
        total_agents=aggregations[SOURCE_AGENTS_AGG]["value"],
        total_cves=aggregations[SOURCE_CVES_AGG]["value"],
        total_packages=aggregations[SOURCE_PACKAGES_AGG]["value"],
    )
    TARGET.write_text(json.dumps(pages, indent=1) + "\n", encoding="utf-8")
    print(f"{TARGET.name}: {len(pages)} pages, {len(buckets)} buckets, {sum(count for _, _, count in keys):,} findings")


def _sorted_keys(raw_buckets: list[dict[str, Any]]) -> list[tuple[str, str, int]]:
    """Order buckets as a composite aggregation returns them: by source, ascending."""
    keys = [(bucket["key"][0], bucket["key"][1], bucket["doc_count"]) for bucket in raw_buckets]
    return sorted(keys, key=lambda item: (item[0], item[1]))


def _severity_targets(raw_buckets: list[dict[str, Any]]) -> "OrderedDict[str, int]":
    return OrderedDict((bucket["key"], bucket["doc_count"]) for bucket in raw_buckets)


def _hosts_for(index: int, name: str, version: str, finding_count: int) -> list[str]:
    """Choose the hosts a (package, version) sits on.

    Every agent id is used at least once: the first host is picked by bucket
    index, and there are far more buckets than agents.
    """
    if _is_kernel(name):
        host_count = 1
    else:
        divisors = [
            candidate
            for candidate in range(1, MAX_HOSTS_PER_PACKAGE + 1)
            if finding_count % candidate == 0
        ]
        host_count = divisors[_digest(f"{name}|{version}|hosts") % len(divisors)]

    start = index % len(AGENT_IDS)
    step = AGENT_STEPS[_digest(f"{name}|{version}|step") % len(AGENT_STEPS)]
    return sorted(AGENT_IDS[(start + offset * step) % len(AGENT_IDS)] for offset in range(host_count))


def _is_kernel(package_name: str) -> bool:
    return package_name.startswith(KERNEL_PREFIXES)


def _apportion_severities(
    keys: list[tuple[str, str, int]],
    targets: "OrderedDict[str, int]",
) -> list[dict[str, int]]:
    """Spread the measured severity totals over the buckets.

    Rows sum to their bucket's finding count and columns sum to the measured
    fleet totals.
    """
    labels = list(targets)
    rows = [_apportion_row(count, labels, targets) for _, _, count in keys]
    _rebalance(rows, labels, targets)
    return rows


def _apportion_row(
    finding_count: int,
    labels: list[str],
    targets: "OrderedDict[str, int]",
) -> dict[str, int]:
    weights = [targets[label] for label in labels]
    total_weight = sum(weights)
    if total_weight <= 0:
        return {label: 0 for label in labels}

    shares = [finding_count * weight / total_weight for weight in weights]
    row = {label: int(share) for label, share in zip(labels, shares, strict=True)}

    shortfall = finding_count - sum(row.values())
    remainders = sorted(
        range(len(labels)),
        key=lambda position: (-(shares[position] % 1), labels[position]),
    )
    for position in remainders[:shortfall]:
        row[labels[position]] += 1
    return row


def _rebalance(
    rows: list[dict[str, int]],
    labels: list[str],
    targets: "OrderedDict[str, int]",
) -> None:
    """Move units between labels within rows until every column hits its target.

    Moving a unit from one label to another inside the same row leaves the row
    sum untouched, so bucket finding counts stay exact throughout.

    Corrections are spread one unit per row: taking the whole correction out of
    whichever rows come first would distort those buckets' severity mix out of
    all proportion to their size, and ranking reads severity first.
    """
    columns = {label: sum(row[label] for row in rows) for label in labels}
    while True:
        surplus = next((label for label in labels if columns[label] > targets[label]), None)
        deficit = next((label for label in labels if columns[label] < targets[label]), None)
        if surplus is None or deficit is None:
            break

        moved = 0
        for row in rows:
            if columns[surplus] == targets[surplus] or columns[deficit] == targets[deficit]:
                break
            if row[surplus] == 0:
                continue
            row[surplus] -= 1
            row[deficit] += 1
            columns[surplus] -= 1
            columns[deficit] += 1
            moved += 1

        if moved == 0:
            raise RuntimeError(
                f"No capacity left to move units from {surplus!r} to {deficit!r}."
            )


def _bucket(
    name: str,
    version: str,
    finding_count: int,
    hosts: list[str],
    severities: dict[str, int],
) -> dict[str, Any]:
    per_host = finding_count // len(hosts)
    return {
        "key": {"pkg": name, "ver": version},
        "doc_count": finding_count,
        "agents": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [{"key": host, "doc_count": per_host} for host in hosts],
        },
        "agent_cardinality": {"value": len(hosts)},
        "severity": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 0,
            "buckets": [
                {"key": label, "doc_count": count}
                for label, count in sorted(
                    ((label, count) for label, count in severities.items() if count > 0),
                    key=lambda item: (-item[1], item[0]),
                )
            ],
        },
        "cves": {"value": finding_count // len(hosts)},
    }


def _paginate(
    buckets: list[dict[str, Any]],
    *,
    total_agents: int,
    total_cves: int,
    total_packages: int,
) -> list[dict[str, Any]]:
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
            aggregations["total_agents"] = {"value": total_agents}
            aggregations["total_cves"] = {"value": total_cves}
            aggregations["total_packages"] = {"value": total_packages}
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


def _verify(
    keys: list[tuple[str, str, int]],
    targets: "OrderedDict[str, int]",
    severities: list[dict[str, int]],
    hosts: list[list[str]],
) -> None:
    """Fail loudly if the derived data stopped reconciling with the measurements."""
    for (name, version, count), row, host_list in zip(keys, severities, hosts, strict=True):
        if sum(row.values()) != count:
            raise RuntimeError(f"Severity row for {name} {version} does not sum to {count}.")
        if count % len(host_list) != 0:
            raise RuntimeError(f"{name} {version}: {count} findings do not divide over hosts.")

    for label, target in targets.items():
        got = sum(row[label] for row in severities)
        if got != target:
            raise RuntimeError(f"Severity {label!r}: apportioned {got}, measured {target}.")

    used = {host for host_list in hosts for host in host_list}
    if used != set(AGENT_IDS):
        raise RuntimeError(f"Agents used ({len(used)}) do not cover the fleet ({len(AGENT_IDS)}).")


def _digest(seed: str) -> int:
    return int.from_bytes(hashlib.blake2b(seed.encode(), digest_size=8).digest(), "big")


if __name__ == "__main__":
    main()
