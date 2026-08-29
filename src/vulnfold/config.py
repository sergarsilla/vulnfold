"""Constants and runtime settings.

No literal that steers behaviour belongs anywhere else in the codebase. Field
names are the one thing that is *not* here: those live in ``mappings/`` and
reach the code through :mod:`vulnfold.mapping`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent

#: Mapping directories, most specific first: an installed copy shipped inside
#: the wheel, then the repository checkout it was built from.
MAPPING_SEARCH_PATHS: tuple[Path, ...] = (
    PACKAGE_ROOT / "mappings",
    PACKAGE_ROOT.parent.parent / "mappings",
)
DEFAULT_MAPPING_NAME = "wazuh-4.x"
MAPPING_FILE_SUFFIX = ".yaml"

DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_REQUEST_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 1.0
RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

#: Buckets requested per ``composite`` page. Pagination follows ``after_key``
#: until exhaustion, so this bounds memory and response size, never the result.
COMPOSITE_PAGE_SIZE = 1000

#: Elasticsearch caps a ``terms`` aggregation at this many buckets by default;
#: a bucket touching more agents is detected against a control cardinality.
AGENT_TERMS_SIZE = 10000

#: Must exceed the number of distinct severity strings a deployment can emit,
#: so no severity is silently dropped from a bucket's breakdown.
SEVERITY_TERMS_SIZE = 25

#: Placeholder for findings whose package version is absent from the document.
UNKNOWN_VERSION = "unknown"

#: Key used in ``severity_breakdown`` for findings carrying no usable severity.
UNKNOWN_SEVERITY = "unknown"

#: Package-name globs that identify a kernel. Kernels dominate the finding
#: count and are remediated as one upgrade plus a reboot (CONTEXT.md, section 2).
KERNEL_PACKAGE_PATTERNS: tuple[str, ...] = (
    "linux-image-*",
    "linux-headers-*",
    "linux-oracle",
    "linux-*-generic",
    "kernel-*",
)

DEFAULT_PASSWORD_ENV_VAR = "VULNFOLD_PASSWORD"
DEFAULT_TOP_ACTIONS = 20


@dataclass(frozen=True)
class ScanConfig:
    """Everything the indexer client needs to run one read-only scan.

    Attributes:
        url: Base URL of the Wazuh indexer, without a trailing path.
        username: Account used for HTTP basic authentication.
        password: Secret for ``username``. Never logged, never rendered.
        index_pattern: Index pattern to query; overrides the mapping default.
        verify_tls: Whether certificates are validated. Disabling it is an
            explicit, warned-about choice.
        timeout_seconds: Per-request timeout.
        page_size: Buckets requested per ``composite`` page.
    """

    url: str
    username: str
    password: str = field(repr=False)
    index_pattern: str
    verify_tls: bool = True
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    page_size: int = COMPOSITE_PAGE_SIZE
