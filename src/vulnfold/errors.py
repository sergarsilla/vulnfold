"""Exception hierarchy for vulnfold.

Every failure vulnfold raises derives from :class:`VulnfoldError`, so a caller
can catch the whole surface with one clause. The hierarchy lives in its own
module because the domain layer and the I/O boundary both raise from it, and
homing it in either one would force a dependency edge between them.
"""

from __future__ import annotations


class VulnfoldError(Exception):
    """Base class for every error vulnfold raises."""


class MappingError(VulnfoldError):
    """A field mapping could not be located, parsed or validated."""


class IndexerError(VulnfoldError):
    """Communication with the indexer failed."""


class IndexNotReadableError(IndexerError):
    """The configured index pattern does not exist or cannot be read."""


class ReadOnlyViolationError(IndexerError):
    """A request was attempted that could modify the cluster.

    vulnfold is read-only by design (CONTEXT.md, decision D2). Reaching this
    error means a code path tried to leave the read-only envelope, which is a
    defect rather than a runtime condition.
    """


class AggregationError(IndexerError):
    """The indexer answered with a body that is not a usable aggregation."""


class ConfigurationError(VulnfoldError):
    """The scan was invoked with settings that cannot produce a result."""
