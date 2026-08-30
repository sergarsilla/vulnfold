# vulnfold is a command, not a service: the image runs one scan and exits.
# Nothing here listens, so no port is exposed and no entrypoint script is needed.
#
#   docker build -t vulnfold:0.1.0 .
#   docker run --rm -e VULNFOLD_PASSWORD ghcr.io/OWNER/vulnfold:0.1.0 \
#       scan --url https://indexer.example.com:9200 --user readonly

FROM python:3.12-slim-bookworm AS build

# Build isolation is disabled below, so the backend has to be present already.
# Pinned to the same version pyproject.toml declares in [build-system].
RUN pip install --no-cache-dir hatchling==1.28.0 build==1.3.0

WORKDIR /src
# mappings/ is force-included into the wheel by pyproject.toml, so it has to be
# here at build time even though it lives outside src/.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY mappings ./mappings
RUN python -m build --wheel --no-isolation --outdir /dist


FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="vulnfold" \
      org.opencontainers.image.description="Collapse Wazuh vulnerability findings into a ranked patch plan." \
      org.opencontainers.image.licenses="Apache-2.0"

# Unbuffered so output still streams when stdout is a pipe rather than a tty,
# which is how a scheduler will always run this.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# A fixed high UID keeps file ownership predictable when a host directory is
# mounted for --evidence output.
RUN useradd --system --create-home --uid 10001 vulnfold

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

USER vulnfold
WORKDIR /home/vulnfold

# The image carries no default indexer, credentials or arguments: every
# deployment supplies its own, and a baked-in default would be a footgun.
ENTRYPOINT ["vulnfold"]
CMD ["--help"]
