# syntax=docker/dockerfile:1.7
# eVal image used for both the web process and the Celery worker.
FROM python:3.12-slim-bookworm AS base

ARG INSTALL_SEMGREP=true
ARG INSTALL_NODE_TOOLS=true
ARG INSTALL_TRIVY=true
ARG TRIVY_VERSION=0.75.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && if [ "$INSTALL_NODE_TOOLS" = "true" ]; then apt-get install -y --no-install-recommends nodejs npm; fi \
 && rm -rf /var/lib/apt/lists/*

# Static analysis toolchain. Tools are optional at runtime: eVal reports any that are missing.
RUN pip install "ruff>=0.6" "bandit>=1.7.9" "mypy>=1.11" \
 && if [ "$INSTALL_SEMGREP" = "true" ]; then pip install "semgrep>=1.90"; fi
RUN if [ "$INSTALL_NODE_TOOLS" = "true" ]; then \
      npm install -g --ignore-scripts eslint@9 typescript@5 && npm cache clean --force; \
    fi
# Trivy: release tarball verified against the release checksum file.
RUN if [ "$INSTALL_TRIVY" = "true" ]; then \
      cd /tmp \
      && curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      && curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" \
      && grep " trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c - \
      && tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy && mv trivy /usr/local/bin/ \
      && rm -f /tmp/trivy_*; \
    fi

WORKDIR /app
COPY pyproject.toml README.md ./
COPY eval_engine ./eval_engine
COPY eval_app ./eval_app
RUN pip install ".[ai]" gunicorn
COPY migrations ./migrations
COPY wsgi.py ./

RUN useradd --create-home --uid 10001 eval \
 && mkdir -p /data /work /trivy-cache && chown eval:eval /data /work /trivy-cache
USER eval

ENV EVAL_DATA_DIR=/data \
    EVAL_WORK_DIR=/work \
    FLASK_APP=wsgi.py

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--access-logfile", "-", "wsgi:app"]
