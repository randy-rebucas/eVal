# Image for eVal terminal sessions: the user's shell runs here, with the audited code and the fix.
# Build: docker build -f sandbox/workspace.Dockerfile -t eval-sandbox-workspace:latest sandbox
# Add the toolchains your repositories need (e.g. Go, a JDK) by extending this image.
FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends git nodejs npm build-essential less nano vim-tiny ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --create-home --home-dir /home/sandbox --shell /bin/bash sandbox \
 && mkdir -p /workspace /eval/fix \
 && chown -R 1000:1000 /workspace /eval

COPY --chmod=0755 init.sh /usr/local/bin/eval-sandbox-init

USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/eval-sandbox-init"]
