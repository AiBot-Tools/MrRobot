# The aos worker image (egress plan I1): what every sandboxed run executes.
# NEEDS VALIDATION: written on Linux without Docker; built once by the operator.
#
# Built by scripts/build-worker-image.sh on the trusted VM and loaded into the
# hostile one, which prints the image's id. That id, pinned as sandbox.imageId
# in config/kernel.yaml, is what the driver runs (src/sandbox/docker.ts), with
# --pull=never, as --user 65534:65534 with a read-only root, --cap-drop=ALL,
# no-new-privileges, --network none, --init and a noexec tmpfs on /tmp. So no
# tag of this image is ever run, and no VM ever pulls one.
#
# Nothing here is a boundary. A run executes as the agent's uid, which can
# override every setting below (a git -c, its own ~/.gitconfig in /tmp, an
# env of its own) and replace the mux. They are what an honest worker needs to
# send each request where the kernel's egress engine can judge it: with
# --network none the one way out is 127.0.0.1:3128, the mux, and the mux
# carries each connection over the run's docker -i channel to the kernel, which
# decides, logs, and dials (images/worker/mux.mjs). Nothing in this image
# holds a credential: the kernel injects one, at its own edge, into a request
# it allowed. test/config-files.test.ts holds this file, images/worker/gitconfig
# and images/worker/.dockerignore to what is said here.
#
# The base is the operator's choice (2026-11-09): node:24-bookworm-slim, by the
# digest of its multi-platform index as Docker Hub served it on 2026-11-11
# (Node 24.22.2; linux/arm64/v8 sha256:5f07e73c8822c93b47ee85fa5e228d7f7b45d3107f8c749f97da46e472efbf91,
# linux/amd64 sha256:c0a93797ee78814ae6d32fcca2561fdbbe423149c3f5389aad32d86e9fd85bd4).
# The VMs are arm64, so their daemon takes the arm64 image from the index. To
# move it, put the index's new digest here (docker buildx imagetools inspect
# node:24-bookworm-slim prints it as Digest) and rebuild; the build script
# refuses a FROM that is not this base by a real digest, a placeholder included.
# Only the classic builder's subset of the syntax is used (no syntax directive,
# no heredoc, no --chmod), so the build pulls no frontend image and works
# whichever builder the docker CLI finds.
FROM node:24-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9

# git and a CA store from Debian bookworm, and nothing either merely
# recommends: git recommends an ssh client, less and patch, which no run uses
# (no route exists for ssh to take). As root, before USER, and before the
# proxy ENV below, which would send apt to a port nothing listens on at build
# time.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Git's system config (images/worker/gitconfig) and the mux, both root's and
# read-only to everyone else.
COPY gitconfig /etc/gitconfig
COPY mux.mjs /opt/aos/mux.mjs
RUN chmod 0755 /opt/aos \
 && chmod 0444 /etc/gitconfig /opt/aos/mux.mjs

# Every HTTP client a run uses sends its requests to the mux: git's libcurl
# reads the lower-case forms (libcurl ignores an upper-case HTTP_PROXY), and
# Node 24's fetch, http and https read them under NODE_USE_ENV_PROXY. There is
# no curl (the slim base purges it, and apt adds only git and a CA store). The
# port is kernel.yaml's egress.muxPort, which config.ts holds to 3128.
# NO_PROXY is empty: no host is reached any other way, and with --network none
# there is no other way; a request to a server the run itself listens on, on
# 127.0.0.1, goes to the mux too, and the kernel denies it.
# GIT_TERMINAL_PROMPT=0: git never waits on a username or password
# (the kernel answers an upstream 401 or 403 as 502 besides). HOME is the
# tmpfs, so nothing a run writes there outlives its container.
ENV HTTP_PROXY="http://127.0.0.1:3128" \
    HTTPS_PROXY="http://127.0.0.1:3128" \
    http_proxy="http://127.0.0.1:3128" \
    https_proxy="http://127.0.0.1:3128" \
    NO_PROXY="" \
    no_proxy="" \
    NODE_USE_ENV_PROXY="1" \
    GIT_TERMINAL_PROMPT="0" \
    HOME="/tmp"

# No entrypoint and no default command: a run's argv is exactly what the
# kernel passed after the image id, which a human approving a sandbox.exec is
# shown. The base's docker-entrypoint.sh would run a shell first, and run as
# `node <argv>` any program it cannot find on PATH.
ENTRYPOINT []

# The driver passes --user 65534:65534 as well; this is the same uid, so a
# container started any other way does not run as root either.
USER 65534:65534
