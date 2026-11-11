#!/usr/bin/env bash
# NEEDS VALIDATION: written on Linux without Docker or Colima; run once by the operator.
#
# Builds the worker image (egress plan I1, images/worker/Dockerfile) on the
# trusted VM, copies it into the hostile VM with docker save | docker load,
# checks that both VMs hold it under one id, and prints that id: the value
# for sandbox.imageId in config/kernel.yaml. The driver runs the image only by
# that id, with --pull=never, so no VM ever pulls it, and one that lacks it
# leaves the sandbox degraded, naming that VM.
#
#   scripts/build-worker-image.sh
#
# On the Mac, from any directory, once scripts/colima-up.sh has both VMs up
# and npm ci has installed tsx. It takes no arguments. Its stdout is the id
# alone (docker's own output, and the line to paste, go to stderr).
#
# Before docker is asked anything, scripts/worker-image.ts reads two files and
# refuses what the build cannot proceed past: images/worker/Dockerfile, whose
# one FROM must be node:24-bookworm-slim pinned by a real digest (a
# placeholder digest is refused), and config/kernel.yaml, through the kernel's
# own parser, for each domain's dockerHost, the tag to give the image
# (sandbox.image) and the kernel's DOCKER_CONFIG (<dataDir>/docker,
# .aos/docker as shipped). Every docker command here gets exactly the
# environment the kernel's own docker calls get, DOCKER_CONFIG, DOCKER_HOST
# and PATH (src/sandbox/docker.ts), so no docker context, ~/.docker or
# exported DOCKER_* variable can point it elsewhere, and it never reaches the
# default Colima profile, which shares $HOME writable: a dockerHost that
# reaches that profile's socket, by any spelling or link to it on the Mac, or
# one socket for both domains, is refused. Any other socket is used as
# kernel.yaml names it, as the kernel uses it for every run.
#
# What it changes: on each VM, an image tagged sandbox.image (the tag moves
# off any image it named before, which stays until pruned), and on the
# trusted VM its build cache and the base image it pulls, anonymously and by
# digest. On the Mac, nothing but .aos/docker, made if missing. No credential
# is read or written anywhere: the build context is images/worker, of which
# its .dockerignore admits only the two files the Dockerfile copies.
set -euo pipefail

if [[ $# -ne 0 ]]; then
  echo "error: scripts/build-worker-image.sh takes no arguments" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTEXT="${REPO_ROOT}/images/worker"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: $1 is not installed" >&2
    exit 1
  }
}

need node
need docker

# 1. The plan, refused here when the base is not pinned by a real digest or
#    kernel.yaml names a socket the build may not use. No docker command runs
#    before this succeeds.
if ! plan="$(cd "${REPO_ROOT}" && node --import tsx scripts/worker-image.ts)"; then
  echo "error: nothing was built (scripts/worker-image.ts refused, above)" >&2
  exit 1
fi

BASE=''
IMAGE=''
TRUSTED_HOST=''
HOSTILE_HOST=''
AOS_DOCKER_CONFIG=''
while IFS= read -r line; do
  case "${line%%=*}" in
    BASE) BASE="${line#*=}" ;;
    IMAGE) IMAGE="${line#*=}" ;;
    TRUSTED_DOCKER_HOST) TRUSTED_HOST="${line#*=}" ;;
    HOSTILE_DOCKER_HOST) HOSTILE_HOST="${line#*=}" ;;
    DOCKER_CONFIG) AOS_DOCKER_CONFIG="${line#*=}" ;;
    *)
      echo "error: scripts/worker-image.ts printed a line this script does not read: ${line}" >&2
      exit 1
      ;;
  esac
done <<<"${plan}"
if [[ -z "${BASE}" || -z "${IMAGE}" || -z "${TRUSTED_HOST}" || -z "${HOSTILE_HOST}" || -z "${AOS_DOCKER_CONFIG}" ]]; then
  echo "error: scripts/worker-image.ts left a value out; nothing was built" >&2
  exit 1
fi

mkdir -p "${AOS_DOCKER_CONFIG}"

# The kernel's own docker environment (DockerDriver's #env): DOCKER_CONFIG,
# DOCKER_HOST and PATH, and nothing else from this shell.
dk() {
  local host="$1"
  shift
  env -i DOCKER_CONFIG="${AOS_DOCKER_CONFIG}" DOCKER_HOST="${host}" PATH="${PATH}" docker "$@"
}

# 2. Both daemons answer, before anything is built.
answers() {
  local domain="$1" host="$2" out
  if ! out="$(dk "${host}" version --format '{{.Server.Version}}' 2>&1)"; then
    echo "error: the ${domain} VM's docker daemon (${host}) does not answer: ${out}" >&2
    echo "fix: start both VMs with scripts/colima-up.sh, then run this again" >&2
    exit 1
  fi
}
answers trusted "${TRUSTED_HOST}"
answers hostile "${HOSTILE_HOST}"

# 3. Build on the trusted VM, the only one that runs a build step.
echo "building ${IMAGE} from ${BASE} on the trusted VM (${TRUSTED_HOST})" >&2
dk "${TRUSTED_HOST}" build --tag "${IMAGE}" --file "${CONTEXT}/Dockerfile" "${CONTEXT}" >&2

id="$(dk "${TRUSTED_HOST}" image inspect --format '{{.Id}}' "${IMAGE}")"
if [[ ! "${id}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "error: the trusted VM gives ${IMAGE} the id '${id}', not sha256:<64 hex>" >&2
  exit 1
fi

# The image runs as 65534:65534 with no entrypoint, as the Dockerfile says,
# whichever builder the docker CLI used.
runs="$(dk "${TRUSTED_HOST}" image inspect --format '{{.Config.User}} {{json .Config.Entrypoint}}' "${id}")"
case "${runs}" in
  '65534:65534 null' | '65534:65534 []') ;;
  *)
    echo "error: ${IMAGE} (${id}) has user and entrypoint '${runs}', not 65534:65534 and none; do not pin it" >&2
    exit 1
    ;;
esac

# 4. Into the hostile VM, which builds nothing itself.
echo "loading ${IMAGE} (${id}) into the hostile VM (${HOSTILE_HOST})" >&2
dk "${TRUSTED_HOST}" save "${IMAGE}" | dk "${HOSTILE_HOST}" load >&2

# 5. Each VM answers the probe's own question, docker image inspect by the id,
#    with that id: one sandbox.imageId must name the image on both.
holds() {
  local domain="$1" host="$2" got
  if ! got="$(dk "${host}" image inspect --format '{{.Id}}' "${id}" 2>&1)" || [[ "${got}" != "${id}" ]]; then
    echo "error: the ${domain} VM does not hold ${id} under that id (it answered: ${got})." >&2
    echo "docker save and docker load did not keep the id, so no one sandbox.imageId names the image on both VMs; do not pin it" >&2
    exit 1
  fi
}
holds trusted "${TRUSTED_HOST}"
holds hostile "${HOSTILE_HOST}"

echo "" >&2
echo "Both VMs hold ${IMAGE} as ${id}. Pin it in config/kernel.yaml, under sandbox:" >&2
echo "  imageId: ${id}" >&2
printf '%s\n' "${id}"
