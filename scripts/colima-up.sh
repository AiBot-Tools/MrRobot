#!/usr/bin/env bash
# NEEDS VALIDATION: written on Linux without Colima; run once by the operator.
#
# Brings up the two sandbox VMs the Docker driver expects, one per trust
# domain, plus an INTERNAL docker network in each. Two VMs rather than two
# networks in one VM: a kernel escape from the hostile domain should not land
# in the same VM as the trusted one.
#
# Idempotent — re-running it starts what is stopped and leaves the rest alone.
#
# Each VM mounts ONLY that domain's mountRoot from config/kernel.yaml, writable,
# and nothing else. Never $HOME (invariant 9). Change a mountRoot in
# kernel.yaml and change it here; they are two halves of one statement.
#
# Everything this writes lives in the program folder (<repo>/.aos) or in
# ~/.colima, the one home directory the operator allowed: COLIMA_CACHE_HOME
# would otherwise default to ~/Library/Caches/colima and DOCKER_CONFIG to
# ~/.docker (Colima FAQ, "environment variables"). Export the same two in any
# shell where you run colima or docker by hand.
#
# A VM created earlier with the old ~/.aos mounts keeps them while it runs:
# `colima stop <profile>`, then re-run this script so the --mount below
# applies (if it does not, `colima delete <profile>` and re-run).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export DOCKER_CONFIG="${REPO_ROOT}/.aos/docker"
export COLIMA_CACHE_HOME="${HOME}/.colima/_cache"
mkdir -p "${DOCKER_CONFIG}" "${COLIMA_CACHE_HOME}"

CPUS="${AOS_COLIMA_CPUS:-4}"
MEMORY="${AOS_COLIMA_MEMORY:-8}"
DISK="${AOS_COLIMA_DISK:-60}"

# Keep in step with sandbox.domains.<name>.mountRoot in config/kernel.yaml.
TRUSTED_MOUNT="${REPO_ROOT}/.aos/workspaces/trusted"
HOSTILE_MOUNT="${REPO_ROOT}/.aos/workspaces/hostile"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: $1 is not installed" >&2
    exit 1
  }
}

need colima
need docker

up() {
  local profile="$1" mount="$2"

  mkdir -p "${mount}"

  if colima status "${profile}" >/dev/null 2>&1; then
    echo "colima profile ${profile} is already running"
  else
    echo "starting colima profile ${profile} (mount: ${mount})"
    # vz + virtiofs: the Virtualization.framework backend with the fast mount
    # type. FSEvents through virtiofs is the thing to check on first run — if
    # file watching inside a container does not see host writes, that is why.
    colima start "${profile}" \
      --vm-type vz \
      --mount-type virtiofs \
      --cpu "${CPUS}" \
      --memory "${MEMORY}" \
      --disk "${DISK}" \
      --mount "${mount}:w"
  fi

  # --internal: containers on this network reach each other and nothing else.
  # Egress belongs to the Phase 2 proxy sidecar, not to the default bridge.
  local network="aos-${profile}"
  if DOCKER_HOST="unix://${HOME}/.colima/${profile}/docker.sock" docker network inspect "${network}" >/dev/null 2>&1; then
    # An existing network is accepted only if it is internal. Inside the VM the
    # Mac's loopback is 192.168.5.2 (host.lima.internal), where pmmcp listens
    # unauthenticated; a network with a route out reaches it. Not deleted here:
    # removing a network is the operator's call. The kernel's probe refuses it
    # too, so the sandbox stays degraded until it is fixed.
    local internal
    internal="$(DOCKER_HOST="unix://${HOME}/.colima/${profile}/docker.sock" docker network inspect --format '{{.Internal}}' "${network}")"
    if [[ "${internal}" != "true" ]]; then
      echo "network ${network} exists but is NOT internal (Internal=${internal})." >&2
      echo "fix: DOCKER_HOST=unix://${HOME}/.colima/${profile}/docker.sock docker network rm ${network}  # then re-run this script" >&2
      exit 1
    fi
    echo "network ${network} already exists and is internal"
  else
    echo "creating internal network ${network}"
    DOCKER_HOST="unix://${HOME}/.colima/${profile}/docker.sock" docker network create --internal "${network}"
  fi
}

up trusted "${TRUSTED_MOUNT}"
up hostile "${HOSTILE_MOUNT}"

cat <<'EOF'

Done. Sockets the kernel expects (config/kernel.yaml, ~ expanded at parse):
  unix://~/.colima/trusted/docker.sock
  unix://~/.colima/hostile/docker.sock

Verify (in a shell with DOCKER_CONFIG exported as above):
  DOCKER_HOST=unix://$HOME/.colima/trusted/docker.sock docker info | head
  DOCKER_HOST=unix://$HOME/.colima/hostile/docker.sock docker network inspect --format '{{.Internal}}' aos-hostile
EOF
