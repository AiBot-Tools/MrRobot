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
set -euo pipefail

CPUS="${AOS_COLIMA_CPUS:-4}"
MEMORY="${AOS_COLIMA_MEMORY:-8}"
DISK="${AOS_COLIMA_DISK:-60}"

# Keep in step with sandbox.domains.<name>.mountRoot in config/kernel.yaml.
TRUSTED_MOUNT="${HOME}/.aos/workspaces/trusted"
HOSTILE_MOUNT="${HOME}/.aos/workspaces/hostile"

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
  if docker --context "colima-${profile}" network inspect "${network}" >/dev/null 2>&1; then
    echo "network ${network} already exists"
  else
    echo "creating internal network ${network}"
    docker --context "colima-${profile}" network create --internal "${network}"
  fi
}

up trusted "${TRUSTED_MOUNT}"
up hostile "${HOSTILE_MOUNT}"

cat <<'EOF'

Done. Sockets the kernel expects (config/kernel.yaml, ~ expanded at parse):
  unix://~/.colima/trusted/docker.sock
  unix://~/.colima/hostile/docker.sock

Verify:
  docker --context colima-trusted info | head
  docker --context colima-hostile network inspect aos-hostile
EOF
