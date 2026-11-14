#!/usr/bin/env bash
# NEEDS VALIDATION: written on Linux without Colima; run once by the operator.
#
# Brings up the two sandbox VMs the Docker driver expects, one per trust
# domain, plus an INTERNAL docker network in each. Two VMs rather than two
# networks in one VM: a kernel escape from the hostile domain should not land
# in the same VM as the trusted one. The VMs still share one Lima user-v2
# network (one `limactl usernet` process on 192.168.5.0/24), so the hostile VM
# can reach the trusted VM's addresses, and both reach every port on the Mac's
# loopback through 192.168.5.2 (README "Sandbox checks on the Mac").
#
# Idempotent — re-running it starts what is stopped and leaves the rest alone.
# It fails, before it touches a VM's network or prints Done., unless `colima
# status` succeeds after the start and the VM has one host share, mounted over
# virtiofs at its mountRoot's path: on a VM that is running but whose first
# start never finished, `colima status` fails and `colima start` answers
# "already running, ignoring" and exits 0, with none of the mounts or sizes
# below applied (seen on 2026-10-21). Which directory of the Mac that one
# share is, the script cannot read from inside the VM: /proc/mounts names a
# virtiofs share by Lima's tag (mount0), not by its Mac path. It reads where
# the share is mounted, and the --mount below is what puts the mountRoot
# there; a profile whose own Colima config mounts another directory ($HOME,
# say) at the mountRoot's path would pass.
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
# A VM created earlier with other mounts (the old ~/.aos ones) keeps them while
# it runs, and this script refuses it, naming where each of its shares is
# mounted: `colima stop <profile>`, then re-run this script so the --mount
# below applies (if it does not, `colima delete <profile>` and re-run).
#
# Every colima command here names its profile: never Colima's default one,
# which with no --mount shares $HOME writable.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export DOCKER_CONFIG="${REPO_ROOT}/.aos/docker"
export COLIMA_CACHE_HOME="${HOME}/.colima/_cache"
mkdir -p "${DOCKER_CONFIG}" "${COLIMA_CACHE_HOME}"

# The sizes the VMs were made and checked with (README "Sandbox checks on the
# Mac": 4 CPUs, 4 GiB and 60 GiB each); MEMORY is in GiB.
CPUS="${AOS_COLIMA_CPUS:-4}"
MEMORY="${AOS_COLIMA_MEMORY:-4}"
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
need awk

# The VM's host shares, read from its own /proc/mounts: each virtiofs, 9p or
# sshfs mount there is a directory of the Mac the VM writes as the operator
# (README "Sandbox checks on the Mac"). It passes only when there is exactly
# one, mounted over virtiofs at the domain's mountRoot, as recorded on
# 2026-10-21, and prints where each share it reads is mounted. Only the mount
# point ($2) is read: a virtiofs entry's source ($1) is Lima's tag, not the
# Mac directory shared. /proc/mounts writes a space, tab, newline or backslash
# in a path as \040, \011, \012 or \134, read back here before the path is
# compared, whole, to the mountRoot, which comes from the environment so that
# awk reads no escape in it.
SHARES_AWK='
function unmangle(s,   out, i, code) {
  out = ""
  for (i = 1; i <= length(s); i++) {
    code = substr(s, i, 4)
    if (code == "\\040") { out = out " "; i += 3 }
    else if (code == "\\011") { out = out "\t"; i += 3 }
    else if (code == "\\012") { out = out "\n"; i += 3 }
    else if (code == "\\134") { out = out "\\"; i += 3 }
    else out = out substr(s, i, 1)
  }
  return out
}
{
  if ($3 == "virtiofs" || $3 == "9p" || $3 == "fuse.sshfs") {
    shares++
    path = unmangle($2)
    print "  " $3 " " path
    if ($3 == "virtiofs" && path == ENVIRON["MOUNT_ROOT"]) own++
  }
}
END { exit (shares == 1 && own == 1 ? 0 : 1) }
'

# Fails the script unless the profile's VM has one host share, mounted over
# virtiofs at its mountRoot, naming where each share it has is mounted.
one_share_at_root() {
  local profile="$1" mount="$2" mounts found
  if ! mounts="$(colima ssh --profile "${profile}" -- cat /proc/mounts </dev/null)"; then
    echo "error: could not read /proc/mounts in colima profile ${profile}: colima ssh --profile ${profile} failed" >&2
    exit 1
  fi
  if found="$(printf '%s\n' "${mounts}" | MOUNT_ROOT="${mount}" LC_ALL=C awk "${SHARES_AWK}")"; then
    echo "colima profile ${profile} has one host share, mounted at ${mount} (virtiofs)"
    return 0
  fi
  echo "error: colima profile ${profile} must have one host share, mounted over virtiofs at its mountRoot, ${mount}; its host shares are mounted at:" >&2
  printf '%s\n' "${found:-  nothing}" >&2
  echo "fix: colima stop ${profile}, then re-run this script so its --mount applies; if the shares stay wrong, colima delete ${profile} and re-run" >&2
  exit 1
}

up() {
  local profile="$1" mount="$2"

  mkdir -p "${mount}"

  # colima status and colima ssh read nothing: each is given /dev/null, so
  # neither takes the operator's terminal or whatever was piped to the script.
  if colima status "${profile}" >/dev/null 2>&1 </dev/null; then
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

  # Asked again whichever branch ran: a VM whose first start never finished
  # fails `colima status` while `colima start` exits 0 on it.
  local status
  if ! status="$(colima status "${profile}" 2>&1 </dev/null)"; then
    echo "error: colima profile ${profile} is not running after the start: colima status ${profile} failed:" >&2
    printf '%s\n' "${status}" >&2
    echo "fix: colima stop ${profile}, then re-run this script; if colima status ${profile} still fails, colima delete ${profile} and re-run" >&2
    exit 1
  fi

  one_share_at_root "${profile}" "${mount}"

  # --internal: containers on this network reach each other and nothing else.
  # No worker is attached to it: every run is --network none, and a worker's
  # one way out is the kernel's egress engine, over its run's docker -i
  # channel. The network is kept, and the kernel's probe still proves it
  # internal, as defence in depth.
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
