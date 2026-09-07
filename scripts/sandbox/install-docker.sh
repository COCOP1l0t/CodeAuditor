#!/usr/bin/env bash
# Fresh Ubuntu installations only. Existing engines are never upgraded here.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install-docker.sh [--dry-run | --apply]

Install Docker Engine from Docker's official Ubuntu apt repository.
Default: print the plan. --apply requires root and can start system services.
Supported: Ubuntu 22.04 / 24.04 / 26.04, amd64 / arm64.
Existing Docker or conflicting packages must be managed separately.
EOF
}

apply=false
case "${1:---dry-run}" in
  --dry-run) ;;
  --apply) apply=true ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
if (( $# > 1 )); then usage >&2; exit 2; fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ "$ID" != ubuntu || ! "$VERSION_ID" =~ ^(22\.04|24\.04|26\.04)$ ]]; then
  echo 'Use the installation instructions for your distribution: https://docs.docker.com/engine/install/' >&2
  exit 1
fi
arch=$(dpkg --print-architecture)
if [[ "$arch" != amd64 && "$arch" != arm64 ]]; then
  echo "Unsupported architecture for this tutorial: $arch" >&2
  exit 1
fi
if command -v docker >/dev/null; then
  echo 'Docker CLI already exists. Check the existing daemon with sandboxctl.py check; this installer does not upgrade it.'
  exit 0
fi
for package in docker-ce docker-ce-cli docker.io docker-compose docker-compose-v2 docker-doc docker-buildx podman-docker containerd containerd.io runc; do
  if [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" == 'install ok installed' ]]; then
    echo "Existing package $package requires operator review; no packages were removed." >&2
    exit 1
  fi
done

repo_file=/etc/apt/sources.list.d/docker.sources
key_file=/etc/apt/keyrings/docker.asc
repo_text="Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: $arch
Signed-By: $key_file"
cat <<EOF
Plan for a fresh Docker installation:
  apt-get update
  apt-get install -y ca-certificates curl
  Download Docker's signing key to $key_file
  Write $repo_file:
$repo_text
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
Package installation may start Docker/containerd services. No users are added to the docker group.
EOF
if ! $apply; then
  echo 'Preview only. Re-run with sudo and --apply to install.'
  exit 0
fi
if (( EUID != 0 )); then echo '--apply requires root.' >&2; exit 1; fi
for path in "$repo_file" "$key_file" /etc/apt/sources.list.d/docker.list; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "Existing repository file needs review: $path. Nothing was overwritten." >&2
    exit 1
  fi
done

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl
download_dir=$(mktemp -d)
trap 'rm -rf -- "$download_dir"' EXIT
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
  --connect-timeout 15 --max-time 120 \
  https://download.docker.com/linux/ubuntu/gpg -o "$download_dir/docker.asc"
install -D -m 0644 "$download_dir/docker.asc" "$key_file"
printf '%s\n' "$repo_text" > "$download_dir/docker.sources"
install -D -m 0644 "$download_dir/docker.sources" "$repo_file"
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
echo 'Docker packages installed. Verify service state and the CodeAuditor service user permissions as described in docs/sandbox.md.'
