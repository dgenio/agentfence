#!/bin/sh
# AgentFence installer (issue #105).
#
# Detects your OS/arch, downloads the matching release archive from GitHub,
# verifies it against the release checksums.txt, and installs the agentfence
# binary. It fails closed on a checksum mismatch.
#
#   curl -fsSL https://raw.githubusercontent.com/dgenio/agentfence/main/scripts/install.sh | sh
#
# Pin a version or change the install dir with environment variables:
#   AGENTFENCE_VERSION=v0.8.0 AGENTFENCE_INSTALL_DIR=/usr/local/bin sh install.sh
#
# Honors no telemetry: the script only contacts the GitHub releases API/CDN.
set -eu

REPO="dgenio/agentfence"
BINARY="agentfence"
INSTALL_DIR="${AGENTFENCE_INSTALL_DIR:-${HOME}/.local/bin}"
VERSION="${AGENTFENCE_VERSION:-latest}"

die() {
	echo "install.sh: $*" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# Prefer curl, fall back to wget.
download() {
	# download <url> <dest>
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$2" "$1"
	else
		die "need curl or wget to download files"
	fi
}

need uname
need tar

# Map uname output to goreleaser's archive naming (Os/Arch from .goreleaser.yml).
os="$(uname -s)"
arch="$(uname -m)"
case "${os}" in
Linux) os="linux" ;;
Darwin) os="darwin" ;;
*) die "unsupported OS: ${os} (use the Windows archive or 'go install')" ;;
esac
case "${arch}" in
x86_64 | amd64) arch="amd64" ;;
arm64 | aarch64) arch="arm64" ;;
*) die "unsupported architecture: ${arch}" ;;
esac

# Resolve the version tag.
if [ "${VERSION}" = "latest" ]; then
	need sed
	api="https://api.github.com/repos/${REPO}/releases/latest"
	tmp_tag="$(mktemp)"
	download "${api}" "${tmp_tag}"
	VERSION="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${tmp_tag}" | head -n1)"
	rm -f "${tmp_tag}"
	[ -n "${VERSION}" ] || die "could not resolve the latest release tag"
fi

# goreleaser archive name_template: agentfence_<version>_<os>_<arch> (no leading v).
ver_noprefix="${VERSION#v}"
archive="${BINARY}_${ver_noprefix}_${os}_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${VERSION}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

echo "install.sh: downloading ${archive} (${VERSION})"
download "${base}/${archive}" "${workdir}/${archive}"
download "${base}/checksums.txt" "${workdir}/checksums.txt"

# Verify the checksum, failing closed on mismatch. Match the filename as an
# exact field (not a regex) so the dots in the archive name cannot match
# unintended lines; checksums.txt rows are "<sha256>  <filename>".
echo "install.sh: verifying checksum"
expected="$(awk -v f="${archive}" '$2 == f {print $1}' "${workdir}/checksums.txt")"
[ -n "${expected}" ] || die "no checksum entry for ${archive} in checksums.txt"
case "${expected}" in
*[!0-9a-fA-F]* | "") die "unexpected checksum value for ${archive}" ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
	actual="$(sha256sum "${workdir}/${archive}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
	actual="$(shasum -a 256 "${workdir}/${archive}" | awk '{print $1}')"
else
	die "need sha256sum or shasum to verify the download"
fi

if [ "${expected}" != "${actual}" ]; then
	die "checksum mismatch for ${archive}: expected ${expected}, got ${actual}"
fi

# Extract and install.
tar -xzf "${workdir}/${archive}" -C "${workdir}"
[ -f "${workdir}/${BINARY}" ] || die "archive did not contain ${BINARY}"

mkdir -p "${INSTALL_DIR}"
install -m 0755 "${workdir}/${BINARY}" "${INSTALL_DIR}/${BINARY}" 2>/dev/null ||
	{ cp "${workdir}/${BINARY}" "${INSTALL_DIR}/${BINARY}" && chmod 0755 "${INSTALL_DIR}/${BINARY}"; }

echo "install.sh: installed ${BINARY} ${VERSION} to ${INSTALL_DIR}/${BINARY}"
case ":${PATH}:" in
*":${INSTALL_DIR}:"*) ;;
*) echo "install.sh: note: ${INSTALL_DIR} is not on your PATH" ;;
esac
