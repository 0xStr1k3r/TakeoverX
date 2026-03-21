#!/usr/bin/env bash
# TakeoverX installer
#
# Installs a prebuilt binary from GitHub Releases. No compiler is required.
# Supports Debian/Ubuntu, Fedora/RHEL/CentOS, Arch, openSUSE, Alpine, and
# macOS (Intel and Apple Silicon).

set -Eeuo pipefail

REPO="0xStr1k3r/TakeoverX"
BINARY="takeoverx"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
MIN_GO="1.24"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'

info()    { printf '%s[*]%s %s\n' "$CYAN" "$RESET" "$*"; }
ok()      { printf '%s[+]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn()    { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
fail()    { printf '%s[x]%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }
step()    { printf '\n%s==>%s %s%s%s\n' "$CYAN" "$RESET" "$BOLD" "$*" "$RESET"; }

# shellcheck disable=SC2317  # invoked indirectly through the ERR trap
die() {
  printf '\n' >&2
  fail "$*"
  printf '%s   Installation aborted. Nothing was changed.%s\n' "$DIM" "$RESET" >&2
  exit 1
}

TMP_CLEANUP=""
# cleanup always succeeds: it runs from the EXIT trap, and a non-zero status
# there would become the script's exit code.
cleanup() {
  if [ -n "$TMP_CLEANUP" ]; then
    rm -rf "$TMP_CLEANUP"
  fi
  return 0
}
trap 'die "unexpected error on line $LINENO"' ERR
trap cleanup EXIT

# mktmp creates a scratch directory that is removed on exit, whichever path the
# script takes. Using one EXIT trap instead of nested RETURN traps matters:
# a function called later would otherwise overwrite the pending trap and leak
# the directory created by main.
mktmp() {
  TMP_CLEANUP="$(mktemp -d)"
  printf '%s' "$TMP_CLEANUP"
}

usage() {
  cat <<EOF
${BOLD}TakeoverX installer${RESET}

  install.sh [options]

  --check       verify an existing installation, then exit
  --force       reinstall even if takeoverx is already present
  --uninstall   remove the installed binary
  --dir PATH    install into PATH instead of $INSTALL_DIR
  --version V   install a specific release tag (default: latest)
  -h, --help    show this message

Examples
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | bash -s -- --dir ~/.local/bin
EOF
}

FORCE=0
CHECK_ONLY=0
UNINSTALL=0
VERSION=""

while [ $# -gt 0 ]; do
  case "$1" in
    --check)     CHECK_ONLY=1 ;;
    --force)     FORCE=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --dir)       [ $# -ge 2 ] || die "--dir needs a path"; INSTALL_DIR="$2"; shift ;;
    --version)   [ $# -ge 2 ] || die "--version needs a tag"; VERSION="$2"; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

printf '%s' "$CYAN"
cat <<'BANNER'
   _____              _          _              _
  |_   _|            | |        | |            | |
    | | __ _  ___ __ _| |__   ___| |_ ___   __ _| | __
    | |/ _` |/ __/ _` | '_ \ / _ \ __/ _ \ / _` |/ /
    | | (_| | (_| (_| | |_) |  __/ ||  __/ (_| |   <
    |_|\__,_|\___\__,_|_.__/ \___|\__\___|\__,_|_|\_\
BANNER
printf '%s' "$RESET"

# ── platform detection ───────────────────────────────────────────────────────

detect_os() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="arm64" ;;
    armv7l|armv7)  arch="armv7" ;;
    i386|i686)     arch="i386" ;;
    *) die "unsupported CPU architecture: $arch" ;;
  esac

  case "$os" in
    Linux)  OS="linux" ;;
    Darwin) OS="darwin" ;;
    *)      die "unsupported operating system: $os (this installer covers Linux and macOS)" ;;
  esac

  printf '%s %s\n' "$OS" "$arch"
}

# ── preflight ────────────────────────────────────────────────────────────────

preflight() {
  step "Checking prerequisites"

  if [ "$(uname -s)" != "Darwin" ]; then
    # Only needed when we fall back to building from source.
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
      fail "neither curl nor wget is installed; install one and re-run"
    fi
    ok "download tool: $(command -v curl >/dev/null 2>&1 && echo curl || echo wget)"
  else
    command -v curl >/dev/null 2>&1 || fail "curl is required on macOS"
    ok "download tool: curl"
  fi

  if [ ! -d "$INSTALL_DIR" ]; then
    info "creating $INSTALL_DIR"
    # Plain mkdir first: reaching for sudo by default creates a root-owned
    # directory that the current user then cannot write to.
    mkdir -p "$INSTALL_DIR" 2>/dev/null \
      || sudo -n mkdir -p "$INSTALL_DIR" 2>/dev/null \
      || die "cannot create $INSTALL_DIR — re-run with sudo or pass --dir"
  fi

  if [ ! -w "$INSTALL_DIR" ]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
      info "$INSTALL_DIR is not writable; sudo will be used for the copy"
    else
      die "$INSTALL_DIR is not writable — re-run with sudo or pass --dir"
    fi
  fi
  ok "install directory: $INSTALL_DIR"

  AVAILABLE_KB="$(df -Pk "$INSTALL_DIR" 2>/dev/null | awk 'NR==2{print $4}')"
  if [ -n "${AVAILABLE_KB:-}" ] && [ "$AVAILABLE_KB" -lt 10240 ]; then
    warn "only ${AVAILABLE_KB}KB free in $INSTALL_DIR"
  fi
}

fetch() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 "$url" -o "$out"
  else
    wget -q --tries=3 --timeout=20 -O "$out" "$url"
  fi
}

# ── existing install ─────────────────────────────────────────────────────────

check_install() {
  if command -v "$BINARY" >/dev/null 2>&1; then
    ok "already installed: $(command -v "$BINARY")"
    "$BINARY" --version 2>/dev/null || warn "the installed binary did not respond to --version"
  elif [ -x "$INSTALL_DIR/$BINARY" ]; then
    ok "already installed: $INSTALL_DIR/$BINARY"
  else
    info "not currently installed"
  fi
}

uninstall_it() {
  step "Removing $BINARY"
  local removed=0

  if [ -x "$INSTALL_DIR/$BINARY" ]; then
    rm -f "$INSTALL_DIR/$BINARY" && removed=1 && ok "removed $INSTALL_DIR/$BINARY"
  fi

  local other
  other="$(command -v "$BINARY" 2>/dev/null || true)"
  if [ -n "$other" ] && [ "$other" != "$INSTALL_DIR/$BINARY" ]; then
    if [ "$removed" -eq 0 ]; then rm -f "$other" && ok "removed $other"; fi
  fi

  if [ "$removed" -eq 0 ] && [ -z "${other:-}" ]; then
    info "nothing to remove"
  else
    ok "$BINARY has been uninstalled"
  fi
}

# ── install ──────────────────────────────────────────────────────────────────

resolve_version() {
  if [ -n "$VERSION" ]; then
    printf '%s' "$VERSION"
    return
  fi
  local tag
  tag="$(fetch "https://api.github.com/repos/$REPO/releases/latest" - | \
        grep -m1 '"tag_name"' | cut -d'"' -f4 || true)"
  [ -n "$tag" ] || die "could not determine the latest release; pass --version"
  printf '%s' "$tag"
}

build_from_source() {
  step "Building from source"

  command -v go >/dev/null 2>&1 || die "no prebuilt binary for $OS/$ARCH and Go is not installed.
  Install Go ${MIN_GO}+ from https://go.dev/dl/ and re-run."

  local have
  have="$(go version | awk '{print $3}')"
  info "found Go $have"
  if [ "$(printf '%s\n%s\n' "$MIN_GO" "$have" | sort -V | head -1)" != "$MIN_GO" ]; then
    die "Go $have is too old; $MIN_GO or newer is required"
  fi

  local tmp
  tmp="$(mktmp)"

  info "cloning source"
  if command -v git >/dev/null 2>&1; then
    git clone --depth 1 --branch "$TAG" "https://github.com/$REPO.git" "$tmp/src" >/dev/null 2>&1 \
      || die "clone failed — check network access to github.com"
  else
    fail "git is required to build from source"
  fi

  step "Compiling"
  ( cd "$tmp/src" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$tmp/$BINARY" . ) \
    || die "compilation failed"
  ok "built $tmp/$BINARY"

  install_binary "$tmp/$BINARY"
}

install_binary() {
  local src="$1"
  local dest="$INSTALL_DIR/$BINARY"

  step "Installing"
  if cp "$src" "$dest" 2>/dev/null; then
    chmod 0755 "$dest"
  elif command -v sudo >/dev/null 2>&1; then
    info "no write permission in $INSTALL_DIR, using sudo"
    sudo -n cp "$src" "$dest" || die "installation failed"
    sudo -n chmod 0755 "$dest"
  else
    die "cannot write to $INSTALL_DIR — re-run with sudo or pass --dir"
  fi
  ok "installed $dest"
}

main() {
  # --uninstall and --check never touch the network or the filesystem.
  if [ "$UNINSTALL" -eq 1 ]; then
    uninstall_it
    return
  fi
  if [ "$CHECK_ONLY" -eq 1 ]; then
    step "Checking installation"
    check_install
    return
  fi

  local existing=""
  existing="$(command -v "$BINARY" 2>/dev/null || true)"
  if [ -n "$existing" ] && [ "$FORCE" -eq 0 ]; then
    ok "$BINARY is already installed at $existing"
    "$existing" --version 2>/dev/null || true
    info "re-run with --force to reinstall"
    return
  fi

  read -r OS ARCH <<<"$(detect_os)"
  step "Platform detected"
  info "os: $OS"
  info "architecture: $ARCH"

  preflight

  step "Resolving release"
  TAG="$(resolve_version)"
  ok "version: $TAG"

  local tmp
  tmp="$(mktmp)"

  local archive="takeoverx_${TAG#v}_${OS}_${ARCH}.tar.gz"
  local url="https://github.com/$REPO/releases/download/$TAG/$archive"

  step "Downloading"
  info "$archive"
  if ! fetch "$url" "$tmp/$archive"; then
    warn "no prebuilt binary for $OS/$ARCH at this release"
    build_from_source
    return
  fi
  ok "downloaded $(du -h "$tmp/$archive" | cut -f1)"

  step "Verifying archive"
  tar -tzf "$tmp/$archive" >/dev/null 2>&1 || die "downloaded archive is corrupt"
  ok "archive is valid"

  tar -xzf "$tmp/$archive" -C "$tmp" "$BINARY" 2>/dev/null \
    || tar -xzf "$tmp/$archive" -C "$tmp"
  [ -f "$tmp/$BINARY" ] || die "archive did not contain a '$BINARY' binary"
  chmod 0755 "$tmp/$BINARY"

  install_binary "$tmp/$BINARY"

  step "Verifying installation"
  "$INSTALL_DIR/$BINARY" --version >/dev/null 2>&1 \
    || die "the installed binary does not run"
  ok "$("$INSTALL_DIR/$BINARY" --version)"

  printf '\n'
  ok "$BINARY is ready"
  printf '   Try:  %s -d example.com --passive\n\n' "$BINARY"
}

main "$@"