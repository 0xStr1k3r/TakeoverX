#!/usr/bin/env bash
# ============================================================
#  TakeoverX — Installation Script
#  Supports: Debian/Ubuntu, Arch Linux, RHEL/Fedora/CentOS,
#            openSUSE, Alpine, macOS (Homebrew / direct)
# ============================================================

set -euo pipefail

TOOL_NAME="takeoverx"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/bin"
MIN_GO_VERSION="1.21"

# ── Colours ───────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

# ── Banner ────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
  ████████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██╗   ██╗███████╗██████╗ ██╗  ██╗
  ╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗╚██╗██╔╝
     ██║   ███████║█████╔╝ █████╗  ██║   ██║██║   ██║█████╗  ██████╔╝ ╚███╔╝
     ██║   ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗ ██╔██╗
     ██║   ██║  ██║██║  ██╗███████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██╔╝ ██╗
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
BANNER
echo -e "${RESET}"
echo -e "${BOLD}  TakeoverX Installer${RESET}"
echo "  ─────────────────────────────────────────────────────"
echo ""

# ── OS Detection ──────────────────────────────────────────
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "${ID_LIKE:-$ID}" in
            *debian*|*ubuntu*)   echo "debian" ;;
            *arch*|*manjaro*)    echo "arch"   ;;
            *rhel*|*fedora*|*centos*|*rocky*|*almalinux*) echo "rhel" ;;
            *suse*)              echo "suse"   ;;
            *alpine*)            echo "alpine" ;;
            *)
                # Fallback: check ID directly
                case "$ID" in
                    ubuntu|debian|linuxmint|pop) echo "debian" ;;
                    arch|manjaro|endeavouros)    echo "arch"   ;;
                    fedora|rhel|centos|rocky|alma) echo "rhel" ;;
                    opensuse*|sles)              echo "suse"   ;;
                    alpine)                      echo "alpine" ;;
                    *)                           echo "unknown" ;;
                esac
                ;;
        esac
    elif [[ -f /etc/arch-release ]]; then
        echo "arch"
    elif [[ -f /etc/fedora-release ]]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

# ── Version Comparison ────────────────────────────────────
version_gte() {
    # Returns 0 (true) if $1 >= $2
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# ── Install Go ────────────────────────────────────────────
install_go() {
    local os_type="$1"
    info "Installing Go compiler..."

    case "$os_type" in
        debian)
            sudo apt-get update -qq
            # Try golang-go first, fall back to snap if version too old
            sudo apt-get install -y golang-go 2>/dev/null || true
            ;;
        arch)
            sudo pacman -Sy --noconfirm go
            ;;
        rhel)
            if command -v dnf &>/dev/null; then
                sudo dnf install -y golang
            else
                sudo yum install -y golang
            fi
            ;;
        suse)
            sudo zypper install -y go
            ;;
        alpine)
            sudo apk add --no-cache go
            ;;
        macos)
            if command -v brew &>/dev/null; then
                brew install go
            else
                error "Homebrew not found. Install it from https://brew.sh then re-run this script."
            fi
            ;;
        *)
            warn "Unknown OS. Please install Go manually from https://go.dev/dl/"
            error "Cannot proceed without Go >= ${MIN_GO_VERSION}"
            ;;
    esac
}

install_go_tarball() {
    # Install latest Go from official tarball (fallback for old distro packages)
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv6l)  arch="armv6l" ;;
        i686|i386) arch="386" ;;
        *) error "Unsupported architecture: $arch" ;;
    esac

    local os_label="linux"
    [[ "$OSTYPE" == "darwin"* ]] && os_label="darwin"

    local go_version
    go_version=$(curl -sSL "https://go.dev/VERSION?m=text" | head -1)
    local tarball="${go_version}.${os_label}-${arch}.tar.gz"
    local url="https://go.dev/dl/${tarball}"

    info "Downloading ${tarball}..."
    local tmp_dir
    tmp_dir=$(mktemp -d)
    curl -sSL "$url" -o "${tmp_dir}/${tarball}"

    info "Extracting to /usr/local/go ..."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "${tmp_dir}/${tarball}"
    rm -rf "$tmp_dir"

    export PATH="/usr/local/go/bin:$PATH"
    # Persist in profile
    if ! grep -q '/usr/local/go/bin' /etc/profile.d/go.sh 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh > /dev/null
    fi
    success "Go ${go_version} installed via tarball."
}

# ── Check/install Go ──────────────────────────────────────
OS_TYPE=$(detect_os)
info "Detected OS family: ${OS_TYPE}"

if command -v go &>/dev/null; then
    CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
    info "Found Go ${CURRENT_GO}"
    if version_gte "$CURRENT_GO" "$MIN_GO_VERSION"; then
        success "Go version is sufficient (>= ${MIN_GO_VERSION})."
    else
        warn "Go ${CURRENT_GO} is too old (need >= ${MIN_GO_VERSION}). Installing newer version..."
        install_go_tarball
    fi
else
    warn "Go not found. Installing..."
    install_go "$OS_TYPE"
    # If package manager version is still too old, use tarball
    if command -v go &>/dev/null; then
        CURRENT_GO=$(go version | awk '{print $3}' | sed 's/go//')
        if ! version_gte "$CURRENT_GO" "$MIN_GO_VERSION"; then
            warn "Package manager provided Go ${CURRENT_GO}, which is too old. Fetching from go.dev..."
            install_go_tarball
        fi
    else
        install_go_tarball
    fi
fi

# Ensure go is in PATH
export PATH="$PATH:/usr/local/go/bin:$(go env GOPATH)/bin"

# ── Install git (required for go get) ────────────────────
if ! command -v git &>/dev/null; then
    info "Installing git..."
    case "$OS_TYPE" in
        debian) sudo apt-get install -y git ;;
        arch)   sudo pacman -Sy --noconfirm git ;;
        rhel)   command -v dnf &>/dev/null && sudo dnf install -y git || sudo yum install -y git ;;
        suse)   sudo zypper install -y git ;;
        alpine) sudo apk add --no-cache git ;;
        macos)  brew install git ;;
        *) warn "Cannot install git automatically. Please install it manually." ;;
    esac
fi

# ── Build ─────────────────────────────────────────────────
info "Building ${TOOL_NAME}..."
cd "$REPO_DIR"

# Download dependencies
go mod tidy

# Build single static binary
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o "${TOOL_NAME}" .

success "Binary built: ${REPO_DIR}/${TOOL_NAME}"

# ── Install binary ────────────────────────────────────────
info "Installing to ${INSTALL_DIR}/${TOOL_NAME} ..."
if [[ -w "$INSTALL_DIR" ]]; then
    cp "${TOOL_NAME}" "${INSTALL_DIR}/${TOOL_NAME}"
else
    sudo cp "${TOOL_NAME}" "${INSTALL_DIR}/${TOOL_NAME}"
fi
sudo chmod +x "${INSTALL_DIR}/${TOOL_NAME}"

# ── Verify ────────────────────────────────────────────────
if command -v "${TOOL_NAME}" &>/dev/null; then
    success "${TOOL_NAME} installed successfully at $(command -v ${TOOL_NAME})"
else
    warn "Binary copied but not found in PATH. Add ${INSTALL_DIR} to your PATH:"
    echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
fi

echo ""
echo -e "${BOLD}Usage examples:${RESET}"
echo "  ${TOOL_NAME} -d sub.example.com"
echo "  ${TOOL_NAME} -w subdomains.txt -c 100"
echo "  ${TOOL_NAME} -w subdomains.txt -o table"
echo "  ${TOOL_NAME} -w subdomains.txt --report report.html"
echo "  ${TOOL_NAME} -w subdomains.txt -o csv > results.csv"
echo "  ${TOOL_NAME} -w subdomains.txt -c 200 -t 10 --only-vuln"
echo "  ${TOOL_NAME} --version"
echo ""
success "Done! Happy hunting 🎯"
