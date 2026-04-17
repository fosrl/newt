#!/bin/sh

# Get Newt - Cross-platform installation script
# Usage: curl -fsSL https://raw.githubusercontent.com/fosrl/newt/refs/heads/main/get-newt.sh | sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# GitHub repository info
REPO="fosrl/newt"
GITHUB_API_URL="https://api.github.com/repos/${REPO}/releases/latest"

# Function to print colored output
print_status() {
    printf '%b[INFO]%b %s\n' "${GREEN}" "${NC}" "$1"
}

print_warning() {
    printf '%b[WARN]%b %s\n' "${YELLOW}" "${NC}" "$1"
}

print_error() {
    printf '%b[ERROR]%b %s\n' "${RED}" "${NC}" "$1"
}

# Function to get latest version from GitHub API
get_latest_version() {
    latest_info=""

    if command -v curl >/dev/null 2>&1; then
        latest_info=$(curl -fsSL "$GITHUB_API_URL" 2>/dev/null)
    elif command -v wget >/dev/null 2>&1; then
        latest_info=$(wget -qO- "$GITHUB_API_URL" 2>/dev/null)
    else
        print_error "Neither curl nor wget is available."
        exit 1
    fi

    if [ -z "$latest_info" ]; then
        print_error "Failed to fetch latest version info"
        exit 1
    fi

    version=$(printf '%s' "$latest_info" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

    if [ -z "$version" ]; then
        print_error "Could not parse version from GitHub API response"
        exit 1
    fi

    version=$(printf '%s' "$version" | sed 's/^v//')
    printf '%s' "$version"
}

# Detect OS and architecture
detect_platform() {
    os=""
    arch=""

    case "$(uname -s)" in
        Linux*)     os="linux" ;;
        Darwin*)    os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        FreeBSD*)   os="freebsd" ;;
        *)
            print_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)   arch="amd64" ;;
        arm64|aarch64)  arch="arm64" ;;
        armv7l|armv6l)
            if [ "$os" = "linux" ]; then
                if [ "$(uname -m)" = "armv6l" ]; then
                    arch="arm32v6"
                else
                    arch="arm32"
                fi
            else
                arch="arm64"
            fi
            ;;
        riscv64)
            if [ "$os" = "linux" ]; then
                arch="riscv64"
            else
                print_error "RISC-V architecture only supported on Linux"
                exit 1
            fi
            ;;
        *)
            print_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac

    printf '%s_%s' "$os" "$arch"
}

# Determine installation directory (default fallback)
get_install_dir() {
    case "$PLATFORM" in
        *windows*)
            echo "$HOME/bin"
            ;;
        *)
            echo "/usr/local/bin"
            ;;
    esac
}

# Parse --path argument from args
# Returns the value after --path, or empty string if not provided
parse_path_arg() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --path)
                if [ -n "$2" ]; then
                    printf '%s' "$2"
                    return
                fi
                ;;
            --path=*)
                printf '%s' "${1#--path=}"
                return
                ;;
        esac
        shift
    done
}

# Detect an existing newt binary location.
# Tries unprivileged which first, then sudo which (for binaries only visible to root).
# Returns the full path of the binary, or empty string if not found.
detect_existing_binary() {
    existing=""

    # Try unprivileged which first
    existing=$(command -v newt 2>/dev/null || true)
    if [ -n "$existing" ]; then
        printf '%s' "$existing"
        return
    fi

    # Try sudo which — some installations land in paths only root can see in $PATH
    if command -v sudo >/dev/null 2>&1; then
        existing=$(sudo which newt 2>/dev/null || true)
        if [ -n "$existing" ]; then
            printf '%s' "$existing"
            return
        fi
    fi
}

# Check if we need sudo for installation
needs_sudo() {
    install_dir="$1"
    if [ -w "$install_dir" ] 2>/dev/null; then
        return 1  # No sudo needed
    else
        return 0  # Sudo needed
    fi
}

# Get the appropriate command prefix (sudo or empty)
get_sudo_cmd() {
    install_dir="$1"
    if needs_sudo "$install_dir"; then
        if command -v sudo >/dev/null 2>&1; then
            echo "sudo"
        else
            print_error "Cannot write to ${install_dir} and sudo is not available."
            print_error "Please run this script as root or install sudo."
            exit 1
        fi
    else
        echo ""
    fi
}

# Download and install newt
install_newt() {
    platform="$1"
    install_dir="$2"
    sudo_cmd="$3"
    custom_path="$4"
    binary_name="newt_${platform}"
    final_name="newt"

    case "$platform" in
        *windows*)
            binary_name="${binary_name}.exe"
            final_name="newt.exe"
            ;;
    esac

    download_url="${BASE_URL}/${binary_name}"
    temp_file="/tmp/${final_name}"

    # If a custom path is provided, use it directly; otherwise use install_dir/final_name
    if [ -n "$custom_path" ]; then
        final_path="$custom_path"
        install_dir=$(dirname "$final_path")
    else
        final_path="${install_dir}/${final_name}"
    fi

    print_status "Downloading newt from ${download_url}"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$download_url" -o "$temp_file"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$download_url" -O "$temp_file"
    else
        print_error "Neither curl nor wget is available."
        exit 1
    fi

    # Make executable before moving
    chmod +x "$temp_file"

    # Create install directory if it doesn't exist and move binary
    if [ -n "$sudo_cmd" ]; then
        $sudo_cmd mkdir -p "$install_dir"
        print_status "Using sudo to install to ${install_dir}"
        $sudo_cmd mv "$temp_file" "$final_path"
    else
        mkdir -p "$install_dir"
        mv "$temp_file" "$final_path"
    fi

    print_status "newt installed to ${final_path}"

    # Check if install directory is in PATH
    if ! echo "$PATH" | grep -q "$install_dir"; then
        print_warning "Install directory ${install_dir} is not in your PATH."
        print_warning "Add it with:"
        print_warning "  export PATH=\"${install_dir}:\$PATH\""
    fi
}

# Verify installation
verify_installation() {
    install_dir="$1"
    exe_suffix=""

    case "$PLATFORM" in
        *windows*) exe_suffix=".exe" ;;
    esac

    newt_path="${install_dir}/newt${exe_suffix}"

    if [ -x "$newt_path" ]; then
        print_status "Installation successful!"
        print_status "newt version: $("$newt_path" --version 2>/dev/null || printf 'unknown')"
        return 0
    else
        print_error "Installation failed. Binary not found or not executable."
        return 1
    fi
}

# Main installation process
main() {
    # --path explicitly overrides everything
    CUSTOM_PATH=$(parse_path_arg "$@")

    if [ -n "$CUSTOM_PATH" ]; then
        print_status "Installing latest version of newt to ${CUSTOM_PATH} (--path override)..."
    else
        print_status "Installing latest version of newt..."
    fi

    print_status "Fetching latest version..."
    VERSION=$(get_latest_version)
    print_status "Latest version: v${VERSION}"

    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

    PLATFORM=$(detect_platform)
    print_status "Detected platform: ${PLATFORM}"

    if [ -n "$CUSTOM_PATH" ]; then
        # --path wins; derive INSTALL_DIR from it
        INSTALL_DIR=$(dirname "$CUSTOM_PATH")
    else
        # Try to find an existing installation so we update the right place
        EXISTING_BINARY=$(detect_existing_binary)
        if [ -n "$EXISTING_BINARY" ]; then
            print_status "Found existing newt binary at ${EXISTING_BINARY}"
            CUSTOM_PATH="$EXISTING_BINARY"
            INSTALL_DIR=$(dirname "$EXISTING_BINARY")
            print_status "Will update existing installation at ${INSTALL_DIR}"
        else
            INSTALL_DIR=$(get_install_dir)
        fi
    fi

    print_status "Install directory: ${INSTALL_DIR}"

    # Check if we need sudo
    SUDO_CMD=$(get_sudo_cmd "$INSTALL_DIR")
    if [ -n "$SUDO_CMD" ]; then
        print_status "Root privileges required for installation to ${INSTALL_DIR}"
    fi

    install_newt "$PLATFORM" "$INSTALL_DIR" "$SUDO_CMD" "$CUSTOM_PATH"

    if [ -n "$CUSTOM_PATH" ]; then
        if [ -x "$CUSTOM_PATH" ]; then
            print_status "Installation successful!"
            print_status "newt version: $("$CUSTOM_PATH" --version 2>/dev/null || printf 'unknown')"
            print_status "newt is ready to use!"
        else
            print_error "Installation failed. Binary not found or not executable at ${CUSTOM_PATH}."
            exit 1
        fi
    elif verify_installation "$INSTALL_DIR"; then
        print_status "newt is ready to use!"
        print_status "Run 'newt --help' to get started."
    else
        exit 1
    fi
}

# Run main function
main "$@"