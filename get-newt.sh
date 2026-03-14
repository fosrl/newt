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
    local latest_info
    
    if command -v curl >/dev/null 2>&1; then
        latest_info=$(curl -fsSL "$GITHUB_API_URL" 2>/dev/null)
    elif command -v wget >/dev/null 2>&1; then
        latest_info=$(wget -qO- "$GITHUB_API_URL" 2>/dev/null)
    else
        print_error "Neither curl nor wget is available. Please install one of them." >&2
        exit 1
    fi
    
    if [ -z "$latest_info" ]; then
        print_error "Failed to fetch latest version information" >&2
        exit 1
    fi
    
    # Extract version from JSON response (works without jq)
    local version=$(echo "$latest_info" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    
    if [ -z "$version" ]; then
        print_error "Could not parse version from GitHub API response" >&2
        exit 1
    fi
    
    # Remove 'v' prefix if present
    version=$(echo "$version" | sed 's/^v//')
    
    echo "$version"
}

# Detect OS and architecture
detect_platform() {
    local os arch
    
    # Detect OS
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
    
    # Detect architecture
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
                arch="arm64"  # Default for non-Linux ARM
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
    
    echo "${os}_${arch}"
}

# Get installation directory
get_install_dir() {
    if [ "$OS" = "windows" ]; then
        echo "$HOME/bin"
    else
        # Prefer /usr/local/bin for system-wide installation
        echo "/usr/local/bin"
    fi
}

# Check if we need sudo for installation
needs_sudo() {
    local install_dir="$1"
    if [ -w "$install_dir" ] 2>/dev/null; then
        return 1  # No sudo needed
    else
        return 0  # Sudo needed
    fi
}

# Get the appropriate command prefix (sudo or empty)
get_sudo_cmd() {
    local install_dir="$1"
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
    local platform="$1"
    local install_dir="$2"
    local sudo_cmd="$3"
    local binary_name="newt_${platform}"
    local exe_suffix=""

    # Add .exe suffix for Windows
    case "$platform" in
        *windows*)
            binary_name="${binary_name}.exe"
            exe_suffix=".exe"
            ;;
    esac

    local download_url="${BASE_URL}/${binary_name}"
    local temp_file="/tmp/newt${exe_suffix}"
    local final_path="${install_dir}/newt${exe_suffix}"

    print_status "Downloading newt from ${download_url}"

    # Download the binary
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$download_url" -o "$temp_file"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$download_url" -O "$temp_file"
    else
        print_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi

    # Make executable before moving
    chmod +x "$temp_file"

    # Create install directory if it doesn't exist
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
        print_warning "Add it to your PATH by adding this line to your shell profile:"
        print_warning "  export PATH=\"${install_dir}:\$PATH\""
    fi
}

# Verify installation
verify_installation() {
    local install_dir="$1"
    local exe_suffix=""
    
    case "$PLATFORM" in
        *windows*) exe_suffix=".exe" ;;
    esac
    
    local newt_path="${install_dir}/newt${exe_suffix}"
    
    if [ -f "$newt_path" ] && [ -x "$newt_path" ]; then
        print_status "Installation successful!"
        print_status "newt version: $("$newt_path" --version 2>/dev/null || echo "unknown")"
        return 0
    else
        print_error "Installation failed. Binary not found or not executable."
        return 1
    fi
}

# Main installation process
main() {
    print_status "Installing latest version of newt..."

    # Get latest version
    print_status "Fetching latest version from GitHub..."
    VERSION=$(get_latest_version)
    print_status "Latest version: v${VERSION}"

    # Set base URL with the fetched version
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

    # Detect platform
    PLATFORM=$(detect_platform)
    print_status "Detected platform: ${PLATFORM}"

    # Get install directory
    INSTALL_DIR=$(get_install_dir)
    print_status "Install directory: ${INSTALL_DIR}"

    # Check if we need sudo
    SUDO_CMD=$(get_sudo_cmd "$INSTALL_DIR")
    if [ -n "$SUDO_CMD" ]; then
        print_status "Root privileges required for installation to ${INSTALL_DIR}"
    fi

    # Install newt
    install_newt "$PLATFORM" "$INSTALL_DIR" "$SUDO_CMD"

    # Verify installation
    if verify_installation "$INSTALL_DIR"; then
        print_status "newt is ready to use!"
        print_status "Run 'newt --help' to get started"
    else
        exit 1
    fi
}

# Run main function
main "$@"