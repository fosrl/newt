#!/bin/sh

# Get Newt - Cross-platform installation script
# Usage: curl -fsSL https://raw.githubusercontent.com/fosrl/newt/refs/heads/main/get-newt.sh | sh
#
# Options (pass after `sh -s --`, e.g. `... | sh -s -- --version 1.19.0`):
#   --version <version>  Install a specific release instead of the latest.
#                        Can also be set with NEWT_VERSION.
#   --path <file>        Install to this exact path.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# GitHub repository info
REPO="fosrl/newt"
RELEASE_API_URL="https://api.fossorial.io/api/v1/versions/newt"

# Function to print colored output
print_status() {
    printf '%b[INFO]%b %s\n' "${GREEN}" "${NC}" "$1"
}

# Warnings and errors go to stderr so they still show up when printed from
# inside a $(...) command substitution.
print_warning() {
    printf '%b[WARN]%b %s\n' "${YELLOW}" "${NC}" "$1" >&2
}

print_error() {
    printf '%b[ERROR]%b %s\n' "${RED}" "${NC}" "$1" >&2
}

# Temporary download directory, removed on exit. A fresh mktemp directory
# avoids clobbering (or following a symlink planted at) a fixed /tmp path.
TMP_DIR=""
cleanup() {
    if [ -n "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# Fetch the latest release info (version and asset checksums) from the
# Fossorial API into RELEASE_INFO. Returns 1 if it isn't available.
RELEASE_INFO=""
fetch_release_info() {
    if command -v curl >/dev/null 2>&1; then
        RELEASE_INFO=$(curl -fsSL "$RELEASE_API_URL" 2>/dev/null || true)
    else
        RELEASE_INFO=$(wget -qO- "$RELEASE_API_URL" 2>/dev/null || true)
    fi
    RELEASE_INFO=$(printf '%s' "$RELEASE_INFO" | tr -d '\n\r')
    [ -n "$RELEASE_INFO" ]
}

# latestVersion from RELEASE_INFO, without a leading "v". Parsed without jq.
release_info_version() {
    printf '%s' "$RELEASE_INFO" |
        sed -n 's/.*"latestVersion"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
        sed 's/^v//'
}

# Published sha256 of a release asset from RELEASE_INFO, or nothing.
release_info_digest() {
    asset_re=$(printf '%s' "$1" | sed 's/[][\.*^$/]/\\&/g')
    printf '%s' "$RELEASE_INFO" |
        sed -n "s/.*\"${asset_re}\"[[:space:]]*:[[:space:]]*\"\([0-9a-f]\{64\}\)\".*/\1/p"
}

# sha256 of a file, with whichever tool this system has.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v sha256 >/dev/null 2>&1; then
        sha256 -q "$1"
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    else
        return 1
    fi
}

# Check a downloaded file against the checksum published for its release
# asset. Exits on a mismatch; warns and carries on when there's no published
# checksum (pinned older version, or the API was unreachable).
verify_checksum() {
    checksum_file="$1"
    checksum_asset="$2"

    checksum_expected=$(release_info_digest "$checksum_asset")
    if [ -z "$checksum_expected" ]; then
        print_warning "No published checksum for ${checksum_asset}; skipping verification."
        return 0
    fi

    checksum_actual=$(sha256_of "$checksum_file" || true)
    if [ -z "$checksum_actual" ]; then
        print_warning "No sha256 tool found (sha256sum, shasum, sha256 or openssl); skipping verification."
        return 0
    fi

    if [ "$checksum_actual" != "$checksum_expected" ]; then
        print_error "Checksum mismatch for ${checksum_asset}!"
        print_error "  expected: ${checksum_expected}"
        print_error "  got:      ${checksum_actual}"
        print_error "The download may be corrupted or tampered with. Nothing was installed."
        exit 1
    fi

    print_status "Checksum verified (sha256 ${checksum_expected})"
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

# Parse command line arguments into CUSTOM_PATH and REQUESTED_VERSION.
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --path)
                if [ -z "$2" ]; then
                    print_error "--path requires a value"
                    exit 1
                fi
                CUSTOM_PATH="$2"
                shift
                ;;
            --path=*)
                CUSTOM_PATH="${1#--path=}"
                ;;
            --version)
                if [ -z "$2" ]; then
                    print_error "--version requires a value"
                    exit 1
                fi
                REQUESTED_VERSION="$2"
                shift
                ;;
            --version=*)
                REQUESTED_VERSION="${1#--version=}"
                ;;
            *)
                print_warning "Ignoring unknown argument: $1"
                ;;
        esac
        shift
    done
}

# Set VERSION and BASE_URL for the release to install: the requested version,
# else the latest from the Fossorial API, else GitHub's latest release (which
# is a plain redirect, not a rate-limited GitHub API call). RELEASE_INFO is
# cleared unless it describes the chosen version, so its checksums are only
# ever used for the release they belong to.
resolve_release() {
    latest=""
    if fetch_release_info; then
        latest=$(release_info_version)
    fi

    if [ -n "$REQUESTED_VERSION" ]; then
        VERSION=$(printf '%s' "$REQUESTED_VERSION" | sed 's/^v//')
        case "$VERSION" in
            ""|*[!0-9A-Za-z.+-]*)
                print_error "Invalid version: ${REQUESTED_VERSION}"
                exit 1
                ;;
        esac
        print_status "Requested version: v${VERSION}"
        BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
        if [ "$VERSION" != "$latest" ]; then
            RELEASE_INFO=""
        fi
        return
    fi

    if [ -n "$latest" ]; then
        VERSION="$latest"
        print_status "Latest version: v${VERSION}"
        BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
    else
        VERSION=""
        RELEASE_INFO=""
        print_warning "Could not get the latest version from ${RELEASE_API_URL}"
        print_warning "Falling back to the latest release on GitHub"
        BASE_URL="https://github.com/${REPO}/releases/latest/download"
    fi
}

# Returns 0 if the directory is an entry in $PATH.
dir_in_path() {
    case ":${PATH}:" in
        *":$1:"*) return 0 ;;
        *) return 1 ;;
    esac
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

# Restore the default SELinux context on an installed binary.
# The binary is downloaded to /tmp, so it carries a temp-file label
# (e.g. user_tmp_t) that mv preserves; on SELinux-enforcing hosts systemd
# then refuses to execute it (status=203/EXEC).
restore_selinux_context() {
    target="$1"
    sudo_cmd="$2"

    [ -e /sys/fs/selinux/enforce ] || return 0

    restorecon_bin=$(command -v restorecon 2>/dev/null || true)
    if [ -z "$restorecon_bin" ]; then
        for candidate in /usr/sbin/restorecon /sbin/restorecon; do
            if [ -x "$candidate" ]; then
                restorecon_bin="$candidate"
                break
            fi
        done
    fi

    if [ -z "$restorecon_bin" ]; then
        print_warning "SELinux is enabled but restorecon was not found."
        print_warning "If the service fails to start, run: restorecon -v ${target}"
        return 0
    fi

    print_status "Restoring SELinux context on ${target}"
    if ! $sudo_cmd "$restorecon_bin" "$target"; then
        print_warning "Failed to restore SELinux context on ${target}."
        print_warning "If the service fails to start, run: restorecon -v ${target}"
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
    temp_file="${TMP_DIR}/${final_name}"

    # If a custom path is provided, use it directly; otherwise use install_dir/final_name
    if [ -n "$custom_path" ]; then
        final_path="$custom_path"
        install_dir=$(dirname "$final_path")
    else
        final_path="${install_dir}/${final_name}"
    fi

    print_status "Downloading newt from ${download_url}"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$download_url" -o "$temp_file" || download_failed=1
    else
        wget -q "$download_url" -O "$temp_file" || download_failed=1
    fi
    if [ -n "${download_failed:-}" ] || [ ! -s "$temp_file" ]; then
        print_error "Failed to download ${download_url}"
        print_error "Check that release ${VERSION:-latest} has a ${binary_name} asset."
        exit 1
    fi

    verify_checksum "$temp_file" "$binary_name"

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

    restore_selinux_context "$final_path" "$sudo_cmd"

    print_status "newt installed to ${final_path}"

    # Check if install directory is in PATH
    if ! dir_in_path "$install_dir"; then
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
    CUSTOM_PATH=""
    REQUESTED_VERSION="${NEWT_VERSION:-}"
    # --path explicitly overrides everything
    parse_args "$@"

    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        print_error "Neither curl nor wget is available."
        exit 1
    fi

    if [ -n "$CUSTOM_PATH" ]; then
        print_status "Installing newt to ${CUSTOM_PATH}..."
    else
        print_status "Installing newt..."
    fi

    resolve_release

    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/newt.XXXXXX")

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
