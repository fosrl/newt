#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Build the package on the target FreeBSD/OPNsense release.
set -eu
umask 022
[ "$(uname -s)" = FreeBSD ] || { echo 'Build on FreeBSD/OPNsense.' >&2; exit 1; }
command -v opnsense-version >/dev/null 2>&1 || { echo 'OPNsense is required.' >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build=$(mktemp -d /tmp/os-newt-build.XXXXXX)
trap 'rm -rf "$build"' EXIT
trap 'exit 1' HUP INT TERM
stage="$build/stage"
metadata="$build/metadata"
mkdir -p "$stage/usr/local" "$metadata" "$source_dir/dist"
cp -R "$source_dir/src/" "$stage/usr/local/"
# Ignore Finder/AppleDouble metadata when sources were copied from macOS.
find "$stage" -type f \( -name '._*' -o -name '.DS_Store' \) -delete
arch=$(uname -p)
mkdir -p "$stage/usr/local/share/doc/os-newt" "$stage/usr/local/opnsense/version"
cp "$source_dir/LICENSE" "$source_dir/README.md" "$stage/usr/local/share/doc/os-newt/"
find "$stage" -type d -exec chmod 755 {} +
find "$stage" -type f -exec chmod 644 {} +
chmod 755 "$stage/usr/local/etc/rc.d/newt"
chmod 755 "$stage/usr/local/opnsense/scripts/OPNsense/Newt/"*

export NEWT_BUILD_STAGE="$stage" NEWT_BUILD_METADATA="$metadata" NEWT_BUILD_ARCH="$arch"
php <<'PHP'
<?php
$annotations = [
    'product_id' => 'os-newt', 'product_name' => 'newt',
    'product_version' => '1.2', 'product_tier' => '4',
    'product_conflicts' => 'os-newt-devel',
    'product_abi' => trim(shell_exec('opnsense-version -a')),
    'product_arch' => getenv('NEWT_BUILD_ARCH'),
    'product_website' => 'https://github.com/fosrl/newt',
    'product_email' => 'soehnke.dencker@sh4u.de',
];
$manifest = [
    'name' => 'os-newt', 'version' => '1.2', 'origin' => 'local/os-newt',
    'comment' => 'Pangolin Newt connector with WebUI and service controls',
    'desc' => 'Pangolin Newt MVC/API integration; requires the separate pangolin-newt package.',
    'maintainer' => 'soehnke.dencker@sh4u.de', 'www' => 'https://github.com/fosrl/newt',
    'prefix' => '/usr/local', 'categories' => ['net', 'security'],
    'licenselogic' => 'single', 'licenses' => ['BSD2CLAUSE'],
    'deps' => ['pangolin-newt' => ['origin' => 'net/pangolin-newt', 'version' => '1.18.1']],
    'abi' => trim(shell_exec('pkg config ABI')),
    'annotations' => $annotations,
    'scripts' => [
        'post-install' => '/usr/local/opnsense/scripts/OPNsense/Newt/setup.sh',
        'pre-deinstall' => '/usr/local/opnsense/scripts/OPNsense/Newt/service.sh stop || true',
        'post-deinstall' => "rm -f /etc/rc.conf.d/newt /usr/local/etc/newt/config.json\n"
            . "service configd restart\n/usr/local/etc/rc.configure_plugins POST_DEINSTALL\n",
    ],
];
file_put_contents(getenv('NEWT_BUILD_METADATA') . '/+MANIFEST', json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
file_put_contents(getenv('NEWT_BUILD_STAGE') . '/usr/local/opnsense/version/newt', json_encode($annotations, JSON_PRETTY_PRINT));
PHP
find "$stage/usr/local" -type f | sed "s|^$stage/usr/local/||" | sort > "$build/plist"
pkg create -r "$stage" -m "$metadata" -p "$build/plist" -o "$source_dir/dist"
echo "Package written to $source_dir/dist"
(cd "$source_dir/dist" && sha256 -r os-newt-1.2.pkg > SHA256SUMS.plugin)
