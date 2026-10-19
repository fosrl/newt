# OPNsense community package

This directory vendors **os-newt 1.2** from
[soehnke1/os-newt](https://github.com/soehnke1/os-newt/tree/05328dca20949711e92d39393357223e185fd6bc)
at commit `05328dca20949711e92d39393357223e185fd6bc`.
Plugin code is BSD-2-Clause; see LICENSE. The separately built Newt executable
is AGPLv3 and is not bundled here.

## Build

On the matching OPNsense release with a complete ports tree and Go 1.26+:

```sh
cd packages/opnsense
PORTSDIR=/usr/ports sh build-port.sh
sh build.sh
```

The output is `dist/pangolin-newt-1.18.1.pkg` and `dist/os-newt-1.2.pkg`.
Both packages are required. Build for the target ABI; do not install packages
built for another FreeBSD/OPNsense release. See README.md for installation,
configuration, migration and rollback instructions, and VALIDATION.md for
previous test results and their limitations.

## Checks

```sh
php tests/model.php
python3 tests/templates.py
```

The model test requires the OPNsense PHP environment; the template test
requires Jinja2. Native package builds require FreeBSD/OPNsense.

This is a community package, not an official OPNsense plugin. Related proposals:
[plugin #5803](https://github.com/opnsense/plugins/pull/5803),
[OPNsense port #301](https://github.com/opnsense/ports/pull/301), and
[FreeBSD port #643](https://github.com/freebsd/freebsd-ports/pull/643).
