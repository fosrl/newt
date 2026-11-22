#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
install -d -m 700 /usr/local/etc/newt
/usr/local/bin/php /usr/local/opnsense/scripts/OPNsense/Newt/migrate.php
/usr/local/sbin/pluginctl -m OPNsense/Newt
service configd restart
/usr/local/etc/rc.configure_plugins POST_INSTALL
configctl template reload OPNsense/Newt
/usr/local/opnsense/scripts/OPNsense/Newt/service.sh stop
if grep -q 'newt_enable="YES"' /etc/rc.conf.d/newt; then
    /usr/local/opnsense/scripts/OPNsense/Newt/service.sh start
fi
