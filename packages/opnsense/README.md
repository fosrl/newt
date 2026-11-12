# Pangolin Newt für OPNsense

`os-newt` bietet unter **VPN → Pangolin Newt** eine WebUI für einen Pangolin-Standort, Dienststeuerung, Autostart und eine Logansicht. LAN-Ressourcen und Zugriffsrechte werden in Pangolin verwaltet.

Dieses Community-Projekt ist noch kein offizielles OPNsense-Paket. Version **1.2** trennt die WebUI (`os-newt`) vom Programm (`pangolin-newt` 1.18.1). Das Plugin installiert `/usr/local/etc/rc.d/newt`; das Programmpaket installiert `/usr/local/sbin/newt`. Beide Pakete werden benötigt.

## Pakete bauen

Auf der passenden OPNsense als root arbeiten. Benötigt werden Git und ein zur OPNsense-Version passender Ports-Baum; der Port benötigt Go 1.26 oder neuer. Der Port-Bau kann fehlende Build-Abhängigkeiten installieren. Nicht auf macOS/Linux erzeugte Pakete auf die Firewall übertragen.

```sh
git clone https://github.com/soehnke1/os-newt.git
cd os-newt
# PORTSDIR muss auf einen vollständigen, passenden Ports-Baum zeigen.
PORTSDIR=/usr/ports sh build-port.sh
sh build.sh
```

Ergebnis:

- `dist/pangolin-newt-1.18.1.pkg`: aus dem geprüften Go-Quellarchiv gebautes Programm.
- `dist/os-newt-1.2.pkg`: WebUI, Konfigurationsmodell und Dienstintegration.
- `dist/SHA256SUMS.port` und `dist/SHA256SUMS.plugin`: Prüfsummen genau dieser Builds.

`build.sh` lädt kein Programm-Binary herunter und installiert nichts. `build-port.sh` nutzt das normale Ports-Framework. Pakete sind an die FreeBSD-/OPNsense-ABI des Buildsystems gebunden. Alte Release-Pakete 1.0 verwenden noch die frühere, gebündelte Paketstruktur.

## Erstinstallation

Vorher die Firewall-Konfiguration sichern. Wenn bisher kein Newt-Paket installiert ist:

```sh
pkg add ./dist/pangolin-newt-1.18.1.pkg ./dist/os-newt-1.2.pkg
```

Danach die WebUI neu laden. Unter **VPN → Pangolin Newt → Settings** HTTPS-Endpunkt, Site-ID und Secret eintragen, aktivieren und „Apply“ ausführen. Ein unkonfiguriertes Plugin kann deaktiviert gespeichert werden. Eine vorhandene Standalone-Konfiguration unter `/usr/local/etc/newt/config.json` wird nur übernommen, wenn noch keine Plugin-Einstellungen existieren.

## Wechsel von älteren Paketen

Nicht mit `pkg add -f` über eine andere Paketaufteilung installieren. Insbesondere `os-newt-devel 1.1` kann ein Programmpaket verwenden, das selbst das Startskript besitzt und `/usr/local/bin/newt` installiert. Zuerst beide neuen Pakete bauen. Die folgenden Schritte unterbrechen den Newt-Tunnel kurzzeitig und sollten über einen unabhängigen LAN-Zugang ausgeführt werden.

Als root im Repository-Verzeichnis:

```sh
umask 077
backup=$(mktemp -d /root/newt-backup.XXXXXX)
cp -p /conf/config.xml "$backup/config.xml"
if [ -f /usr/local/etc/newt/config.json ]; then
    cp -p /usr/local/etc/newt/config.json "$backup/runtime.json"
fi
for name in os-newt os-newt-devel pangolin-newt; do
    if pkg info -e "$name"; then pkg create -o "$backup" "$name" || exit 1; fi
done
service newt onestop || true
for name in os-newt os-newt-devel pangolin-newt; do
    if pkg info -e "$name"; then pkg delete -y "$name" || exit 1; fi
done
if [ -f "$backup/runtime.json" ]; then
    install -d -m 700 /usr/local/etc/newt
    install -m 600 "$backup/runtime.json" /usr/local/etc/newt/config.json
fi
pkg add ./dist/pangolin-newt-1.18.1.pkg ./dist/os-newt-1.2.pkg
```

Die Plugin-Einstellungen in `config.xml` bleiben bei der Deinstallation erhalten. Die Sicherung enthält vertrauliche Zugangsdaten und gehört nicht ins Repository. Für eine Rückkehr zuerst die neuen Pakete entfernen und danach die gesicherten Programmpakete und das gesicherte Plugin installieren.

## Betrieb und Prüfung

```sh
configctl newt status
configctl newt restart
pkg check -d -s os-newt pangolin-newt
php tests/model.php
python3 tests/templates.py
```

Der Template-Test benötigt Jinja2. Der Dienststatus prüft den Prozess; den tatsächlichen Tunnelstatus zeigt Pangolin. Die Laufzeitkonfiguration ist root-only (0600). Zugangsdaten sind auch in OPNsense-Konfigurationssicherungen enthalten.

`pkg delete os-newt` entfernt die Integration und stoppt Newt. `pangolin-newt` bleibt als separates Paket bestehen und kann bei Bedarf ebenfalls entfernt werden.

## Tests und Upstream

Siehe [VALIDATION.md](VALIDATION.md) für Testumfang und Grenzen.

- [OPNsense-Plugin-PR #5803](https://github.com/opnsense/plugins/pull/5803)
- [OPNsense-Port #301](https://github.com/opnsense/ports/pull/301)
- [FreeBSD-Port #643](https://github.com/freebsd/freebsd-ports/pull/643)

Die PRs sind eigenständige Einreichungen; dieses Repository liefert den lokalen Paketbau. Plugin-Code: BSD-2-Clause, siehe [LICENSE](LICENSE). Das separate [Newt-Programm](https://github.com/fosrl/newt/tree/v1.18.1) steht unter AGPLv3; dessen Lizenz installiert das Ports-Framework.
