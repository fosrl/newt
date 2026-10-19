# Validierung

## Repository-Version 1.2

Testsystem am 18.10.2026: OPNsense 26.7.7, FreeBSD 15.1-RELEASE-p4, amd64.

- `build.sh`: natives Plugin-Paket `os-newt-1.2.pkg` erzeugt; Manifest enthält `pangolin-newt` 1.18.1 als Abhängigkeit und die OPNsense-Annotation `product_conflicts=os-newt-devel`.
- `tests/model.php`: gültige Werte und leere optionale Felder akzeptiert, ungültige Werte abgelehnt. Deaktivierte leere Konfiguration akzeptiert; Aktivierung ohne Zugangsdaten abgelehnt.
- `tests/templates.py`: JSON-Escaping, optionale Felder und Aktivierung geprüft.
- `build-port.sh`: natives Programmpaket aus dem mitgelieferten Port erfolgreich gebaut.
- Beide Pakete in einem isolierten Root mit deaktivierten Installationsskripten installiert und entfernt; Abhängigkeiten, Dateiprüfsummen und eindeutige Dateibesitzer geprüft. Das erzeugte Programm meldet Newt 1.18.1.
- Paketdateiliste geprüft: kein gebündeltes Binary, keine AppleDouble-Dateien; das Plugin besitzt das Startskript.

Der Paketbau nutzt einen vorhandenen Ports-Baum und eine vorhandene Go-1.26.9-Toolchain mit expliziten GO_CMD/BINARY_ALIAS-Argumenten und NO_DEPENDS=yes. Dies ist kein sauberer Poudriere-Build und kein Test der automatischen Installation der Build-Abhängigkeiten.

## Vorheriger Live-Test der Upstream-Paketaufteilung

Am selben Tag wurden der identische Programmpaket-Port und das Plugin aus PR #5803 auf diesem System gebaut, mit `check-plist` und `stage-qa` geprüft und vorübergehend live installiert. Template-Neuladen, Start, Stopp, Neustart und Tunnelaufbau waren erfolgreich. Danach wurden die vorher installierten Pakete (`os-newt-devel 1.1` und dessen Programmpaket) wiederhergestellt. Konfiguration und Zugangsdaten blieben bytegenau unverändert.

Dieser Live-Test prüfte die PR-Version, nicht den neuen lokalen Paketbauer von Version 1.2. Ein erneuter Live-Wechsel, ein Firewall-Neustart, Erstimport einer Standalone-Konfiguration und ein Browser-/WebUI-API-Test wurden für Version 1.2 nicht ausgeführt.
