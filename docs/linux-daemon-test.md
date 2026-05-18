# Daemon-Test auf Linux

> **Hintergrund:** Auf macOS werden eingehende UDP-Pakete vom Scanner (192.168.2.117 → 192.168.1.213:55265) durch Reverse Path Filtering verworfen, weil kein direkter Return-Path über dasselbe Interface existiert. Wireshark sieht die Pakete (Layer 2), der Socket erhält sie nicht. Auf Linux tritt dieses Problem nicht auf.

## Voraussetzungen

- Linux-Host mit `gcc`, `make`, `libpthread` (meist vorinstalliert)
- Scanner und Linux-Rechner im gleichen Netzwerk (oder über Router erreichbar)
- ScanSnap Home beenden (falls vorhanden)
- Root/sudo für `tcpdump` falls Diagnose nötig

## Schritt 1 — Repository holen

```bash
git clone <repo-url> ~/scansnap
cd ~/scansnap
```

Oder per rsync vom Mac:

```bash
rsync -av --exclude='.git' --exclude='*.pcapng' \
  user@mac:~/Documents/Projects/scansnap-docker/ \
  ~/scansnap/
```

## Schritt 2 — Bauen und Tests ausführen

```bash
cd ~/scansnap
make
make test
```

Erwartete Ausgabe:

```
test_button_notify: 12 passed
fixtures OK
scansnap_org_button_test.pcapng: OK (two button bursts)
```

## Schritt 3 — Netzwerk prüfen

```bash
# Scanner erreichbar?
ping -c 2 192.168.2.117

# Route zum Scanner prüfen
ip route get 192.168.2.117

# Eigene IP ermitteln (für -s falls nötig)
ip -4 addr show | grep inet

# Reverse Path Filtering — sollte 0 sein für unsere Nutzung
sysctl net.ipv4.conf.all.rp_filter

# Port 55265 muss frei sein
ss -ulnp | grep 55265
```

Falls `rp_filter` = 2 (strict):

```bash
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0
```

## Schritt 4 — Daemon nativ starten

```bash
# Key und Scanner-IP anpassen:
./scansnap -d --daemon -s 192.168.2.117 -k 175132178180 -o ./output
```

Erwartetes Init-Log:

```
MAC=xx:xx:xx:xx:xx:xx  IP=192.168.x.x
UDP registration...
  registration OK (132 bytes from 192.168.2.117)
TCP:53219 handshake...
  handshake result: 0
TCP:53218 init session...
  06+12: 136B  E7: 52B  C2: 72B  E6a: 44B  E6b: 40B  D5: 48B  D6: 40B
Daemon ready on UDP 55265 (output: ./output). Press scanner button or Ctrl+C to exit.
```

## Schritt 5 — Button drücken und Ergebnis prüfen

Nach dem Button-Druck am Scanner sollte der Daemon loggen:

```
UDP 48B from scanner (notify counter N)
Button event (counter N), scanning...
Starting scan...
Saved ./output/scan_20260518_214500.pdf (2 pages)
```

Falls **nichts** erscheint → Diagnose parallel in einem zweiten Terminal:

```bash
sudo tcpdump -n -i any udp port 55265
```

Zeigt `tcpdump` Pakete aber der Daemon nicht → Socket-Problem (RPF oder Firewall).  
Zeigt `tcpdump` keine Pakete → Scanner schickt keine Events (Registrierung fehlgeschlagen).

## Schritt 6 — Docker-Test

Nach erfolgreichem Nativ-Test mit Docker:

```bash
# output-Verzeichnis anlegen
mkdir -p output

# Docker-Image bauen
docker compose build

# Daemon im Container starten (network_mode: host nötig!)
docker compose run --rm scansnap \
  --daemon -s 192.168.2.117 -k 175132178180 -o /output
```

`compose.yml` verwendet bereits `network_mode: host`, damit UDP-Ports direkt
vom Container erreichbar sind — kein Port-Forwarding erforderlich.

## Bekannte Stolpersteine

| Symptom | Ursache | Lösung |
|---|---|---|
| `bind 55265: Address already in use` | Anderer Prozess belegt Port | `ss -ulnp \| grep 55265`, dann `kill <pid>` |
| `registration OK` aber keine Button-Events | macOS RPF oder falsches Interface | `tcpdump` — kommen Pakete auf 55265 an? |
| `Scan failed: no image data` | Kein Papier eingelegt | Papier in ADF legen |
| `Scan failed: TCP handshake` | Scanner Power-Cycle nötig | Scanner neu starten, Daemon neu starten |
| Daemon startet nach Scan nicht mehr | Scanner sendet Events nicht neu | `daemon_prepare_session` neu → Scanner-Neustart |

## Erster Scan ohne Daemon (Funktionstest)

Vor dem Daemon-Test empfehlenswert:

```bash
# Einzelscan — Papier einlegen, dann:
./scansnap -d -s 192.168.2.117 -k 175132178180 -o test.pdf
```

Damit verifizierst du, dass Scan-Protokoll, Key und Netzwerk grundsätzlich funktionieren, bevor du den Daemon testest.

## Pairing Key ermitteln (falls kein Key vorhanden)

Falls `-k` nicht bekannt, den Key per Fake-Scanner holen:

```bash
# Sicherstellen: physischer Scanner ausgeschaltet
./scansnap --getkey --getkey-ip <LINUX-IP>
# Dann ScanSnap Home auf Mac öffnen → verbindet sich mit Fake-Scanner → Key erscheint
```

Der Key bleibt konstant (WiFi-Modul-Seriennummer), hier: `175132178180`.
