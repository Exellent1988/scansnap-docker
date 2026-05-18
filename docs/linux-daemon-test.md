# Daemon-Test auf Linux

> **Hintergrund:** Auf macOS werden eingehende UDP-Pakete vom Scanner (192.168.2.117 → 192.168.1.213:55265) durch Reverse Path Filtering verworfen, weil kein direkter Return-Path über dasselbe Interface existiert. Wireshark sieht die Pakete (Layer 2), der Socket erhält sie nicht. Auf Linux tritt dieses Problem nicht auf.

## Voraussetzungen

- Linux-Host mit Docker (für den Container-Betrieb) **oder** `gcc`, `make`, `libpthread` (für nativen Build)
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

Erwartetes Init-Log (Scanner **ein**):

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

Wenn der Scanner beim Start **ausgeschaltet oder im Standby** ist, wartet der Daemon automatisch:

```
MAC=xx:xx:xx:xx:xx:xx  IP=192.168.x.x
UDP registration...
  recvfrom 52217: Resource temporarily unavailable
Scanner not reachable, retrying in 20s...
...
  registration OK (132 bytes from 192.168.2.117)
...
Daemon ready on UDP 55265 (output: ./output). Press scanner button or Ctrl+C to exit.
```

Gleiches gilt wenn der Scanner nach einem Scan in den Standby geht — der Daemon erholt sich selbst, **kein Neustart nötig**.

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

Der Container kompiliert den Daemon selbst (Multi-stage Build), d.h. kein lokales `gcc` nötig.

```bash
# output- und config-Verzeichnis anlegen
mkdir -p output config

# Docker-Image bauen
docker build -t scansnap:local .

# Daemon im Container starten (--network host nötig für UDP!)
docker run --rm \
  --network host \
  -v ./output:/work \
  -v ./config:/config \
  scansnap:local \
  --daemon -s 192.168.2.117 -k 175132178180 -o /work
```

`--network host` ist zwingend, damit der Container UDP-Port 55265 direkt vom Scanner empfangen kann — kein Port-Forwarding möglich/nötig.

> **Hinweis für Unraid:** `docker compose` steht standardmäßig nicht zur Verfügung, daher die obigen `docker build` / `docker run`-Befehle verwenden.

## Bekannte Stolpersteine

| Symptom | Ursache | Lösung |
|---|---|---|
| `bind 55265: Address already in use` | Anderer Prozess belegt Port | `ss -ulnp \| grep 55265`, dann `kill <pid>` |
| `registration OK` aber keine Button-Events | macOS RPF oder falsches Interface | `tcpdump` — kommen Pakete auf 55265 an? |
| `Scan failed: no image data` | Kein Papier eingelegt | Papier in ADF legen |
| `Scan failed: TCP handshake` | Scanner braucht Power-Cycle | Scanner neu starten — Daemon erholt sich automatisch |
| `Scanner not reachable, retrying in 20s...` | Scanner aus oder im Standby beim Start | Normal — Daemon wartet selbst, kein Eingriff nötig |

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
