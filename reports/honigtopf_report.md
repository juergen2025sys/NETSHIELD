# Honigtopf – Report
**Aktualisiert:** 2026-09-18 00:24 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ✅ gültig (HTTP 200) |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 00:24 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **41,860** |
| Bad Hosts – VNC | **1,514** |
| Bad Hosts – SIP | **170** |
| Bad Hosts – SSH | **3,852** |
| Bad Hosts – MSSQL | **969** |
| Bad Hosts – RDP | **977** |
| Bad Hosts – SNMP | **535** |
| Bad Hosts – HTTP | **4,460** |
| Bad Hosts – FTP | **28,612** |
| Bad Hosts – TFTP | **222** |
| Bad Hosts – CouchDB | **225** |
| Bad Hosts – ProConOs | **168** |
| Bad Hosts – Telnet | **3,070** |
| Bad Hosts – MySQL | **711** |
| Bad Hosts – PostgreSQL | **475** |
| Bad Hosts – Kubernetes | **781** |
| Bad Hosts – Redis | **466** |
| Bad Hosts – Elasticsearch | **577** |
| Bad Hosts – Oracle | **297** |
| Bad Hosts – ClickhouseHTTP | **267** |
| Bad Hosts – Modbus | **244** |
| Bad Hosts – IPP | **145** |
| Bad Hosts – RAW | **215** |
| Bad Hosts – LDAP | **209** |
| Bad Hosts – Memcached | **249** |
| Bad Hosts – MQTT | **222** |
| Bad Hosts – HashCountRandom | **226** |
| Bad Hosts – LPD | **53** |
| Bad Hosts – MOTD | **56** |
| Bad Hosts – DNS.udp | **0** |
| Bad Hosts – Echo | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-17)**: **40,295** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **1** |
| 2026-09-17 | **40,295** |
| 2026-09-16 | **1,564** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **45,012** |
| Kandidaten dieses Abrufs | **45,012** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,111** |
| Entfernt | **-3,573** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 00:24 CEST (Berlin)*