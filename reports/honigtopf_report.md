# Honigtopf – Report
**Aktualisiert:** 2026-10-06 16:09 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ⚠️ unklar (410) – im Pool belassen |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 16:09 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,370** |
| Bad Hosts – SIP | **175** |
| Bad Hosts – SSH | **3,724** |
| Bad Hosts – SNMP | **401** |
| Bad Hosts – MSSQL | **502** |
| Bad Hosts – RDP | **884** |
| Bad Hosts – TFTP | **217** |
| Bad Hosts – VNC | **343** |
| Bad Hosts – HTTP | **3,624** |
| Bad Hosts – Telnet | **2,613** |
| Bad Hosts – MySQL | **693** |
| Bad Hosts – FTP | **562** |
| Bad Hosts – Memcached | **228** |
| Bad Hosts – ProConOs | **163** |
| Bad Hosts – Kubernetes | **906** |
| Bad Hosts – Redis | **439** |
| Bad Hosts – PostgreSQL | **533** |
| Bad Hosts – CouchDB | **376** |
| Bad Hosts – ClickhouseHTTP | **345** |
| Bad Hosts – Elasticsearch | **680** |
| Bad Hosts – Oracle | **271** |
| Bad Hosts – Modbus | **193** |
| Bad Hosts – LDAP | **256** |
| Bad Hosts – MQTT | **267** |
| Bad Hosts – RAW | **142** |
| Bad Hosts – HashCountRandom | **109** |
| Bad Hosts – LPD | **95** |
| Bad Hosts – IPP | **120** |
| Bad Hosts – MOTD | **82** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **7,716** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **7,716** |
| 2026-10-05 | **3,654** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,085** |
| Kandidaten dieses Abrufs | **14,085** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,327** |
| Entfernt | **-1,976** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 16:09 CEST (Berlin)*