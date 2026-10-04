# Honigtopf – Report
**Aktualisiert:** 2026-10-04 19:32 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-04 19:32 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,432** |
| Bad Hosts – SIP | **191** |
| Bad Hosts – SSH | **3,932** |
| Bad Hosts – SNMP | **420** |
| Bad Hosts – MSSQL | **435** |
| Bad Hosts – RDP | **680** |
| Bad Hosts – HTTP | **2,648** |
| Bad Hosts – VNC | **324** |
| Bad Hosts – Telnet | **2,695** |
| Bad Hosts – ProConOs | **162** |
| Bad Hosts – MySQL | **472** |
| Bad Hosts – TFTP | **195** |
| Bad Hosts – Redis | **434** |
| Bad Hosts – FTP | **408** |
| Bad Hosts – PostgreSQL | **498** |
| Bad Hosts – CouchDB | **325** |
| Bad Hosts – Kubernetes | **652** |
| Bad Hosts – Elasticsearch | **531** |
| Bad Hosts – ClickhouseHTTP | **362** |
| Bad Hosts – Oracle | **292** |
| Bad Hosts – Memcached | **217** |
| Bad Hosts – Modbus | **202** |
| Bad Hosts – MQTT | **217** |
| Bad Hosts – LDAP | **170** |
| Bad Hosts – IPP | **93** |
| Bad Hosts – RAW | **128** |
| Bad Hosts – LPD | **78** |
| Bad Hosts – MOTD | **68** |
| Bad Hosts – HashCountRandom | **37** |
| Bad Hosts – Echo | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-04)**: **8,204** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-04 | **8,204** |
| 2026-10-03 | **2,228** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,016** |
| Kandidaten dieses Abrufs | **13,016** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+116** |
| Entfernt | **-186** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-04 19:32 CEST (Berlin)*