# Honigtopf – Report
**Aktualisiert:** 2026-09-24 02:26 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-24 02:26 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **12,461** |
| Bad Hosts – SIP | **161** |
| Bad Hosts – RDP | **1,154** |
| Bad Hosts – SSH | **4,003** |
| Bad Hosts – MSSQL | **639** |
| Bad Hosts – HTTP | **3,222** |
| Bad Hosts – SNMP | **347** |
| Bad Hosts – VNC | **373** |
| Bad Hosts – TFTP | **176** |
| Bad Hosts – Telnet | **2,924** |
| Bad Hosts – MySQL | **670** |
| Bad Hosts – ProConOs | **198** |
| Bad Hosts – PostgreSQL | **501** |
| Bad Hosts – FTP | **659** |
| Bad Hosts – Kubernetes | **871** |
| Bad Hosts – CouchDB | **1,138** |
| Bad Hosts – Redis | **463** |
| Bad Hosts – Elasticsearch | **677** |
| Bad Hosts – Oracle | **295** |
| Bad Hosts – ClickhouseHTTP | **312** |
| Bad Hosts – Modbus | **296** |
| Bad Hosts – Memcached | **282** |
| Bad Hosts – LDAP | **279** |
| Bad Hosts – RAW | **218** |
| Bad Hosts – MQTT | **239** |
| Bad Hosts – IPP | **99** |
| Bad Hosts – HashCountRandom | **98** |
| Bad Hosts – LPD | **93** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-24)**: **504** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-24 | **504** |
| 2026-09-23 | **11,957** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **15,304** |
| Kandidaten dieses Abrufs | **15,304** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+569** |
| Entfernt | **-762** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-24 02:26 CEST (Berlin)*