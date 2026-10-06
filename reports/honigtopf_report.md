# Honigtopf – Report
**Aktualisiert:** 2026-10-06 17:59 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-06 17:59 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,413** |
| Bad Hosts – SIP | **169** |
| Bad Hosts – SSH | **3,737** |
| Bad Hosts – SNMP | **415** |
| Bad Hosts – MSSQL | **489** |
| Bad Hosts – RDP | **823** |
| Bad Hosts – TFTP | **215** |
| Bad Hosts – VNC | **346** |
| Bad Hosts – HTTP | **3,601** |
| Bad Hosts – Telnet | **2,628** |
| Bad Hosts – MySQL | **668** |
| Bad Hosts – FTP | **544** |
| Bad Hosts – Memcached | **228** |
| Bad Hosts – ProConOs | **159** |
| Bad Hosts – Kubernetes | **912** |
| Bad Hosts – Redis | **440** |
| Bad Hosts – PostgreSQL | **521** |
| Bad Hosts – CouchDB | **388** |
| Bad Hosts – ClickhouseHTTP | **342** |
| Bad Hosts – Elasticsearch | **644** |
| Bad Hosts – Oracle | **259** |
| Bad Hosts – Modbus | **213** |
| Bad Hosts – LDAP | **262** |
| Bad Hosts – MQTT | **255** |
| Bad Hosts – RAW | **148** |
| Bad Hosts – LPD | **96** |
| Bad Hosts – HashCountRandom | **109** |
| Bad Hosts – IPP | **115** |
| Bad Hosts – MOTD | **81** |
| Bad Hosts – Docker | **5** |
| Bad Hosts – BitcoinRPC | **1** |
| Bad Hosts – Echo | **5** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-06)**: **8,503** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-06 | **8,503** |
| 2026-10-05 | **2,910** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,049** |
| Kandidaten dieses Abrufs | **14,049** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+390** |
| Entfernt | **-340** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-06 17:59 CEST (Berlin)*