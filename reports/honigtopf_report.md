# Honigtopf – Report
**Aktualisiert:** 2026-09-23 01:26 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-23 01:26 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,252** |
| Bad Hosts – SIP | **273** |
| Bad Hosts – RDP | **944** |
| Bad Hosts – SSH | **3,981** |
| Bad Hosts – MSSQL | **535** |
| Bad Hosts – SNMP | **388** |
| Bad Hosts – HTTP | **2,930** |
| Bad Hosts – VNC | **347** |
| Bad Hosts – Telnet | **2,832** |
| Bad Hosts – TFTP | **210** |
| Bad Hosts – MySQL | **683** |
| Bad Hosts – ProConOs | **150** |
| Bad Hosts – PostgreSQL | **610** |
| Bad Hosts – FTP | **537** |
| Bad Hosts – Kubernetes | **726** |
| Bad Hosts – Redis | **443** |
| Bad Hosts – Elasticsearch | **572** |
| Bad Hosts – CouchDB | **239** |
| Bad Hosts – ClickhouseHTTP | **269** |
| Bad Hosts – MQTT | **254** |
| Bad Hosts – Oracle | **295** |
| Bad Hosts – LDAP | **340** |
| Bad Hosts – Modbus | **224** |
| Bad Hosts – RAW | **255** |
| Bad Hosts – Memcached | **269** |
| Bad Hosts – IPP | **131** |
| Bad Hosts – LPD | **102** |
| Bad Hosts – HashCountRandom | **107** |
| Bad Hosts – MOTD | **65** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-22)**: **11,009** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-23 | **16** |
| 2026-09-22 | **11,009** |
| 2026-09-21 | **227** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **14,272** |
| Kandidaten dieses Abrufs | **14,272** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+582** |
| Entfernt | **-441** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-23 01:26 CEST (Berlin)*