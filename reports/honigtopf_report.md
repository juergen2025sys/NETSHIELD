# Honigtopf – Report
**Aktualisiert:** 2026-09-18 12:00 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 12:00 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **40,761** |
| Bad Hosts – SIP | **173** |
| Bad Hosts – MSSQL | **921** |
| Bad Hosts – VNC | **1,557** |
| Bad Hosts – SSH | **3,858** |
| Bad Hosts – RDP | **1,168** |
| Bad Hosts – SNMP | **445** |
| Bad Hosts – HTTP | **4,526** |
| Bad Hosts – FTP | **27,465** |
| Bad Hosts – TFTP | **234** |
| Bad Hosts – ProConOs | **170** |
| Bad Hosts – Telnet | **3,076** |
| Bad Hosts – PostgreSQL | **569** |
| Bad Hosts – MySQL | **677** |
| Bad Hosts – Kubernetes | **779** |
| Bad Hosts – Redis | **399** |
| Bad Hosts – Elasticsearch | **421** |
| Bad Hosts – CouchDB | **257** |
| Bad Hosts – Oracle | **297** |
| Bad Hosts – ClickhouseHTTP | **266** |
| Bad Hosts – Modbus | **205** |
| Bad Hosts – Memcached | **263** |
| Bad Hosts – MQTT | **259** |
| Bad Hosts – LDAP | **209** |
| Bad Hosts – RAW | **179** |
| Bad Hosts – IPP | **113** |
| Bad Hosts – HashCountRandom | **196** |
| Bad Hosts – LPD | **47** |
| Bad Hosts – MOTD | **62** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **15,263** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **15,263** |
| 2026-09-17 | **25,498** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **44,284** |
| Kandidaten dieses Abrufs | **44,284** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+3,698** |
| Entfernt | **-3,940** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 12:00 CEST (Berlin)*