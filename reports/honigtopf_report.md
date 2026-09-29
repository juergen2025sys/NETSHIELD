# Honigtopf – Report
**Aktualisiert:** 2026-09-29 09:04 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-29 09:04 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,312** |
| Bad Hosts – SIP | **163** |
| Bad Hosts – SSH | **2,826** |
| Bad Hosts – MSSQL | **499** |
| Bad Hosts – RDP | **678** |
| Bad Hosts – SNMP | **296** |
| Bad Hosts – HTTP | **4,603** |
| Bad Hosts – VNC | **301** |
| Bad Hosts – ProConOs | **138** |
| Bad Hosts – Telnet | **2,484** |
| Bad Hosts – PostgreSQL | **412** |
| Bad Hosts – TFTP | **180** |
| Bad Hosts – MySQL | **360** |
| Bad Hosts – Kubernetes | **674** |
| Bad Hosts – Elasticsearch | **542** |
| Bad Hosts – FTP | **282** |
| Bad Hosts – Redis | **333** |
| Bad Hosts – CouchDB | **245** |
| Bad Hosts – ClickhouseHTTP | **277** |
| Bad Hosts – LDAP | **179** |
| Bad Hosts – Oracle | **224** |
| Bad Hosts – Modbus | **180** |
| Bad Hosts – RAW | **130** |
| Bad Hosts – MQTT | **195** |
| Bad Hosts – Memcached | **166** |
| Bad Hosts – IPP | **113** |
| Bad Hosts – HashCountRandom | **71** |
| Bad Hosts – MOTD | **66** |
| Bad Hosts – LPD | **42** |
| Bad Hosts – Echo | **3** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-29)**: **6,195** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-29 | **6,195** |
| 2026-09-28 | **5,117** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,462** |
| Kandidaten dieses Abrufs | **13,462** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+3,356** |
| Entfernt | **-1,300** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-29 09:04 CEST (Berlin)*