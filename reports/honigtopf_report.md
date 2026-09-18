# Honigtopf – Report
**Aktualisiert:** 2026-09-18 13:15 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-18 13:15 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **40,515** |
| Bad Hosts – SIP | **174** |
| Bad Hosts – MSSQL | **929** |
| Bad Hosts – VNC | **1,549** |
| Bad Hosts – SSH | **3,886** |
| Bad Hosts – RDP | **1,163** |
| Bad Hosts – SNMP | **435** |
| Bad Hosts – HTTP | **4,537** |
| Bad Hosts – FTP | **27,172** |
| Bad Hosts – TFTP | **234** |
| Bad Hosts – ProConOs | **175** |
| Bad Hosts – Telnet | **3,065** |
| Bad Hosts – PostgreSQL | **584** |
| Bad Hosts – MySQL | **681** |
| Bad Hosts – Kubernetes | **775** |
| Bad Hosts – Redis | **398** |
| Bad Hosts – Elasticsearch | **428** |
| Bad Hosts – CouchDB | **256** |
| Bad Hosts – Oracle | **299** |
| Bad Hosts – ClickhouseHTTP | **268** |
| Bad Hosts – Modbus | **199** |
| Bad Hosts – Memcached | **258** |
| Bad Hosts – RAW | **224** |
| Bad Hosts – LDAP | **214** |
| Bad Hosts – MQTT | **267** |
| Bad Hosts – IPP | **116** |
| Bad Hosts – HashCountRandom | **196** |
| Bad Hosts – LPD | **61** |
| Bad Hosts – MOTD | **64** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-18)**: **17,638** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-18 | **17,638** |
| 2026-09-17 | **22,877** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **44,112** |
| Kandidaten dieses Abrufs | **44,112** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,217** |
| Entfernt | **-2,389** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-18 13:15 CEST (Berlin)*