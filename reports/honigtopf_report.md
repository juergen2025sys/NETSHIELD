# Honigtopf – Report
**Aktualisiert:** 2026-09-28 20:16 CEST (Berlin)  
**Modus:** `VOLL` (voll: /services + /bad-hosts + alle Service-Endpunkte)

---
## API-Key-Status

| Credential | Status |
|---|---|
| cred1 | ✅ gültig (HTTP 200) |
| cred2 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |
| cred3 | ⚠️ HTTP 402 auf Daten-Endpunkt – für diesen Lauf deaktiviert |

---
## Freshness (liefert die API wirklich neue Daten?)

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-28 20:16 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **8,531** |
| Bad Hosts – SIP | **146** |
| Bad Hosts – RDP | **687** |
| Bad Hosts – SSH | **2,824** |
| Bad Hosts – MSSQL | **489** |
| Bad Hosts – VNC | **264** |
| Bad Hosts – SNMP | **296** |
| Bad Hosts – HTTP | **1,863** |
| Bad Hosts – ProConOs | **156** |
| Bad Hosts – PostgreSQL | **397** |
| Bad Hosts – Telnet | **2,415** |
| Bad Hosts – TFTP | **141** |
| Bad Hosts – FTP | **206** |
| Bad Hosts – Kubernetes | **699** |
| Bad Hosts – MySQL | **315** |
| Bad Hosts – Redis | **327** |
| Bad Hosts – Elasticsearch | **536** |
| Bad Hosts – ClickhouseHTTP | **272** |
| Bad Hosts – CouchDB | **210** |
| Bad Hosts – Oracle | **190** |
| Bad Hosts – Modbus | **190** |
| Bad Hosts – LDAP | **218** |
| Bad Hosts – MQTT | **214** |
| Bad Hosts – RAW | **139** |
| Bad Hosts – Memcached | **148** |
| Bad Hosts – IPP | **96** |
| Bad Hosts – LPD | **57** |
| Bad Hosts – HashCountRandom | **28** |
| Bad Hosts – MOTD | **59** |
| Bad Hosts – Echo | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-28)**: **6,702** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-28 | **6,702** |
| 2026-09-27 | **1,829** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **10,577** |
| Kandidaten dieses Abrufs | **10,577** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+2,957** |
| Entfernt | **-3,874** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-28 20:16 CEST (Berlin)*