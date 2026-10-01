# Honigtopf – Report
**Aktualisiert:** 2026-10-01 15:46 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-01 15:46 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,611** |
| Bad Hosts – SIP | **163** |
| Bad Hosts – SSH | **3,951** |
| Bad Hosts – RDP | **683** |
| Bad Hosts – MSSQL | **459** |
| Bad Hosts – HTTP | **2,792** |
| Bad Hosts – SNMP | **432** |
| Bad Hosts – VNC | **279** |
| Bad Hosts – MySQL | **565** |
| Bad Hosts – Telnet | **2,893** |
| Bad Hosts – FTP | **430** |
| Bad Hosts – ProConOs | **95** |
| Bad Hosts – PostgreSQL | **346** |
| Bad Hosts – TFTP | **255** |
| Bad Hosts – Kubernetes | **501** |
| Bad Hosts – Elasticsearch | **565** |
| Bad Hosts – Redis | **349** |
| Bad Hosts – CouchDB | **269** |
| Bad Hosts – Oracle | **314** |
| Bad Hosts – ClickhouseHTTP | **285** |
| Bad Hosts – Modbus | **158** |
| Bad Hosts – Memcached | **163** |
| Bad Hosts – RAW | **101** |
| Bad Hosts – LDAP | **158** |
| Bad Hosts – MQTT | **165** |
| Bad Hosts – IPP | **102** |
| Bad Hosts – HashCountRandom | **116** |
| Bad Hosts – LPD | **63** |
| Bad Hosts – MOTD | **55** |
| Bad Hosts – Echo | **6** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |
| Bad Hosts – DNS.udp | **0** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-01)**: **6,359** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-01 | **6,359** |
| 2026-09-30 | **4,252** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,305** |
| Kandidaten dieses Abrufs | **13,305** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+414** |
| Entfernt | **-2,172** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-01 15:46 CEST (Berlin)*