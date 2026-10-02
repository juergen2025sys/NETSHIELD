# Honigtopf – Report
**Aktualisiert:** 2026-10-02 13:14 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 13:14 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,663** |
| Bad Hosts – SIP | **170** |
| Bad Hosts – SSH | **3,029** |
| Bad Hosts – MSSQL | **520** |
| Bad Hosts – SNMP | **412** |
| Bad Hosts – RDP | **768** |
| Bad Hosts – HTTP | **3,491** |
| Bad Hosts – VNC | **464** |
| Bad Hosts – MySQL | **661** |
| Bad Hosts – ProConOs | **186** |
| Bad Hosts – Telnet | **3,058** |
| Bad Hosts – FTP | **554** |
| Bad Hosts – TFTP | **188** |
| Bad Hosts – PostgreSQL | **404** |
| Bad Hosts – Kubernetes | **820** |
| Bad Hosts – Redis | **415** |
| Bad Hosts – CouchDB | **324** |
| Bad Hosts – Elasticsearch | **475** |
| Bad Hosts – Oracle | **292** |
| Bad Hosts – ClickhouseHTTP | **273** |
| Bad Hosts – Modbus | **207** |
| Bad Hosts – MQTT | **260** |
| Bad Hosts – Memcached | **225** |
| Bad Hosts – LDAP | **190** |
| Bad Hosts – HashCountRandom | **150** |
| Bad Hosts – RAW | **91** |
| Bad Hosts – IPP | **95** |
| Bad Hosts – LPD | **65** |
| Bad Hosts – MOTD | **80** |
| Bad Hosts – Echo | **4** |
| Bad Hosts – Random | **1** |
| Bad Hosts – WebLogic | **2** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **5,796** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **5,796** |
| 2026-10-01 | **4,867** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,521** |
| Kandidaten dieses Abrufs | **13,521** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+807** |
| Entfernt | **-658** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 13:14 CEST (Berlin)*