# Honigtopf – Report
**Aktualisiert:** 2026-10-02 21:51 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-10-02 21:51 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **10,619** |
| Bad Hosts – SIP | **154** |
| Bad Hosts – SSH | **2,946** |
| Bad Hosts – VNC | **440** |
| Bad Hosts – SNMP | **369** |
| Bad Hosts – MSSQL | **514** |
| Bad Hosts – HTTP | **3,495** |
| Bad Hosts – RDP | **808** |
| Bad Hosts – MySQL | **609** |
| Bad Hosts – Telnet | **3,001** |
| Bad Hosts – ProConOs | **190** |
| Bad Hosts – FTP | **543** |
| Bad Hosts – TFTP | **197** |
| Bad Hosts – PostgreSQL | **419** |
| Bad Hosts – Kubernetes | **818** |
| Bad Hosts – CouchDB | **330** |
| Bad Hosts – Redis | **422** |
| Bad Hosts – Elasticsearch | **479** |
| Bad Hosts – ClickhouseHTTP | **339** |
| Bad Hosts – Oracle | **277** |
| Bad Hosts – Modbus | **198** |
| Bad Hosts – MQTT | **223** |
| Bad Hosts – Memcached | **254** |
| Bad Hosts – LDAP | **186** |
| Bad Hosts – RAW | **124** |
| Bad Hosts – IPP | **112** |
| Bad Hosts – HashCountRandom | **126** |
| Bad Hosts – LPD | **76** |
| Bad Hosts – MOTD | **36** |
| Bad Hosts – Echo | **3** |
| Bad Hosts – WebLogic | **1** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-10-02)**: **9,285** IPs

| last_seen | IPs |
|---|---:|
| 2026-10-02 | **9,285** |
| 2026-10-01 | **1,334** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,464** |
| Kandidaten dieses Abrufs | **13,464** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+316** |
| Entfernt | **-1,254** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-10-02 21:51 CEST (Berlin)*