# Honigtopf – Report
**Aktualisiert:** 2026-09-25 19:07 CEST (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-09-25 19:07 CEST (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **11,019** |
| Bad Hosts – SIP | **151** |
| Bad Hosts – SSH | **3,474** |
| Bad Hosts – RDP | **756** |
| Bad Hosts – MSSQL | **491** |
| Bad Hosts – HTTP | **3,561** |
| Bad Hosts – ProConOs | **155** |
| Bad Hosts – VNC | **267** |
| Bad Hosts – TFTP | **191** |
| Bad Hosts – SNMP | **354** |
| Bad Hosts – Telnet | **2,840** |
| Bad Hosts – MySQL | **599** |
| Bad Hosts – PostgreSQL | **456** |
| Bad Hosts – FTP | **477** |
| Bad Hosts – Kubernetes | **638** |
| Bad Hosts – Redis | **465** |
| Bad Hosts – Elasticsearch | **566** |
| Bad Hosts – CouchDB | **207** |
| Bad Hosts – ClickhouseHTTP | **211** |
| Bad Hosts – Oracle | **246** |
| Bad Hosts – Memcached | **165** |
| Bad Hosts – Modbus | **167** |
| Bad Hosts – MQTT | **160** |
| Bad Hosts – LDAP | **202** |
| Bad Hosts – RAW | **139** |
| Bad Hosts – IPP | **93** |
| Bad Hosts – LPD | **74** |
| Bad Hosts – HashCountRandom | **23** |
| Bad Hosts – MOTD | **16** |
| Bad Hosts – Echo | **4** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-09-25)**: **8,588** IPs

| last_seen | IPs |
|---|---:|
| 2026-09-25 | **8,588** |
| 2026-09-24 | **2,431** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **13,498** |
| Kandidaten dieses Abrufs | **13,498** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+1,057** |
| Entfernt | **-1,326** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-09-25 19:07 CEST (Berlin)*