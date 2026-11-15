# Honigtopf – Report
**Aktualisiert:** 2026-11-15 07:25 CET (Berlin)  
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

🟢 Aktiv – letzte Änderung im Roh-Abruf: 2026-11-15 07:25 CET (Berlin) (0 unveränderte Läufe seither).

---
## Endpunkte & Ergebnisse

| Endpunkt | Treffer |
|---|---:|
| Bad Hosts (24h, alle Dienste) | **32,049** |
| Bad Hosts – SIP | **1,853** |
| Bad Hosts – RDP | **575** |
| Bad Hosts – SSH | **3,331** |
| Bad Hosts – SNMP | **212** |
| Bad Hosts – MSSQL | **254** |
| Bad Hosts – VNC | **237** |
| Bad Hosts – HTTP | **3,845** |
| Bad Hosts – BitcoinP2P | **783** |
| Bad Hosts – FTP | **16,186** |
| Bad Hosts – ProConOs | **76** |
| Bad Hosts – Telnet | **2,241** |
| Bad Hosts – PostgreSQL | **186** |
| Bad Hosts – MySQL | **298** |
| Bad Hosts – ClickhouseHTTP | **285** |
| Bad Hosts – Redis | **561** |
| Bad Hosts – Docker | **113** |
| Bad Hosts – Kubernetes | **448** |
| Bad Hosts – TFTP | **106** |
| Bad Hosts – CouchDB | **171** |
| Bad Hosts – EVMRPC | **37** |
| Bad Hosts – Elasticsearch | **312** |
| Bad Hosts – BitcoinRPC.dogecoin | **305** |
| Bad Hosts – BitcoinRPC | **275** |
| Bad Hosts – BitcoinRPC.dash | **63** |
| Bad Hosts – Oracle | **102** |
| Bad Hosts – Memcached | **89** |
| Bad Hosts – BitcoinRPC.litecoin | **40** |
| Bad Hosts – Modbus | **109** |
| Bad Hosts – RAW | **87** |
| Bad Hosts – Electrum | **25** |
| Bad Hosts – IPP | **53** |
| Bad Hosts – MQTT | **77** |
| Bad Hosts – HashCountRandom | **52** |
| Bad Hosts – LDAP | **67** |
| Bad Hosts – BeaconAPI.web3signer | **59** |
| Bad Hosts – LPD | **24** |
| Bad Hosts – LND | **67** |
| Bad Hosts – ClaymoreAPI | **28** |
| Bad Hosts – IPFS | **32** |
| Bad Hosts – MOTD | **22** |
| Bad Hosts – BitcoinP2P.litecoin | **9** |
| Bad Hosts – BeaconAPI | **21** |
| Bad Hosts – SubstrateRPC | **16** |
| Bad Hosts – XMRigAPI | **32** |
| Bad Hosts – MoneroRPC | **11** |
| Bad Hosts – WebLogic | **4** |
| Bad Hosts – MoneroRPC.restricted | **3** |
| Bad Hosts – BitcoinP2P.dogecoin | **9** |
| Bad Hosts – SolanaRPC | **4** |
| Bad Hosts – MoneroRPC.wallet | **4** |
| Bad Hosts – BeaconAPI.engine | **7** |
| Bad Hosts – SubstrateRPC.legacy | **10** |
| Bad Hosts – CgminerAPI | **10** |
| Bad Hosts – BeaconAPI.keymanager | **8** |
| Bad Hosts – BitcoinRPC.zcash | **8** |
| Bad Hosts – Echo | **6** |

---
## Feed-Frische – /bad-hosts (last_seen)

Davon **heute (2026-11-15)**: **8,569** IPs

| last_seen | IPs |
|---|---:|
| 2026-11-15 | **8,569** |
| 2026-11-14 | **23,480** |

---
| Metrik | Wert |
|---|---|
| Gesamt Honigtopf-IPs | **32,142** |
| Kandidaten dieses Abrufs | **32,142** |
| Veroeffentlichung | Veröffentlicht |
| Neu | **+7,598** |
| Entfernt | **-10,398** |

---
> ℹ️ Die IPs werden automatisch vom **update_combined_blacklist**-Workflow eingelesen.

---
*Generiert: 2026-11-15 07:25 CET (Berlin)*