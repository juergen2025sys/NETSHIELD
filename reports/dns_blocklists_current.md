# NETSHIELD – aktuelle DNS-Blocklisten

Stand: **2026-11-24 14:52 UTC**

Es werden nur Listen angezeigt, deren **konkrete Listen-Datei in den letzten 7 Tagen aktualisiert wurde**. Eine frische README oder irgendein anderer Repository-Commit reicht nicht.

**Wichtig:** Der Workflow aktiviert keine Liste automatisch. Er erstellt nur einen Fundbericht mit Raw-Links.

## 💡 Tipp: Diese Listen einbauen

- 🦠 **asteroid-99942/apophis-blocklist** / `lists/diff_report.txt` - Malware/C2, 1.068 neue Domains, 0 beliebte  
  `https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/diff_report.txt`
- 🎣 **blazskufca/si-cert-dnsbl** / `domains.txt` - Phishing/Betrug, 993 neue Domains, 0 beliebte  
  `https://raw.githubusercontent.com/blazskufca/si-cert-dnsbl/main/domains.txt`

**Vielleicht - erst pruefen:**

- 🎣 fisventurous/fisphish / `data/discord-scams.txt` - ⚠️ pruefen: 2 beliebte Domain(s) - freecash.com, serveuser.com
- 🦠 Tagoletta/SiberGuvenlikBaskanligi-API / `data/days-120-domains.txt` - ⚠️ pruefen: 1 beliebte Domain(s) - earn.fm

## Alle Funde

| # | Tipp | Kategorie | Liste | Eintraege | Gesperrt | Neu | Beliebte Domains |
|---:|---|---|---|---:|---:|---:|---|
| 1 | ✅ einbauen | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[diff_report.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/diff_report.txt) · 0.1 d | 4.150 | 74 % | 1.068 | 0 ✅ |
| 2 | ✅ einbauen | 🎣 Phishing/Betrug | [blazskufca/si-cert-dnsbl](https://github.com/blazskufca/si-cert-dnsbl)<br>[domains.txt](https://raw.githubusercontent.com/blazskufca/si-cert-dnsbl/main/domains.txt) · 0.1 d | 1.731 | 43 % | 993 | 0 ✅ |
| 3 | ⚠️ pruefen | 🎣 Phishing/Betrug | [fisventurous/fisphish](https://github.com/fisventurous/fisphish)<br>[discord-scams.txt](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/discord-scams.txt) · 0.3 d | 32.227 | 15 % | 27.336 | ⚠️ 2: freecash.com, serveuser.com |
| 4 | ➖ kaum Neues | 🎣 Phishing/Betrug | [0xDanielLopez/phishunt-feed](https://github.com/0xDanielLopez/phishunt-feed)<br>[domains.txt](https://raw.githubusercontent.com/0xDanielLopez/phishunt-feed/main/blocklist/domains.txt) · 0.2 d | 805 | 94 % | 49 | ⚠️ 4: dothome.co.kr, hashnode.dev |
| 5 | ✅ schon drin | 🛡️ Sicherheit | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[all.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/security/all.txt) · 0.0 d | 75.074 | 100 % | 0 | 0 ✅ |
| 6 | ❌ nein | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[blocklist.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/blocklist.txt) · 0.1 d | 4.638.370 | 62 % | 1.752.980 | ⚠️ 1116: 000webhost.com, 13o.net |
| 7 | ❌ nein | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[blocklist_previous.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/blocklist_previous.txt) · 0.1 d | 4.638.370 | 62 % | 1.752.980 | ⚠️ 1116: 000webhost.com, 13o.net |
| 8 | ❌ nein | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[hosts.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/output/hosts.txt) · 0.1 d | 4.638.370 | 62 % | 1.752.980 | ⚠️ 1116: 000webhost.com, 13o.net |
| 9 | ❌ nein | 🪙 Krypto-Drainer | [fisventurous/fisphish](https://github.com/fisventurous/fisphish)<br>[crypto-drainers.txt](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/crypto-drainers.txt) · 0.3 d | 415.751 | 13 % | 360.177 | ⚠️ 9: deepl.network, digiday.com |
| 10 | ⚠️ pruefen | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[days-120-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/days-120-domains.txt) · 0.0 d | 19.285 | 90 % | 1.858 | ⚠️ 1: earn.fm |
| 11 | ➖ Kopie | 🦠 Malware/C2 | [rosical-labs/SiberGuvenlikBaskanligi-API](https://github.com/rosical-labs/SiberGuvenlikBaskanligi-API)<br>[days-120-domains.txt](https://raw.githubusercontent.com/rosical-labs/SiberGuvenlikBaskanligi-API/main/data/days-120-domains.txt) · 0.3 d | 19.303 | 90 % | 1.878 | ⚠️ 1: earn.fm |
| 12 | ❌ nein | 📢 Werbung/Tracker | [DanielEnki420/dns-blocklist-builder](https://github.com/DanielEnki420/dns-blocklist-builder)<br>[blocklist-all.pihole.txt](https://raw.githubusercontent.com/DanielEnki420/dns-blocklist-builder/main/lists/blocklist-all.pihole.txt) · 1.1 d | 2.006 | 80 % | 409 | ⚠️ 103: 33across.com, addthis.com |
| 13 | ❌ nein | 🛡️ Sicherheit | [PhishIndex/phishindex-blocklist](https://github.com/PhishIndex/phishindex-blocklist)<br>[all_domains.txt](https://raw.githubusercontent.com/PhishIndex/phishindex-blocklist/main/Data/Malicious%20Domains/txt/all_domains.txt) · 0.1 d | 240.848 | 68 % | 78.219 | ⚠️ 25: binance.info, blsp.at |
| 14 | ➖ kaum Neues | 🦠 Malware/C2 | [Jam0k/Public-Feeds-IOCs](https://github.com/Jam0k/Public-Feeds-IOCs)<br>[domains.txt](https://raw.githubusercontent.com/Jam0k/Public-Feeds-IOCs/main/feeds/full/domains.txt) · 0.9 d | 2.385 | 81 % | 449 | ⚠️ 4: ccwu.cc, dedyn.io |
| 15 | ❌ nein | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/community/domains.txt) · 0.4 d | 1.183.301 | 36 % | 759.486 | ⚠️ 102: 1blu.de, 1fichier.com |
| 16 | ❌ nein | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary/domains.txt) · 0.4 d | 233.541 | 66 % | 78.387 | ⚠️ 16: blsp.at, glorioushop.com |
| 17 | ❌ nein | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/community_active/domains.txt) · 0.4 d | 516.247 | 71 % | 148.582 | ⚠️ 102: 1blu.de, 1fichier.com |
| 18 | ➖ kaum Neues | 🛡️ Sicherheit | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[ct.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/security/ct.txt) · 0.0 d | 75.063 | 100 % | 0 | 0 ✅ |
| 19 | ➖ kaum Neues | 🦠 Malware/C2 | [Jam0k/Public-Feeds-IOCs](https://github.com/Jam0k/Public-Feeds-IOCs)<br>[domains.txt](https://raw.githubusercontent.com/Jam0k/Public-Feeds-IOCs/main/feeds/domains.txt) · 0.9 d | 658 | 100 % | 0 | 0 ✅ |
| 20 | ❌ nein | 📢 Werbung/Tracker | [cenk/bad-hosts](https://github.com/cenk/bad-hosts)<br>[bad-hosts-domains](https://raw.githubusercontent.com/cenk/bad-hosts/main/bad-hosts-domains) · 0.4 d | 2.147.248 | 82 % | 397.560 | ⚠️ 2488: 000webhost.com, 071kk.com |
| 21 | ✅ schon drin | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[days-90-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/days-90-domains.txt) · 0.0 d | 13.776 | 100 % | 0 | ⚠️ 1: earn.fm |
| 22 | ➖ Kopie | 🦠 Malware/C2 | [rosical-labs/SiberGuvenlikBaskanligi-API](https://github.com/rosical-labs/SiberGuvenlikBaskanligi-API)<br>[days-90-domains.txt](https://raw.githubusercontent.com/rosical-labs/SiberGuvenlikBaskanligi-API/main/data/days-90-domains.txt) · 0.3 d | 13.849 | 100 % | 33 | ⚠️ 1: earn.fm |
| 23 | ➖ Kopie | 🦠 Malware/C2 | [rosical-labs/SiberGuvenlikBaskanligi-API](https://github.com/rosical-labs/SiberGuvenlikBaskanligi-API)<br>[days-60-domains.txt](https://raw.githubusercontent.com/rosical-labs/SiberGuvenlikBaskanligi-API/main/data/days-60-domains.txt) · 0.3 d | 9.294 | 100 % | 0 | ⚠️ 1: earn.fm |
| 24 | ❌ nein | 🎰 Gluecksspiel | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[all.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/gambling/all.txt) · 0.0 d | 917.291 | 28 % | 664.260 | ⚠️ 13: betting.co.zw, betway.co.bw |
| 25 | ❌ nein | 🎰 Gluecksspiel | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[ct.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/gambling/ct.txt) · 0.0 d | 915.618 | 28 % | 662.679 | ⚠️ 6: covers.com, cricbet99.black |
| 26 | ✅ schon drin | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/domains.txt) · 0.4 d | 139.906 | 100 % | 0 | ⚠️ 16: blsp.at, glorioushop.com |
| 27 | ❌ nein | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[full-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/full-domains.txt) · 0.0 d | 481.076 | 28 % | 343.862 | ⚠️ 27: 1fichier.com, 713mtauburnctcolumbusoh43085.st |
| 28 | ➖ kaum Neues | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[days-60-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/days-60-domains.txt) · 0.0 d | 9.232 | 100 % | 0 | ⚠️ 1: earn.fm |
| 29 | ✅ schon drin | 🦠 Malware/C2 | [cenk/malware-domains](https://github.com/cenk/malware-domains)<br>[domains](https://raw.githubusercontent.com/cenk/malware-domains/main/domains) · 0.2 d | 2.911.764 | 100 % | 0 | ⚠️ 173: 000webhost.com, 2miners.com |
| 30 | ❌ nein | 🦠 Malware/C2 | [cenk/malware-domains](https://github.com/cenk/malware-domains)<br>[wildcard-domains](https://raw.githubusercontent.com/cenk/malware-domains/main/wildcard-domains) · 0.2 d | 2.643.939 | 100 % | 0 | ⚠️ 151: 000webhost.com, 2miners.com |

## Bedeutung

- **Reihenfolge:** nach Score (Frische am staerksten, Abzuege fuer beliebte Domains, Abdeckung und genutzte Listen). Score, Format, Groesse und Datum stehen in `dns_blocklists_current.json`.
- **Liste:** Repo-Link, darunter die Datei (Link = Download-Adresse fuer Unbound) und ihr Alter in Tagen.
- **Tipp:** ✅ einbauen = Schutz-Kategorie, 0 beliebte Domains, mind. 500 neue · ⚠️ pruefen · ❌ nicht (Gluecksspiel/Erwachsene/Werbung, >5 beliebte Domains) · ➖ bringt kaum Neues oder ist eine Kopie.
- **Kategorie:** erkannt an Dateipfad, Repo-Name/-Beschreibung und am Inhalt (Anteil Gluecksspiel-/Erwachsenen-Namen ab 30 %).
- **✅ schon drin** = URL steht schon in Unbound oder NETSHIELD · **➖ Kopie** = Spiegel einer genutzten Quelle unter anderem Konto · **❔ zu gross** = Datei nicht voll pruefbar.
- **Schon gesperrt / Neu fuer mich:** Abgleich mit allen eigenen Unbound-Listen (eigene URLs + AdGuard, StevenBlack, OISD NSFW, Hagezi Pro++/TIF/DoH-Bypass + Unbound-Wildcard-Domains wie pages.dev/workers.dev), exakt und ueber die Hauptdomain (Wildcard). Score-Abzug ab 80 % (-10) und 95 % (-25) Abdeckung.
- **Beliebte Domains:** Treffer aus den 20.000 meistbesuchten Domains (Tranco). Jeder Treffer waere eine echte Seite. die gesperrt wuerde.
- **Eintraege:** Anzahl Domains in der ganzen Datei (nicht nur Stichprobe).
- **OPNsense direkt = Ja:** Stichprobe besteht zu mindestens 98 % aus reinen Domains/Wildcards.
- **dnsmasq / hosts / adblock:** gefunden, aber nicht als direkte reine Domainliste markiert.
- **Maximal 7 Tage alt:** aeltere Listen werden gar nicht erst im Report ausgegeben.

Der Score sagt nichts darueber aus, ob eine Liste garantiert frei von False Positives ist.
