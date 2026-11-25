# NETSHIELD – aktuelle DNS-Blocklisten

Stand: **2026-11-25 14:17 UTC**

Es werden nur Listen angezeigt, deren **konkrete Listen-Datei in den letzten 7 Tagen aktualisiert wurde**. Eine frische README oder irgendein anderer Repository-Commit reicht nicht.

**Wichtig:** Der Workflow aktiviert keine Liste automatisch. Er erstellt nur einen Fundbericht mit Raw-Links.

## 💡 Tipp: Diese Listen einbauen

- 🎣 **blazskufca/si-cert-dnsbl** / `domains.txt` - Phishing/Betrug, 940 neue Domains, 0 beliebte  
  `https://raw.githubusercontent.com/blazskufca/si-cert-dnsbl/main/domains.txt`

**Vielleicht - erst pruefen:**

- 🦠 asteroid-99942/apophis-blocklist / `lists/diff_report.txt` - ⚠️ pruefen: 2 beliebte Domain(s) - arenabg.com, paypalinc.com
- 🎣 fisventurous/fisphish / `data/discord-scams.txt` - ⚠️ pruefen: 2 beliebte Domain(s) - freecash.com, serveuser.com
- 🦠 Tagoletta/SiberGuvenlikBaskanligi-API / `data/days-120-domains.txt` - ⚠️ pruefen: 1 beliebte Domain(s) - earn.fm

## Alle Funde

| # | Tipp | Kategorie | Liste | Eintraege | Gesperrt | Neu | Beliebte Domains |
|---:|---|---|---|---:|---:|---:|---|
| 1 | ✅ einbauen | 🎣 Phishing/Betrug | [blazskufca/si-cert-dnsbl](https://github.com/blazskufca/si-cert-dnsbl)<br>[domains.txt](https://raw.githubusercontent.com/blazskufca/si-cert-dnsbl/main/domains.txt) · 0.1 d | 1.732 | 46 % | 940 | 0 ✅ |
| 2 | ⚠️ pruefen | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[diff_report.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/diff_report.txt) · 0.1 d | 6.639 | 77 % | 1.520 | ⚠️ 2: arenabg.com, paypalinc.com |
| 3 | ⚠️ pruefen | 🎣 Phishing/Betrug | [fisventurous/fisphish](https://github.com/fisventurous/fisphish)<br>[discord-scams.txt](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/discord-scams.txt) · 0.7 d | 32.235 | 15 % | 27.450 | ⚠️ 2: freecash.com, serveuser.com |
| 4 | ➖ kaum Neues | 🎣 Phishing/Betrug | [0xDanielLopez/phishunt-feed](https://github.com/0xDanielLopez/phishunt-feed)<br>[domains.txt](https://raw.githubusercontent.com/0xDanielLopez/phishunt-feed/main/blocklist/domains.txt) · 0.2 d | 754 | 91 % | 69 | ⚠️ 5: dothome.co.kr, hashnode.dev |
| 5 | ✅ schon drin | 🛡️ Sicherheit | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[all.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/security/all.txt) · 0.0 d | 74.088 | 100 % | 0 | 0 ✅ |
| 6 | ❌ nein | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[blocklist.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/blocklist.txt) · 0.1 d | 4.639.327 | 56 % | 2.023.746 | ⚠️ 1111: 000webhost.com, 13o.net |
| 7 | ❌ nein | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[blocklist_previous.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/lists/blocklist_previous.txt) · 0.1 d | 4.639.327 | 56 % | 2.023.746 | ⚠️ 1111: 000webhost.com, 13o.net |
| 8 | ❌ nein | 🦠 Malware/C2 | [asteroid-99942/apophis-blocklist](https://github.com/asteroid-99942/apophis-blocklist)<br>[hosts.txt](https://raw.githubusercontent.com/asteroid-99942/apophis-blocklist/main/output/hosts.txt) · 0.1 d | 4.639.327 | 56 % | 2.023.746 | ⚠️ 1111: 000webhost.com, 13o.net |
| 9 | ❌ nein | 🪙 Krypto-Drainer | [fisventurous/fisphish](https://github.com/fisventurous/fisphish)<br>[crypto-drainers.txt](https://raw.githubusercontent.com/fisventurous/fisphish/main/data/crypto-drainers.txt) · 0.3 d | 415.865 | 14 % | 359.720 | ⚠️ 9: deepl.network, digiday.com |
| 10 | ⚠️ pruefen | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[days-120-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/days-120-domains.txt) · 0.0 d | 19.396 | 82 % | 3.459 | ⚠️ 1: earn.fm |
| 11 | ➖ Kopie | 🦠 Malware/C2 | [rosical-labs/SiberGuvenlikBaskanligi-API](https://github.com/rosical-labs/SiberGuvenlikBaskanligi-API)<br>[days-120-domains.txt](https://raw.githubusercontent.com/rosical-labs/SiberGuvenlikBaskanligi-API/main/data/days-120-domains.txt) · 0.1 d | 19.361 | 82 % | 3.466 | ⚠️ 1: earn.fm |
| 12 | ❌ nein | 📢 Werbung/Tracker | [DanielEnki420/dns-blocklist-builder](https://github.com/DanielEnki420/dns-blocklist-builder)<br>[blocklist-all.pihole.txt](https://raw.githubusercontent.com/DanielEnki420/dns-blocklist-builder/main/lists/blocklist-all.pihole.txt) · 2.1 d | 2.006 | 79 % | 427 | ⚠️ 103: 33across.com, addthis.com |
| 13 | ➖ kaum Neues | 🦠 Malware/C2 | [Jam0k/Public-Feeds-IOCs](https://github.com/Jam0k/Public-Feeds-IOCs)<br>[domains.txt](https://raw.githubusercontent.com/Jam0k/Public-Feeds-IOCs/main/feeds/full/domains.txt) · 0.9 d | 2.403 | 81 % | 464 | ⚠️ 4: ccwu.cc, dedyn.io |
| 14 | ➖ Kopie | 🦠 Malware/C2 | [rosical-labs/SiberGuvenlikBaskanligi-API](https://github.com/rosical-labs/SiberGuvenlikBaskanligi-API)<br>[full-domains.txt](https://raw.githubusercontent.com/rosical-labs/SiberGuvenlikBaskanligi-API/main/data/full-domains.txt) · 0.1 d | 481.324 | 26 % | 354.077 | ⚠️ 27: 1fichier.com, 713mtauburnctcolumbusoh43085.st |
| 15 | ❌ nein | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/community/domains.txt) · 0.1 d | 1.184.432 | 36 % | 757.963 | ⚠️ 101: 1blu.de, 1fichier.com |
| 16 | ❌ nein | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/community_active/domains.txt) · 0.1 d | 516.755 | 72 % | 146.523 | ⚠️ 101: 1blu.de, 1fichier.com |
| 17 | ❌ nein | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary/domains.txt) · 0.1 d | 233.746 | 66 % | 78.762 | ⚠️ 16: blsp.at, glorioushop.com |
| 18 | ➖ kaum Neues | 🛡️ Sicherheit | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[ct.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/security/ct.txt) · 0.0 d | 74.077 | 100 % | 0 | 0 ✅ |
| 19 | ➖ kaum Neues | 🦠 Malware/C2 | [Jam0k/Public-Feeds-IOCs](https://github.com/Jam0k/Public-Feeds-IOCs)<br>[domains.txt](https://raw.githubusercontent.com/Jam0k/Public-Feeds-IOCs/main/feeds/domains.txt) · 0.9 d | 731 | 100 % | 0 | 0 ✅ |
| 20 | ❌ nein | 📢 Werbung/Tracker | [cenk/bad-hosts](https://github.com/cenk/bad-hosts)<br>[bad-hosts-domains](https://raw.githubusercontent.com/cenk/bad-hosts/main/bad-hosts-domains) · 0.4 d | 2.159.360 | 81 % | 403.279 | ⚠️ 2482: 000webhost.com, 071kk.com |
| 21 | ✅ schon drin | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[days-90-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/days-90-domains.txt) · 0.0 d | 13.904 | 100 % | 0 | ⚠️ 1: earn.fm |
| 22 | ➖ Kopie | 🦠 Malware/C2 | [rosical-labs/SiberGuvenlikBaskanligi-API](https://github.com/rosical-labs/SiberGuvenlikBaskanligi-API)<br>[days-90-domains.txt](https://raw.githubusercontent.com/rosical-labs/SiberGuvenlikBaskanligi-API/main/data/days-90-domains.txt) · 0.1 d | 13.874 | 100 % | 12 | ⚠️ 1: earn.fm |
| 23 | ➖ Kopie | 🦠 Malware/C2 | [rosical-labs/SiberGuvenlikBaskanligi-API](https://github.com/rosical-labs/SiberGuvenlikBaskanligi-API)<br>[days-60-domains.txt](https://raw.githubusercontent.com/rosical-labs/SiberGuvenlikBaskanligi-API/main/data/days-60-domains.txt) · 0.1 d | 9.396 | 100 % | 0 | ⚠️ 1: earn.fm |
| 24 | ❌ nein | 🎰 Gluecksspiel | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[all.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/gambling/all.txt) · 0.0 d | 946.860 | 28 % | 683.834 | ⚠️ 13: betting.co.zw, betway.co.bw |
| 25 | ❌ nein | 🎰 Gluecksspiel | [ezoblocker/ezoblocker.app](https://github.com/ezoblocker/ezoblocker.app)<br>[ct.txt](https://raw.githubusercontent.com/ezoblocker/ezoblocker.app/main/domains/gambling/ct.txt) · 0.0 d | 945.140 | 28 % | 682.210 | ⚠️ 6: covers.com, cricbet99.black |
| 26 | ✅ schon drin | 🎣 Phishing/Betrug | [phishdestroy/destroylist](https://github.com/phishdestroy/destroylist)<br>[domains.txt](https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/domains.txt) · 0.3 d | 139.799 | 100 % | 0 | ⚠️ 16: blsp.at, glorioushop.com |
| 27 | ❌ nein | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[full-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/full-domains.txt) · 0.0 d | 481.369 | 26 % | 354.078 | ⚠️ 27: 1fichier.com, 713mtauburnctcolumbusoh43085.st |
| 28 | ➖ kaum Neues | 🦠 Malware/C2 | [Tagoletta/SiberGuvenlikBaskanligi-API](https://github.com/Tagoletta/SiberGuvenlikBaskanligi-API)<br>[days-60-domains.txt](https://raw.githubusercontent.com/Tagoletta/SiberGuvenlikBaskanligi-API/main/data/days-60-domains.txt) · 0.0 d | 9.431 | 100 % | 0 | ⚠️ 1: earn.fm |
| 29 | ✅ schon drin | 🦠 Malware/C2 | [cenk/malware-domains](https://github.com/cenk/malware-domains)<br>[domains](https://raw.githubusercontent.com/cenk/malware-domains/main/domains) · 0.2 d | 1.947.648 | 100 % | 0 | ⚠️ 179: 000webhost.com, 2miners.com |
| 30 | ❌ nein | 🦠 Malware/C2 | [cenk/malware-domains](https://github.com/cenk/malware-domains)<br>[wildcard-domains](https://raw.githubusercontent.com/cenk/malware-domains/main/wildcard-domains) · 0.2 d | 1.684.315 | 100 % | 0 | ⚠️ 156: 000webhost.com, 2miners.com |

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
