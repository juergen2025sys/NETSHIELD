# Security Policy

## Unterstützte Versionen

NETSHIELD wird auf dem `main`-Branch aktiv gepflegt. Es gibt derzeit keine versionierten Releases — nutze immer den aktuellen Stand von `main`.

## Sicherheitslücke melden

**Bitte erstelle KEIN öffentliches Issue für Sicherheitsprobleme.**

Melde Schwachstellen stattdessen vertraulich über:

- **GitHub Private Vulnerability Reporting:** [Security → Report a vulnerability](https://github.com/juergen2025sys/NETSHIELD/security/advisories/new)

Alternativ per E-Mail an den Repository-Inhaber (siehe GitHub-Profil).

### Was gehört in eine Meldung?

- Beschreibung der Schwachstelle
- Schritte zur Reproduktion
- Betroffene Dateien / Workflows
- Mögliche Auswirkung (z.B. Whitelist-Bypass, IP-Injection, Cache-Manipulation)

### Reaktionszeit

- Bestätigung innerhalb von **72 Stunden**
- Einschätzung und Zeitplan innerhalb von **7 Tagen**
- Fix oder Workaround so schnell wie möglich

## Scope

Relevante Sicherheitsthemen für dieses Projekt:

- Manipulation der Blocklisten oder Whitelist
- Injection von IPs über Community Reports oder Auto Feed Discovery
- Zugriff auf API-Keys oder Secrets
- Umgehung von Schutzmechanismen (Leerungsschutz, Rate-Limiting, FP-Filter)
- Cache-Poisoning der seen_db

## Danke

Verantwortungsvolle Meldungen helfen, die Infrastruktur aller NETSHIELD-Nutzer zu schützen.
