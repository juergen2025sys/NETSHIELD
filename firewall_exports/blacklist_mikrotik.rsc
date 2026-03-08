# NETSHIELD Blacklist – Mikrotik RouterOS
# Aktualisiert: 2026-03-08 18:12 UTC
# Eintraege: 0
# Import: /import file=blacklist_mikrotik.rsc

# Bestehende Liste leeren
/ip firewall address-list remove [find list=NETSHIELD_Blacklist]

# Neue Eintraege hinzufuegen
