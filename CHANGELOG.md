# Changelog

## 0.1.2 — parent glue, DNSBL safety and documentation

- Inspect authoritative parent referrals (AUTHORITY delegation, ADDITIONAL glue) rather than treating recursive A/AAAA responses as glue.
- Compare in-domain nameserver parent A/AAAA glue with child authoritative addresses; identify missing glue and mismatches, with RFC 9471 nuances.
- Retry truncated referrals over TCP and compare up to two parent authorities.
- Classify Spamhaus 127.255.255.x policy/errors as INCONCLUSIVE, not blacklist hits.
- Add detailed README, manual, DNS/glue and DNSBL explanations, prepublication test instructions and smoke script.
- Move Debian source packaging metadata to standard 3.0 (quilt) / 0.1.2-1 for non-native distribution.


## 0.1.1 — packaging and dialog fixes

- Fix interactive `zwhois -d` screen visibility by preserving terminal output and capturing selections on a separate file descriptor.
- Stop listing RPM documentation twice.
- Install a terminal dialog provider with RPM/DEB packages.

## 0.1.0 — initial test release

- Domain/IP/ASN RDAP, lifecycle dates, nameservers
- Optional web/mail hosting checks, subdomains, SPF/DMARC/DKIM selector checks
- Configurable DNSBL queries, authoritative IPv4/IPv6 UDP/TCP tests
- Interactive dialog/whiptail menu
- Source tarball, RPM spec, Debian packaging skeleton, Makefile and manual page

Known limitations: IP ownership is not necessarily hosting vendor; parent glue checks can be inconclusive if authorities are unreachable; DNSBL provider restrictions limit results.
