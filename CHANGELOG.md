# Changelog

## 0.1.5 — Python 3.9/3.10 registrar expiration compatibility

- Fix two-digit fractional timestamps returned by registrar RDAP, such as eNom's `2027-01-25T03:18:00.00Z`, on AlmaLinux/RHEL 9 Python 3.9.
- Normalize RFC 3339 fractional seconds to six digits before comparison, keeping the original RDAP values in the report.
- Add a regression test simulating Python 3.9's stricter `datetime.fromisoformat` parser.

## 0.1.4 — avoid misleading expiration warnings

- Preserve the exact registry and registrar expiration timestamps while suppressing warnings for same-day differences of at most 60 seconds (e.g., eNom 10-second offset).
- Continue warning for different UTC dates or differences over 60 seconds.
- Add regression tests for rounding, midnight crossings, and true renewal mismatches.


## 0.1.3 — distinguish registrar and registry expiration

- Label the registry `expiration` event **Registry Expires** and the distinct `registrar expiration` event **Registrar Expires**.
- Query the registrar's RDAP service where it can be discovered from IANA's official registrar ID directory.
- Fall back only to an explicitly labeled registrar expiration event in registry RDAP; never guess a registrar date from the registry expiry.
- Warn when dates differ, normalize timezone offsets for comparisons and report unavailable registrar RDAP without failing a registration lookup.
- Add registrar expiration tests, source documentation and a live smoke check.


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
