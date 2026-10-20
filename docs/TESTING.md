# Local testing and prepublication checklist

## Automated offline tests

`make test` runs Python standard-library `unittest` tests. These deliberately avoid real registrar, DNSBL and registry calls; they verify output parsing, input selection, dates, dialog mechanics, parent referral/glue parsing and classification.

`python3 -m compileall -q zwhois zwhois_lib` checks syntax.

## Installed RPM/DEB smoke test

After installing the RPM/DEB, from the extracted source directory:

```sh
sh scripts/installed-smoke.sh > zwhois-test-report.txt 2>&1
```

The script records versions, help, a domain RDAP lookup, an IP RDAP lookup, and a nameserver/glue test. It distinguishes an environmental lookup failure from a deterministic test failure. **The report may contain public registration and hostnames**; inspect it before sharing.

## Manual integration matrix

- `zwhois -h`: options and examples displayed; zero Python traceback.
- `zwhois example.com`: RDAP registrar, expiration, nameservers when published (absence shown as `Not provided`). Verify against current registry lookup.
- `zwhois secure.example.com`: registered parent identification; optional DNS checks use host.
- `zwhois 8.8.8.8`: IP allocation data, no domain expiry shown.
- `zwhois 2001:4860:4860::8888`: IPv6 RDAP response.
- `zwhois AS15169`: ASN RDAP response.
- `zwhois -w example.com`, `-m`, `-H`, `-s`, `-S`: verify observations with manual `dig` queries.
- `zwhois -ns example.com`: parent referral/glue and child authoritative IP families/transports. Verify manually against the **correct parent**.
- `zwhois -b example.com`: labels Spamhaus policy-error responses as **INCONCLUSIVE**, not listed.
- `zwhois -d`: opens a visible menu in an SSH/terminal TTY; target and selected tests remain after returning to main menu.
- `rpmbuild -ta zwhois-0.1.2.tar.gz` on a real RPM distribution; check files and `%doc` warnings.
- `dpkg-buildpackage -us -uc -b` on a Debian/Ubuntu build host; review package dependencies and installed files.
- `man zwhois` and `make install` / `make uninstall` under a staging DESTDIR.

## Before a public stable release

Run the matrix on live domains under different registries, including a known multi-label public suffix (`.co.uk` or similar), a properly delegated in-domain NS, an IPv4-only NS, and a deliberately unavailable transport. Check external registrar data independently. Negative answers can be cached by resolvers; a recursive cache is not evidence of registry glue. Test without privileged network changes, and obtain explicit publication approval before publishing code or signed releases.

This source archive is a **test candidate** and not a certification of all registrar implementations, DNSBL APIs, or distributions.

## Version 0.1.5 expiration tests

Run `make test` to test ICANN eventAction parsing, registrar IANA ID lookup, HTTPS-only IANA directory parsing, source preference, absence/failure fallback, matching dates with different timezone offsets, and the resulting text report. All tests are offline fixtures; they do not prove that a registrar's live RDAP endpoint is reachable.

After installing an RPM or DEB, compare `zwhois thelinuxpros.com` or another registrar-operated domain against the registrar account's expiration date. Confirm it prints both `Registry Expires` and `Registrar Expires` when available, or `Not provided` without substituting the registry date if the registrar is inaccessible.

### 0.1.5 live regression

For `thelinuxpros.com`, the previously observed registry value `2027-01-25T03:18:10Z` and registrar value `2027-01-25T03:18:00.00Z` must both be printed but should **not** cause a WARN about renewal-date disagreement. A full-day/year mismatch still must warn. Network access is needed only for the live check; automated tests use static fixtures.

### Python 3.9 compatibility regression (0.1.5)

AlmaLinux 9 ships Python 3.9; `datetime.fromisoformat()` there rejects 1-, 2-,
4-, 5-, or 7-digit fractional second values returned by some registrar RDAP
services. The automated test mocks those older parsing restrictions even on
Python 3.11+, and checks eNom's `.00Z` timestamp. Confirm `zwhois
thelinuxpros.com` displays both expiry dates without a mismatch warning for a
ten-second difference. A complete end-to-end RPM test requires a real EL9 host.
