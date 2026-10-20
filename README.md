# zwhois

**The familiar WHOIS report, plus optional hosting, mail and DNS diagnostics.**

`zwhois` is a Linux command-line utility for people who want to know **when a domain expires**, **which nameservers it uses**, and—when requested—who appears to be hosting its mail, websites and DNS. Registration data comes from **RDAP**; DNS tests use the system `dig` command. Results are human-readable, not JSON.

Created by **Zeffie** · Published by **One Avenue LLC** · Development assistance: **OpenAI ChatGPT**. Licensed under **MIT**. Project information: [zeffie.com](https://zeffie.com) and [oneavenue.com](https://oneavenue.com). Report bugs at [GitHub Issues](https://github.com/wwZeffie/zwhois/issues). Those websites are references, not a promise of free technical support.

**Status: 0.1.2 test release.** Source and packaging are intended for local review; neither distribution acceptance nor exhaustive public-registry compatibility is claimed. Nothing is uploaded to GitHub automatically.

## At a glance

```text
zwhois example.com                   # Registration dates, registrar, status, nameservers
zwhois secure.example.com            # Registered parent + optional exact-host checks
zwhois 8.8.8.8                       # IP network registration
zwhois 2001:4860:4860::8888          # IPv6 network registration
zwhois AS15169                       # Autonomous system registration
zwhois -m example.com                # MX records, mail IPs and network allocation owner
zwhois -w example.com                # Apex/www, A/AAAA/CNAME and network allocation owner
zwhois -H example.com                # Web + mail hosting together (no spam tests)
zwhois -s example.com                # Common subdomains
zwhois -S example.com                # SPF/DMARC and configured DKIM selectors
zwhois -b example.com                # Configurable IP DNS blocklist queries
zwhois -ns example.com               # Parent delegation/glue + child DNS transport audit
zwhois -H -ns example.com            # Add checks together
zwhois -f example.com                # All optional checks
zwhois -d                             # Interactive text dialog (TTY required)
zwhois -h                             # Help, including explained examples
zwhois example.com example.net       # Several targets sequentially
zwhois < domains.txt                 # Read one target per input line
zwhois < domains.txt > audit.txt     # Save report to a file
```

A **plain** lookup does not run hosting, DNSBL, web crawling or TLS-certificate checks. The `-ns` tests issue live DNS questions and can be slower on unreliable servers.

## Installation

### Requirements

- **Python 3.9+** (standard library only; no pip dependencies).
- `dig` from `bind-utils` (Fedora/AlmaLinux/RHEL/Rocky) or `bind9-dnsutils` / `dnsutils` (Debian/Ubuntu) for DNS checks.
- `dialog` (recommended) or `whiptail` for the interactive `-d` menu. Interactive mode requires an actual terminal or SSH TTY.
- HTTPS connectivity to public RDAP services for registration and IP ownership reports. Normal CA validation is used; `zwhois` does not evaluate or display TLS certificate health.

### Source tarball (root installation)

From the directory containing the downloaded archive:

```sh
tar -xzf zwhois-0.1.2.tar.gz; \
cd zwhois-0.1.2; \
make test; \
make install; \
zwhois -h
```

**One-liner for a local, already-downloaded release** (uses `&&` so an error stops the chain):

```sh
tar -xzf zwhois-0.1.2.tar.gz && cd zwhois-0.1.2 && make test && make install
```

Uninstall with `make uninstall` from that same source tree. Default source installation is under `/usr/local`; package manager installations use `/usr`. Do not run an arbitrary `curl | sh` command; once an official GitHub release exists, its versioned archive URL and SHA-256 checksum can support a remote download/verify/install one-liner.

### RPM build (AlmaLinux, Rocky, Fedora, RHEL)

Install your distribution's RPM build tools and Python/`dig` dependencies. The source archive contains `packaging/rpm/zwhois.spec`, so the simplest build is:

```sh
rpmbuild -ta zwhois-0.1.2.tar.gz
```

Built RPMs typically appear under `~/rpmbuild/RPMS/noarch/`. Install with your package manager after inspecting the build output:

```sh
dnf install ~/rpmbuild/RPMS/noarch/zwhois-0.1.2-1*.noarch.rpm
```

The manual alternative is to place the tarball in `~/rpmbuild/SOURCES/`, copy `packaging/rpm/zwhois.spec` to `~/rpmbuild/SPECS/` and use `rpmbuild -ba` on the spec. The 0.1.1 duplicate `%doc` warnings were corrected in the RPM spec. **An RPM build still requires testing on your target RPM distribution.**

### Debian / Ubuntu build

Install `build-essential`, `debhelper`, `dpkg-dev`, `python3`, `bind9-dnsutils` (or `dnsutils`) and `dialog` as appropriate. Extract the source archive, then:

```sh
cd zwhois-0.1.2; \
dpkg-buildpackage -us -uc -b
```

The `.deb` is written in the parent directory if the build succeeds; install with `apt install ./zwhois_0.1.2-1_all.deb` from there. A distribution source package additionally requires the correctly named upstream tarball (`zwhois_0.1.2.orig.tar.gz`) and `dpkg-buildpackage -S`; see [Debian's packaging guide](https://www.debian.org/doc/manuals/debmake-doc/ch06.en.html). An RPM built from the source tarball is **not** a substitute for actually testing a Debian package.

## Domain names vs hostnames

`zwhois secure.example.com` reports registration for the registered domain (`example.com`, if that's the registered domain in RDAP). With `-m`, `-w`, `-H`, `-s`, or `-S`, DNS questions target **secure.example.com** and its appropriate hostnames; they are not silently rewritten to the parent. `-ns` checks delegation for the **registered domain** as its registry parent publishes it.

RDAP hostname-to-domain discovery is best-effort and can vary by registry; a hostname does not have a separate registrar expiry date just because it exists in DNS.

## Important reporting behavior

- **Expires, Created, Updated**: values come from the RDAP `events` array, not a domain's TLS certificate. All other dated events that the registry returns are shown. If absent, `Not provided` is printed. Registry-level expiry may differ from a registrar's billing/renewal date.
- **Nameservers**: the default registration report uses RDAP data. `-ns` actively checks DNS parent/child consistency.
- **IP ownership vs hosting**: address registrations identify the registered network operator, which might be a CDN or upstream, not the customer's actual hosting or mail provider.
- **No website access**: `-w` uses DNS only. It also tries `www.` plus the requested hostname, which may not exist for a subdomain.
- **SPF, DMARC, DKIM**: `-S` reports published DNS TXT content; it does **not** evaluate delivery security or discover all DKIM selectors.
- **DNSBLs**: `-b` checks IP-based lists only. A provider's error or inaccessible service is never proof an address is listed or clean; see [DNSBL notes](docs/DNSBL.md).

## Parent glue and authoritative DNS checks (`-ns`)

The check discovers the candidate DNS parent using the *registered domain*, obtains the parent zone's nameservers and queries up to **two parent authorities directly with recursion disabled**. It reads the delegation from **AUTHORITY** and genuine glue from **ADDITIONAL**. It compares the parent-published in-domain NS A/AAAA glue against child-zone A/AAAA answers. Missing, mismatched, unreachable, and unverifiable cases are reported distinctly. Truncated parent referrals are retried over TCP. It separately checks each resolver-visible nameserver's SOA and NS response over available IPv4/IPv6, TCP/UDP (not all nameservers necessarily have both address families).

**Important:** missing AAAA glue alongside a child AAAA is reported as an **operational warning**, not automatically a standards violation. The IETF requires return of *available* in-domain glue, not creation of glue records that have not been registered. See [RFC 9471](https://www.rfc-editor.org/rfc/rfc9471). A parent NS lookup or authoritative server can fail; such results are **UNKNOWN**, not PASS.

The tool does not require or attempt AXFR (zone transfer). Full DNS zone content and arbitrary hidden subdomains cannot be verified by ordinary public DNS queries. More detail and examples: [DNS auditing reference](docs/DNS-AUDIT.md).

## Interactive terminal mode

Run `zwhois -d` to open a text menu: enter a domain, hostname, IP or ASN; select flags using Space; execute; view the report; return to the same target, change it, or exit. A local TTY is needed. If a menu does not appear, verify `dialog` is installed and that `zwhois -d` runs directly in a terminal, not in redirected or noninteractive input.

Optional convenience alias in `~/.bashrc`:

```sh
alias zwhois='zwhois -d'
```

This changes interactive commands, too. To bypass it for scripted or one-time noninteractive calls, use `command zwhois -ns example.com` or `\zwhois -ns example.com`. **Do not put the alias in system-wide profiles.**

## Configuration

The optional config file is `~/.config/zwhois/config.json`. Create it by copying the packaged `example.json` or `config/example.json` in the source tree. Use `--config PATH` for a different file.

```sh
mkdir -p ~/.config/zwhois; \
cp config/example.json ~/.config/zwhois/config.json
```

Configure DNSBL zones, known DKIM selectors, and selected subdomain prefixes. `zwhois` never carries customer exports, keys, or credentials in its source archive. Note that provider rate limits and terms apply to bulk audits.

## Testing / contributing

Run `make test` for offline regression tests; see [Testing and release checklist](docs/TESTING.md). The archive provides an optional installed CLI smoke script at `scripts/installed-smoke.sh`. Live results depend on public services and DNS state. Before declaring a stable release, test an RPM build on AlmaLinux/Rocky/Fedora, a `.deb` build on Ubuntu/Debian, real IPv4/IPv6 DNS paths, and the interactive dialog on a terminal. Contributions are welcome through the public GitHub repository once published.

### References

- [RDAP bootstrap RFC 9224](https://www.rfc-editor.org/rfc/rfc9224)
- [RDAP JSON event semantics RFC 9083](https://www.rfc-editor.org/rfc/rfc9083)
- [DNS glue in parent referrals RFC 9471](https://www.rfc-editor.org/rfc/rfc9471)
- [DNS over TCP RFC 7766](https://www.rfc-editor.org/rfc/rfc7766)
- [Spamhaus DNSBL error codes and access requirements](https://www.spamhaus.org/faqs/dnsbl-usage/)

**Legacy:** The MIT license allows this project to remain forkable, redistributable, and maintainable even when its original creator is no longer involved.
