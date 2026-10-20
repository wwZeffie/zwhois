# DNSBL / reputation checks

`zwhois -b example.com` queries configured **IP-based** DNS blocklists for IP addresses resolved from the target and its MX hosts. Results are advisory observations, **not email deliverability guarantees**, and the tool is not an MTA.

Configuration file: `~/.config/zwhois/config.json`, JSON key `dnsbls`. The example lists `zen.spamhaus.org`, `bl.spamcop.net`, and `b.barracudacentral.org` for your review. Check each provider's current terms before bulk or commercial use; not every list accepts IPv6 queries and some require registration or a particular DNS resolver.

**Spamhaus**: DNS return codes in `127.255.255.0/24` are **error codes**, not proof of a listing. Notably `127.255.255.252` (invalid DNSBL name), `.254` (resolver not authorized), and `.255` (too many queries). `zwhois` prints these as **INCONCLUSIVE**. Valid Spamhaus reputation responses generally use other `127.0.x.x` codes. An `NXDOMAIN` may mean not listed, but in some restricted environments can also mean unavailable; it should never be treated as a strong assurance.

Consult [Spamhaus official DNSBL FAQ](https://www.spamhaus.org/faqs/dnsbl-usage/) and [DNSBL error code guidance](https://www.spamhaus.org/resource-hub/dnsbl/using-our-public-mirrors-check-your-return-codes-now/).

This release **does not** query a domain-only reputation list such as Spamhaus DBL, and it does not perform SMTP delivery tests or identify an outbound SMTP IP based only on a recipient's MX records. Incoming MX host IPs are not necessarily outbound sender IPs. Future domain-only blocklist support should be separately configured and must follow the provider's API and DNS-query policy.

If you operate commercial mail services, check provider licensing before querying lists as part of a fleet audit.
