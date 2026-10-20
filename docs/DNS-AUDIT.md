# `zwhois -ns`: Parent delegation, glue and DNS transport checks

## Why check glue separately?

`dig ns1.example.com AAAA` is a normal DNS lookup. It does **not** show whether the registry-level parent publishes that address as glue. For in-domain nameservers (`ns1.example.com` serving `example.com`), the authoritative parent referral is the appropriate source.

`zwhois -ns example.com`:

1. Discovers the registered domain using RDAP and derives the parent-zone candidate (for `example.co.uk`, candidate `co.uk`).
2. Retrieves parent-zone NS hostnames and their addresses via the system resolver.
3. Sends **nonrecursive** DNS NS questions for the registered domain directly to up to two parent authorities, without using cached recursive answers as a substitute for parent data. The referral's **AUTHORITY** section identifies delegation; its **ADDITIONAL** section contains parent-published glue.
4. Retries a truncated (TC) parent referral using TCP.
5. For NS hostnames inside the delegated domain, compares returned A/AAAA glue with child authoritative A/AAAA answers. A missing AAAA alongside a child AAAA is reported as a warning; not all child addresses must necessarily be in the parent.
6. Independently checks the resolver-visible nameservers for SOA answers over IPv4 UDP, IPv4 TCP, IPv6 UDP, and IPv6 TCP *when the NS has that address family*. An IPv4-only NS is not incorrectly marked as a failing IPv6 host.
7. Compares child NS answers to resolver-visible NS records and prints SOA serials.

### Output interpretation

- `PASS`: this specific check succeeded. It does not certify the whole zone or network.
- `WARN`: an observed mismatch, unreachable transport, absent in-domain glue when child records exist, or other issue requiring judgment.
- `UNKNOWN`: the authoritative check could not be made (timeout, firewall, parent not reachable, inaccessible records). **UNKNOWN is not evidence of correctness or failure.**
- `Out-of-domain nameserver`: another domain is the nameserver's owner; no in-domain glue for this delegation is expected.

Parent responses may vary during propagation. The tool checks up to two directly contacted authorities and notes when only one was reachable; it is **not** an exhaustive sweep of the entire TLD's registry infrastructure. It does not make blanket assumptions that every nameserver must publish AAAA.

### Troubleshooting with `dig`

The manual equivalent of the parent referral check is:

```sh
dig @a.gtld-servers.net example.com NS +norecurse +noall +authority +additional
```

That server is suitable for `.com`; **do not** use it as the parent for non-`.com` domains. A nameserver's regular A/AAAA records are not automatically its registry glue.

To test one authoritative DNS endpoint yourself (replace the example address with a real authoritative server):

```sh
dig -4 @192.0.2.53 example.com SOA +norecurse; \
dig -4 @192.0.2.53 example.com SOA +tcp +norecurse; \
dig -6 @2001:db8::53 example.com SOA +norecurse; \
dig -6 @2001:db8::53 example.com SOA +tcp +norecurse
```

The documentation-only IP addresses above are reserved examples, not live DNS servers.

`zwhois -ns` does not require AXFR, doesn't fetch the full zone, and cannot know all undisclosed hostnames. Even valid authoritative answers may not prove reachability from every global network.

Reference: [RFC 9471](https://www.rfc-editor.org/rfc/rfc9471).
