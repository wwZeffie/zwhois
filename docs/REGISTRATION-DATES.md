# Registration expiration dates in zwhois

## Why there are two dates

ICANN's Registration Data Policy (effective August 21, 2025) distinguishes **Registry Expiry Date** from **Registrar Registration Expiration Date**. These can differ when a registry auto-renews a domain without corresponding registrant/registrar renewal. The registrar's customer-facing expiration is not necessarily the registry's auto-renewed expiration.

RDAP's domain-level `events` array uses **`eventAction: expiration`** for the registry date and **`eventAction: registrar expiration`** for the registrar date. The latter is an ICANN-registered RDAP extension value. A registrar may omit the registry date from its response; a registry may omit the registrar date. Source: [ICANN Registration Data Policy §9.1.1](https://www.icann.org/resources/pages/registration-data-policy-2024-02-21-en/), [IANA RDAP JSON Values](https://www.iana.org/assignments/rdap-json-values).

## How zwhois obtains the dates

1. Locate the registered domain using TLD/registry RDAP bootstrap from IANA.
2. Read the registry's `expiration` event, if available, as `Registry Expires`.
3. Identify the ICANN registrar by its **IANA Registrar ID** in the registry RDAP's `registrar` entity (`publicIds` or numeric `handle`).
4. Look up the registrar's **RDAP Base URL** in [IANA Registrar IDs](https://www.iana.org/assignments/registrar-ids), then query the registrar's domain RDAP object. Use **only** `registrar expiration` for `Registrar Expires`.
5. If that lookup fails, use a **clearly identified** registrar-expiration event from the registry response if present; otherwise print `Not provided` and a brief diagnostic. Never silently copy the registry expiry into the registrar field.
6. Display both exact timestamps. Normalize timezone offsets for comparisons. Warn when the UTC calendar dates differ or the timestamps differ by more than 60 seconds; up to 60 seconds on the same UTC date is treated as minor reporting precision noise. This is a local zwhois reporting decision, **not an ICANN rule**.

Queries use normal HTTPS validation and may be slow or unavailable due to provider downtime, rate limits, or access restrictions. No customer login/API credentials are used. The IANA directory is downloaded once per invocation (in-memory only); no persistent tracking or credentials. For non-gTLDs or registrars not identified by IANA ID, only available RDAP events can be displayed.

## How to audit renewal risk

- **Never** interpret `Registry Expires` as a guaranteed paid-through or customer renewal date.
- Verify actual registration/renewal entitlement and payment with the registrar's customer portal or contract.
- Missing fields mean **not provided**, not "safe" or "expired".
- `zwhois example.com` shows both dates; `zwhois -ns example.com` adds delegation checks but does not change expiration semantics.

A registrar may use a separate billing date or grace-period rules. `zwhois` reports RDAP data, not authoritative invoices, billing state, or redemption eligibility.

## Standards

- [ICANN Registration Data Policy §9.1.1](https://www.icann.org/resources/pages/registration-data-policy-2024-02-21-en/)
- [RDAP JSON events, RFC 9083](https://www.rfc-editor.org/rfc/rfc9083)
- [IANA registrar RDAP directory](https://www.iana.org/assignments/registrar-ids)
- [IANA RDAP event types](https://www.iana.org/assignments/rdap-json-values)
