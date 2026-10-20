"""RDAP queries and opt-in DNS diagnostics. Standard library plus system dig."""
import csv
import datetime
from functools import lru_cache
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = 'zwhois/0.1.5 (registration-audit utility)'
BOOTSTRAP = 'https://data.iana.org/rdap/'
REGISTRAR_DIRECTORY = 'https://www.iana.org/assignments/registrar-ids/registrar-ids-1.csv'
DEFAULT_RBLS = ['zen.spamhaus.org', 'bl.spamcop.net', 'b.barracudacentral.org']

class LookupError_(Exception):
    pass


def get_json(url, timeout=10):
    if not url.startswith('https://'):
        raise LookupError_('Refusing non-HTTPS RDAP URL')
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'application/rdap+json, application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.load(response)
    except (OSError, ValueError, urllib.error.HTTPError) as exc:
        raise LookupError_(f'RDAP request failed ({url}): {exc}') from exc


def bootstrap_url(category, target):
    data = get_json(BOOTSTRAP + category + '.json')
    matches = []
    for identifiers, urls in data.get('services', []):
        for identifier in identifiers:
            if category == 'dns':
                ok = target.lower() == identifier.lower() or target.lower().endswith('.' + identifier.lower())
                score = len(identifier)
            elif category in ('ipv4', 'ipv6'):
                try:
                    network = ipaddress.ip_network(identifier, strict=False)
                    ok = ipaddress.ip_address(target) in network
                    score = network.prefixlen
                except ValueError:
                    continue
            else:
                try:
                    lo, hi = [int(n) for n in identifier.split('-', 1)]
                    ok = lo <= int(target) <= hi
                    score = -(hi-lo)
                except ValueError:
                    continue
            if ok:
                matches.extend((score, u) for u in urls if u.startswith('https://'))
    if not matches:
        raise LookupError_('No RDAP bootstrap service found for target')
    return max(matches, key=lambda x: x[0])[1].rstrip('/') + '/'


def registered_domain(host):
    """Best-effort RDAP discovery from host labels; never claim a guessed suffix is a PSL result."""
    host = host.lower().rstrip('.')
    labels = host.split('.')
    if len(labels) < 2:
        raise LookupError_('Specify a fully qualified hostname or domain')
    base = bootstrap_url('dns', host)
    errors = []
    # Probe candidates from most specific to shorter; RDAP 404 is expected for subdomains.
    for i in range(max(0, len(labels)-7), len(labels)-1):
        candidate = '.'.join(labels[i:])
        try:
            return candidate, get_json(base + 'domain/' + urllib.parse.quote(candidate))
        except LookupError_ as exc:
            errors.append(str(exc))
    raise LookupError_('Could not locate a registered domain in RDAP (last response: ' + errors[-1] + ')')


def rdap_for(value):
    target = value.strip().rstrip('.')
    if not target or '/' in target or any(c.isspace() for c in target):
        raise LookupError_('Invalid target')
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        addr = None
    if addr:
        category = 'ipv4' if addr.version == 4 else 'ipv6'
        url = bootstrap_url(category, str(addr)) + 'ip/' + urllib.parse.quote(str(addr))
        return 'ip', target, get_json(url), None
    m = re.fullmatch(r'AS(\d+)', target, re.IGNORECASE)
    if m:
        asn = int(m.group(1))
        return 'asn', target.upper(), get_json(bootstrap_url('asn', str(asn)) + 'autnum/' + str(asn)), None
    if not re.fullmatch(r'(?=.{1,253}$)[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+', target):
        raise LookupError_('Invalid domain/hostname syntax')
    registered, result = registered_domain(target)
    return 'domain', registered, result, target.lower()


def dates(obj):
    items = []
    for e in obj.get('events', []):
        if e.get('eventAction') and e.get('eventDate'):
            items.append((e['eventAction'], e['eventDate']))
    return items



def event_date(obj, action):
    """RDAP eventAction is authoritative: do not confuse the two expiry events."""
    for item in obj.get('events', []):
        if (isinstance(item, dict) and str(item.get('eventAction', '')).strip().lower() == action
                and item.get('eventDate')):
            return str(item['eventDate'])
    return None


def registrar_iana_id(obj):
    """Read the IANA registrar ID from the RDAP registrar entity (ICANN profile)."""
    for entity in obj.get('entities', []):
        if not isinstance(entity, dict) or 'registrar' not in entity.get('roles', []):
            continue
        for ident in entity.get('publicIds', []):
            if (str(ident.get('type', '')).lower() == 'iana registrar id'
                    and str(ident.get('identifier', '')).isdigit()):
                return str(int(ident['identifier']))
        handle = str(entity.get('handle', ''))
        if handle.isdigit():
            return str(int(handle))
    return None


@lru_cache(maxsize=1)
def registrar_services():
    """Download IANA's official registrar ID -> RDAP Base URL directory.

    Only the HTTPS URLs listed by IANA are used for registrar lookups.
    This is separate from the TLD/bootstrap registry RDAP service.
    """
    req = urllib.request.Request(REGISTRAR_DIRECTORY, headers={'User-Agent': USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=6) as response:
            raw = response.read(2_000_001)
    except (OSError, urllib.error.HTTPError) as exc:
        raise LookupError_(f'IANA registrar directory unavailable: {exc}') from exc
    if len(raw) > 2_000_000:
        raise LookupError_('IANA registrar directory exceeds size limit')
    try:
        reader = csv.DictReader(io.StringIO(raw.decode('utf-8-sig')))
        if not reader.fieldnames or not {'ID', 'RDAP Base URL'} <= set(reader.fieldnames):
            raise ValueError('Unexpected registrar CSV header')
        return {
            str(int(row['ID'].strip())): row['RDAP Base URL'].strip()
            for row in reader
            if (row.get('ID') or '').strip().isdigit()
            and (row.get('RDAP Base URL') or '').strip().startswith('https://')
        }
    except (ValueError, UnicodeError, csv.Error, KeyError, TypeError) as exc:
        raise LookupError_(f'Cannot parse IANA registrar directory: {exc}') from exc


def registrar_expiration(domain, registry_obj):
    """Return (date, provenance, notice) without ever failing a registry lookup.

    Registry 'expiration' != registrar 'registrar expiration'. Registrar's
    own RDAP is preferred; registry's optional registrar event is fallback.
    """
    copied = event_date(registry_obj, 'registrar expiration')
    ident = registrar_iana_id(registry_obj)
    if not ident:
        return copied, ('Registry RDAP (registrar expiration event)' if copied else None), None
    try:
        base = registrar_services().get(ident)
    except LookupError_ as exc:
        return copied, ('Registry RDAP (registrar expiration event)' if copied else None), str(exc)
    if not base:
        return copied, ('Registry RDAP (registrar expiration event)' if copied else None), 'No registrar RDAP URL listed by IANA'
    url = base.rstrip('/') + '/domain/' + urllib.parse.quote(domain, safe='')
    try:
        registrar_obj = get_json(url, timeout=7)
        # An unexpected domain response is not authoritative for this target.
        if registrar_obj.get('ldhName', '').lower().rstrip('.') != domain.lower().rstrip('.'):
            raise LookupError_('Registrar RDAP returned a different or missing domain name')
        date = event_date(registrar_obj, 'registrar expiration')
        if date:
            return date, 'Registrar RDAP', None
        return copied, ('Registry RDAP (registrar expiration event)' if copied else None), 'Registrar RDAP omitted registrar expiration'
    except (LookupError_, ValueError, AttributeError, TypeError) as exc:
        return copied, ('Registry RDAP (registrar expiration event)' if copied else None), 'Registrar RDAP unavailable: ' + str(exc)


def parse_rdap_timestamp(value):
    """Parse an RDAP RFC 3339 instant on Python 3.9 and newer.

    Python 3.9/3.10 datetime.fromisoformat rejects fractional seconds that
    have lengths other than 3 or 6. Some registrar RDAP servers return .00Z.
    Normalize the fractional part to six digits before parsing, while
    preserving the original timestamp string for the report.
    """
    if not isinstance(value, str):
        raise ValueError('Expected an RDAP timestamp string')
    match = re.fullmatch(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
        r'(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})', value)
    if not match:
        raise ValueError('Invalid RDAP RFC 3339 timestamp')
    body, fractional, zone = match.groups()
    # fromisoformat in Python 3.9 accepts a six-digit fraction reliably.
    if fractional is not None:
        body += '.' + fractional[:6].ljust(6, '0')
    if zone == 'Z':
        zone = '+00:00'
    return datetime.datetime.fromisoformat(body + zone)


def different_expiration_dates(registry, registrar):
    """Return whether two expiration timestamps merit a renewal warning.

    Preserve both precise RDAP values in the report. Treat a difference of at
    most 60 seconds on the same UTC calendar date as timestamp precision noise,
    not a material renewal-date disagreement. Different UTC dates always warn,
    including a few seconds on opposite sides of midnight. Timezone offsets
    are normalized before comparison. This is a reporting policy, not RDAP law.
    """
    if not registry or not registrar:
        return False
    try:
        first = parse_rdap_timestamp(registry)
        second = parse_rdap_timestamp(registrar)
        if first.tzinfo is None or second.tzinfo is None:
            return registry != registrar
        first = first.astimezone(datetime.timezone.utc)
        second = second.astimezone(datetime.timezone.utc)
        if first.date() != second.date():
            return True
        return abs((first - second).total_seconds()) > 60
    except (TypeError, ValueError, OverflowError):
        return registry != registrar


def entity_name(entity):
    v = entity.get('vcardArray') or []
    if len(v) == 2 and isinstance(v[1], list):
        for field in v[1]:
            if isinstance(field, list) and len(field) >= 4 and field[0] in ('fn', 'org'):
                if field[3]:
                    return str(field[3])
    return entity.get('handle', 'Not provided')


def report_rdap(kind, registered, obj, requested=None, registrar_expiry=None, registrar_source=None, registrar_notice=None):
    result = [f'Target:           {requested or registered}', f'Type:             {kind.upper()}']
    if kind == 'domain':
        result += [f'Registered domain: {registered}']
        if requested and requested != registered:
            result.append('Note:             Registration applies to parent domain, DNS checks target hostname')
        registrar = next((entity_name(e) for e in obj.get('entities', []) if 'registrar' in e.get('roles', [])), 'Not provided')
        result.extend([f'Registrar:        {registrar}', f'Registry ID:      {obj.get("handle", "Not provided")}'])
    elif kind == 'ip':
        result.extend([f'Network:          {obj.get("name", "Not provided")}', f'Range:            {obj.get("startAddress", "?")} - {obj.get("endAddress", "?")}', f'Country:          {obj.get("country", "Not provided")}'])
        if obj.get('entities'):
            result.append('Organizations:    ' + ', '.join(entity_name(e) for e in obj['entities'][:5]))
    else:
        result.extend([f'AS number:        {obj.get("startAutnum", "?")}', f'Network:          {obj.get("name", "Not provided")}'])
    events = dates(obj)
    if kind == 'domain':
        registry_expiry = event_date(obj, 'expiration')
        # When directly calling report_rdap (tests/other consumers), display a
        # registry-provided registrar event without inventing a registrar query.
        registrar_expiry = registrar_expiry or event_date(obj, 'registrar expiration')
        result.append(f'{"Registry Expires:":20}{registry_expiry or "Not provided"}')
        result.append(f'{"Registrar Expires:":20}{registrar_expiry or "Not provided"}')
        if registrar_expiry and registrar_source:
            result.append(f'Registrar date from: {registrar_source}')
        if different_expiration_dates(registry_expiry, registrar_expiry):
            result.append('WARN: Registrar and registry expiration dates differ; confirm the renewal deadline with your registrar')
        if registrar_notice and not registrar_expiry:
            result.append('Note:             Registrar expiration could not be independently confirmed (' + registrar_notice + ')')
        for label, action in [('Created', 'registration'), ('Updated', 'last changed')]:
            result.append(f'{label + ":":20}{event_date(obj, action) or "Not provided"}')
    for action, when in events:
        if kind != 'domain' or action.lower() not in ('registration', 'last changed', 'expiration', 'registrar expiration'):
            result.append(f'Date ({action}): {when}')
    if kind == 'domain':
        nss = [x.get('ldhName', '') for x in obj.get('nameservers', [])]
        result.append('Nameservers:      ' + (', '.join(nss) if nss else 'Not provided'))
    statuses = obj.get('status', [])
    result.append('Status:           ' + (', '.join(statuses) if statuses else 'Not provided'))
    for note in obj.get('notices', []):
        if 'redact' in note.get('title', '').lower():
            result.append('Privacy:          Registry reports redacted fields')
            break
    return '\n'.join(result)


def dig(name, rtype, server=None, family=None, tcp=False, timeout=4):
    if not shutil.which('dig'):
        raise LookupError_('DNS checks require dig (bind-utils / dnsutils)')
    cmd = ['dig']
    if family in (4, 6):
        cmd.append('-' + str(family))
    if server:
        cmd.append('@' + server)
    cmd += [name, rtype, '+time=2', '+tries=1', '+noall', '+answer', '+comments']
    if tcp:
        cmd.append('+tcp')
    if server:
        cmd.append('+norecurse')
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 'TIMEOUT', []
    lines = p.stdout.splitlines()
    status = re.search(r'status:\s*(\w+)', p.stdout)
    answers = []
    for line in lines:
        if line.startswith(';') or not line.strip():
            continue
        fields = line.split(None, 4)
        if len(fields) >= 5 and fields[2] == 'IN':
            answers.append((fields[0].rstrip('.'), fields[3], fields[4].strip()))
    if p.returncode or 'no servers could be reached' in p.stdout or 'timed out' in p.stdout:
        return 'UNREACHABLE', answers
    if server:
        flags = re.search(r'flags:\s*([^;]*);', p.stdout)
        if not flags or 'aa' not in flags.group(1).split():
            return 'NONAUTHORITATIVE', answers
    return (status.group(1) if status else 'UNKNOWN'), answers


def lookup(name, rtype):
    status, rows = dig(name, rtype)
    return status, [r[2] for r in rows if r[1] == rtype]


def add_section(lines, title, content):
    lines.extend(['', '=== ' + title + ' ==='] + content)


def ip_owner(ip, cache):
    if ip not in cache:
        try:
            _, _, obj, _ = rdap_for(ip)
            owner = obj.get('name') or obj.get('handle') or 'Not provided'
            cache[ip] = owner
        except LookupError_ as exc:
            cache[ip] = 'RDAP unavailable: ' + str(exc)
    return cache[ip]


def host_addresses(host, cache):
    lines = []
    for typ in ('CNAME', 'A', 'AAAA'):
        status, vals = lookup(host, typ)
        if vals:
            for val in vals:
                lines.append(f'{typ:6} {host} -> {val}')
                if typ in ('A', 'AAAA'):
                    lines.append('       Network: ' + ip_owner(val, cache))
        elif status not in ('NOERROR', 'NXDOMAIN'):
            lines.append(f'{typ}: {status}')
    return lines or ['No A, AAAA, or CNAME answers']


def web_report(target, cache):
    out = []
    for name in dict.fromkeys((target, 'www.' + target)):
        out.extend(host_addresses(name, cache))
    return out


def mx_hosts(target):
    status, records = lookup(target, 'MX')
    result = []
    for r in records:
        parts = r.split()
        if len(parts) >= 2:
            # Null MX means this name does not accept mail.
            if parts[1] == '.':
                result.append((parts[0], None))
            else:
                result.append((parts[0], parts[1].rstrip('.')))
    return status, result


def mail_report(target, cache):
    status, mx = mx_hosts(target)
    out = [f'MX lookup: {status}']
    if not mx:
        out.append('No MX records found (SMTP implicit A/AAAA fallback may apply)')
    for pref, host in mx:
        if host is None:
            out.append('Null MX: domain does not accept mail')
        else:
            out.append(f'MX priority {pref}: {host}')
            out.extend(host_addresses(host, cache))
    return out


def security_report(target, selectors):
    out = []
    status, records = lookup(target, 'TXT')
    spf = [r for r in records if 'v=spf1' in r.lower()]
    out += ['SPF: ' + (' | '.join(spf) if spf else 'Not found')]
    status, dmarc = lookup('_dmarc.' + target, 'TXT')
    out += ['DMARC: ' + (' | '.join(x for x in dmarc if 'v=dmarc1' in x.lower()) if dmarc else 'Not found')]
    for selector in selectors:
        status, dk = lookup(selector + '._domainkey.' + target, 'TXT')
        out.append(f'DKIM selector {selector}: ' + (' | '.join(dk) if dk else 'Not found'))
    out.append('DKIM note: absent guessed selectors do NOT prove DKIM is absent')
    return out


def load_config(path):
    path = Path(path).expanduser()
    if not path.exists():
        return {'dnsbls': DEFAULT_RBLS, 'dkim_selectors': ['default', 'selector1', 'selector2', 'google']}
    try:
        cfg = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise LookupError_(f'Invalid config file {path}: {exc}') from exc
    return {'dnsbls': cfg.get('dnsbls', DEFAULT_RBLS), 'dkim_selectors': cfg.get('dkim_selectors', ['default'])}


def blacklist_report(target, cfg):
    out = ['DNSBL results are advisory; provider access restrictions can make answers inconclusive.']
    ips = []
    for name in [target] + [host for _, host in mx_hosts(target)[1] if host]:
        for typ in ('A', 'AAAA'):
            ips.extend(lookup(name, typ)[1])
    for ip in dict.fromkeys(ips):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not addr.is_global:
            out.append(f'{ip}: non-global address, not queried')
            continue
        for provider in cfg['dnsbls']:
            if not re.fullmatch(r'[a-zA-Z0-9.-]+', provider):
                out.append('Invalid DNSBL provider entry: ' + repr(provider))
                continue
            reverse = '.'.join(str(x) for x in reversed(addr.packed)) if addr.version == 4 else '.'.join(reversed(addr.exploded.replace(':', '')))
            q = reverse + '.' + provider
            status, a = lookup(q, 'A')
            if a:
                codes = set(a)
                if provider.endswith('spamhaus.org') and any(c.startswith('127.255.255.') for c in codes):
                    out.append(f'{ip} / {provider}: INCONCLUSIVE (Spamhaus access/error response {", ".join(a)})')
                else:
                    out.append(f'{ip} / {provider}: RESPONSE {", ".join(a)} (check provider policy/response meanings)')
            elif status == 'NXDOMAIN':
                out.append(f'{ip} / {provider}: NXDOMAIN (not listed or unavailable by policy)')
            else:
                out.append(f'{ip} / {provider}: INCONCLUSIVE ({status})')
    if not ips:
        out.append('No IPs found to check')
    return out


def parent_referral(domain, server, tcp=False):
    """Query an authoritative PARENT server without recursion, never a resolver's NS cache.

    Returns status, delegation names, referral glue and truncation flag.
    Glue is taken ONLY from the referral's ADDITIONAL section.
    """
    if not shutil.which('dig'):
        raise LookupError_('Parent glue checks require dig (bind-utils / dnsutils)')
    cmd = ['dig', '@' + server, domain, 'NS', '+norecurse', '+time=2',
           '+tries=1', '+noall', '+authority', '+additional', '+comments']
    if ':' in server:
        cmd.insert(1, '-6')
    else:
        cmd.insert(1, '-4')
    if tcp:
        cmd.append('+tcp')
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return 'UNREACHABLE', [], {}, False
    if p.returncode or 'no servers could be reached' in p.stdout or 'timed out' in p.stdout:
        return 'UNREACHABLE', [], {}, False
    header = re.search(r'status:\s*(\w+)', p.stdout)
    flags = re.search(r'flags:\s*([^;]*);', p.stdout)
    truncated = bool(flags and 'tc' in flags.group(1).split())
    status = header.group(1) if header else 'UNKNOWN'
    section = None
    delegates, glue = set(), {}
    domain = domain.lower().rstrip('.')
    for line in p.stdout.splitlines():
        if line.startswith(';; AUTHORITY SECTION:'):
            section = 'authority'
            continue
        if line.startswith(';; ADDITIONAL SECTION:'):
            section = 'additional'
            continue
        if line.startswith(';; ') and 'SECTION:' in line:
            section = None
            continue
        if section not in ('authority', 'additional') or not line or line.startswith(';'):
            continue
        cols = line.split(None, 4)
        if len(cols) < 5 or cols[2] != 'IN':
            continue
        owner, typ, value = cols[0].lower().rstrip('.'), cols[3], cols[4].strip()
        if section == 'authority' and owner == domain and typ == 'NS':
            delegates.add(value.lower().rstrip('.'))
        elif section == 'additional' and typ in ('A', 'AAAA'):
            try:
                addr = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            glue.setdefault(owner, {}).setdefault(typ, set()).add(addr)
    return status, sorted(delegates), glue, truncated


def parent_glue_report(domain):
    """Inspect actual parent referrals and compare in-domain glue with child DNS.

    A missing IPv6 glue record is noteworthy but not necessarily a violation:
    RFC 9471 specifies returning all AVAILABLE glue, not installing new glue.
    """
    parent = domain.split('.', 1)[1] if '.' in domain else None
    if not parent:
        return ['UNKNOWN: No parent DNS zone identified']
    lines = [f'Parent candidate: {parent} (parent NS queried directly; no recursive glue inference)']
    st, parent_ns = lookup(parent, 'NS')
    if not parent_ns:
        return lines + [f'UNKNOWN: Could not discover parent nameservers ({st})']
    replies = []
    problems = []
    tried = 0
    for servername in dict.fromkeys(parent_ns):
        servername = servername.rstrip('.')
        ips = lookup(servername, 'A')[1] + lookup(servername, 'AAAA')[1]
        for ip in ips[:3]:
            tried += 1
            status, ns, glue, tc = parent_referral(domain, ip)
            if tc:
                status, ns, glue, tc = parent_referral(domain, ip, tcp=True)
                if tc:
                    problems.append(f'{servername} ({ip}): truncated TCP referral')
                    continue
            if status == 'NOERROR' and ns:
                replies.append((servername, ip, ns, glue))
                break
            problems.append(f'{servername} ({ip}): {status}, no delegation referral')
        if len(replies) >= 2 or tried >= 12:
            break
    if not replies:
        return lines + ['UNKNOWN: No parent referral could be verified'] + problems[:4]
    for server, ip, names, _ in replies:
        lines.append(f'Parent authority {server} ({ip}): NS={", ".join(names)}')
    reference = replies[0][2]
    if any(ns != reference for _, _, ns, _ in replies[1:]):
        lines.append('WARN: Parent authorities disagree on delegation NS set')
    else:
        lines.append('PASS: Checked parent authorities agree on delegation' if len(replies) > 1 else 'NOTE: Only one parent authority verified')
    # Only parent-published data counts as glue; do not pretend a recursive A/AAAA is glue.
    for name in reference:
        if not (name == domain or name.endswith('.' + domain)):
            lines.append(f'{name}: Out-of-domain nameserver (no in-domain glue requirement)')
            continue
        for typ in ('A', 'AAAA'):
            values = set().union(*(entry.get(name, {}).get(typ, set()) for _, _, _, entry in replies))
            if values:
                lines.append(f'{name} parent {typ} GLUE: {", ".join(sorted(values))}')
            # Ask a child authority, not a recursive resolver, for comparable A/AAAA.
            child_values = set()
            child_status = 'UNREACHABLE'
            for nsname in reference:
                addresses = (set().union(*(r.get(nsname, {}).get('A', set()) | r.get(nsname, {}).get('AAAA', set()) for _, _, _, r in replies))
                             if nsname == domain or nsname.endswith('.' + domain) else set())
                if not addresses:
                    addresses = set(lookup(nsname, 'A')[1] + lookup(nsname, 'AAAA')[1])
                for addr in sorted(addresses)[:2]:
                    child_status, rr = dig(name, typ, server=addr, family=(6 if ':' in addr else 4))
                    if child_status == 'NOERROR':
                        child_values = {v for host, rt, v in rr if host.lower().rstrip('.') == name and rt == typ}
                        break
                if child_status == 'NOERROR':
                    break
            if child_values and values and child_values != values:
                lines.append(f'WARN: {name} {typ} GLUE MISMATCH: parent={",".join(sorted(values))}, child={",".join(sorted(child_values))}')
            elif child_values and not values:
                lines.append(f'WARN: {name} {typ} available in child ({", ".join(sorted(child_values))}) but MISSING FROM PARENT GLUE (registrar host update may be needed)')
            elif values and child_status == 'NOERROR' and not child_values:
                lines.append(f'WARN: {name} {typ} parent glue present but child returned no {typ}')
            elif child_status != 'NOERROR':
                lines.append(f'UNKNOWN: Could not verify child {name} {typ} ({child_status})')
            elif values:
                lines.append(f'PASS: {name} {typ} matches child zone')
    if problems:
        lines.append(f'NOTE: {len(problems)} parent endpoints did not provide a usable referral')
    lines.append('Glue is parent referral ADDITIONAL data; no AXFR attempted. Absent AAAA glue is an operational warning, not by itself an RFC 9471 violation.')
    return lines


def nameserver_report(domain):
    out = ['Parent referral / glue and child authoritative checks; UDP/TCP over each available IPv4/IPv6 NS address.']
    out.extend(parent_glue_report(domain))
    st, nss = lookup(domain, 'NS')
    out.append(f'Resolver-visible NS ({st}): ' + (', '.join(nss) if nss else 'none'))
    for name in nss:
        nsname = name.rstrip('.')
        addresses = []
        for typ in ('A', 'AAAA'):
            addresses.extend((addr, 4 if typ == 'A' else 6) for addr in lookup(nsname, typ)[1])
        if not addresses:
            out.append(f'{nsname}: UNKNOWN: no nameserver addresses available')
        for addr, family in addresses:
            for tcp in (False, True):
                status, answer = dig(domain, 'SOA', server=addr, family=family, tcp=tcp)
                serial = next((x[2].split()[2] for x in answer if x[1] == 'SOA' and len(x[2].split()) > 2), '-')
                outcome = 'PASS' if status == 'NOERROR' and serial != '-' else 'WARN'
                out.append(f'{outcome}: {nsname} {addr} IPv{family} {"TCP" if tcp else "UDP"}: {status} SOA serial={serial}')
            state, child = dig(domain, 'NS', server=addr, family=family)
            childset = sorted({row[2].lower().rstrip('.') for row in child if row[1] == 'NS'})
            parentset = sorted({x.lower().rstrip('.') for x in nss})
            if childset and childset != parentset:
                out.append(f'WARN: child NS mismatch at {addr}: {", ".join(childset)}')
    return out


def hostname_delegation_report(domain, hostname):
    """Best effort: ask the registered domain's NS about a specific hostname's delegation."""
    if hostname.lower().rstrip('.') == domain.lower().rstrip('.'):
        return []
    lines = [f'Exact hostname: {hostname} (checking possible separate zone cut)']
    status, parent_nss = lookup(domain, 'NS')
    if not parent_nss:
        return lines + [f'UNKNOWN: no parent-domain authoritative server addresses ({status})']
    attempted = False
    for ns in parent_nss:
        ipaddrs = lookup(ns.rstrip('.'), 'A')[1] + lookup(ns.rstrip('.'), 'AAAA')[1]
        for addr in ipaddrs[:2]:
            st, delegated, _, tc = parent_referral(hostname, addr)
            if tc:
                st, delegated, _, _ = parent_referral(hostname, addr, tcp=True)
            if st != 'NOERROR':
                continue
            attempted = True
            if delegated:
                return lines + [f'NOTE: Hostname delegation found at {ns.rstrip(".")}: {", ".join(delegated)}']
            # A separate SOA on this server, without a referral, may indicate an
            # independently configured child zone shadowing records in the parent.
            soa_st, soa = dig(hostname, 'SOA', server=addr, family=(6 if ':' in addr else 4))
            if soa_st == 'NOERROR' and any(rtype == 'SOA' and owner.lower().rstrip('.') == hostname.lower().rstrip('.') for owner, rtype, value in soa):
                return lines + [f'WARN: {hostname} has its own SOA on {ns.rstrip(".")}; check for shadow zone or intended subdelegation']
            return lines + ['NOTE: No separate hostname delegation observed at a checked parent nameserver']
    if not attempted:
        lines.append('UNKNOWN: unable to inspect hostname delegation at parent-domain nameservers')
    return lines

def subdomain_report(domain, cfg):
    out = []
    for prefix in cfg.get('subdomains', ['www', 'mail', 'smtp', 'imap', 'pop', 'autodiscover', 'secure']):
        name = prefix + '.' + domain
        records = []
        for typ in ('CNAME', 'A', 'AAAA'):
            records += [f'{typ} {v}' for v in lookup(name, typ)[1]]
        if records:
            out.append(name + ': ' + ', '.join(records))
    return out or ['No selected subdomain records found (not a comprehensive enumeration)']


def audit(target, flags, cfg):
    kind, registered, obj, requested = rdap_for(target)
    if kind == 'domain':
        registrar_date, registrar_source, registrar_notice = registrar_expiration(registered, obj)
    else:
        registrar_date, registrar_source, registrar_notice = None, None, None
    out = [report_rdap(kind, registered, obj, requested,
                       registrar_expiry=registrar_date,
                       registrar_source=registrar_source,
                       registrar_notice=registrar_notice)]
    if kind != 'domain':
        if any(flags):
            out.append('\nDNS options require a domain or hostname; registration report shown only.')
        return '\n'.join(out)
    name = requested or registered
    cache = {}
    web, mail, hosting, sub, secure, black, names, full = flags
    if web or hosting or full:
        add_section(out, 'WEB HOSTING', web_report(name, cache))
    if mail or hosting or full:
        add_section(out, 'MAIL HOSTING', mail_report(name, cache))
    if sub or full:
        add_section(out, 'SUBDOMAIN LOOKUPS', subdomain_report(name, cfg))
    if secure or full:
        add_section(out, 'EMAIL SECURITY', security_report(name, cfg['dkim_selectors']))
    if black or full:
        add_section(out, 'DNS BLOCKLISTS', blacklist_report(name, cfg))
    if names or full:
        add_section(out, 'NAMESERVER AND TRANSPORT AUDIT', nameserver_report(registered) + hostname_delegation_report(registered, name))
    return '\n'.join(out)
