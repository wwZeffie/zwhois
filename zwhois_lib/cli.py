"""zwhois command line and dialog UI."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from . import __version__
from .core import LookupError_, audit, load_config

EXAMPLES = '''Examples:
  zwhois example.com                   Registry/registrar expiry dates, nameservers
  zwhois secure.example.com            Registration for parent; DNS checks target host
  zwhois 8.8.8.8                       IP network RDAP lookup
  zwhois 2001:4860:4860::8888          IPv6 network RDAP lookup
  zwhois AS15169                       Autonomous system registration
  zwhois -m example.com                MX, mail host IPs and network owners
  zwhois -w example.com                Website and www DNS + network owners
  zwhois -H example.com                Both web and mail hosting
  zwhois -s -S example.com             Subdomains, SPF/DMARC/DKIM selectors
  zwhois -b example.com                DNS blocklist checks (provider-dependent)
  zwhois -ns example.com               Parent glue + authoritative DNS IPv4/IPv6 UDP/TCP
  zwhois -H -ns example.com            Combine checks
  zwhois -f example.com                Full report
  zwhois -d                             Interactive dialog interface
  zwhois example.com example.net       Multiple targets
  zwhois < domains.txt                 One target per input line
  zwhois < domains.txt > audit.txt     Save combined reports

  The < sign redirects a text file into standard input. The > sign saves
  output to a file. A plain domain list is supported, NOT a registrar CSV.
  Registry and registrar expiration dates are distinct; either may be missing.
  Missing RDAP fields are reported as Not provided. Results are observations,
  not guarantees of host ownership, deliverability, or security.
  Configuration: ~/.config/zwhois/config.json (see example in source archive).
  For the optional dialog shortcut add: alias zwhois='zwhois -d'
  To bypass that alias in a script or command use: command zwhois -m example.com
'''


def parser():
    p = argparse.ArgumentParser(prog='zwhois', description='WHOIS-style RDAP registry/registrar expiry, registration and optional DNS/hosting audits (no pip packages required)', epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('targets', nargs='*', help='Domain, hostname, IPv4/IPv6 address, or AS number; reads redirected stdin if none')
    p.add_argument('-m', '--mail', action='store_true', help='MX, mail server addresses, IP RDAP ownership')
    p.add_argument('-w', '--web', action='store_true', help='A/AAAA/CNAME for hostname and www; IP RDAP ownership')
    p.add_argument('-H', '--hosting', action='store_true', help='Web and mail hosting summary')
    p.add_argument('-s', '--subdomains', action='store_true', help='Configured common subdomain DNS checks')
    p.add_argument('-S', '--security', action='store_true', help='SPF, DMARC and configured DKIM selector checks')
    p.add_argument('-b', '--blocklists', action='store_true', help='Configured DNSBL lookups for web and MX IPs')
    p.add_argument('-ns', '--nameservers', action='store_true', help='Parent NS/glue and child SOA/NS, UDP/TCP IPv4/IPv6')
    p.add_argument('-f', '--full', action='store_true', help='Run all optional checks')
    p.add_argument('-d', '--dialog', action='store_true', help='Interactive dialog UI (dialog or whiptail package)')
    p.add_argument('--config', default=str(Path.home() / '.config/zwhois/config.json'), help='JSON configuration path')
    p.add_argument('--version', action='version', version='zwhois ' + __version__)
    return p


def dialog_ui(cfg):
    program = shutil.which('dialog') or shutil.which('whiptail')
    if not program:
        print('zwhois: -d requires the dialog or whiptail program (install the dialog package).', file=sys.stderr)
        return 2
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        print('zwhois: -d requires an interactive terminal (run it from a shell or SSH session).', file=sys.stderr)
        return 2
    target = ''
    flags = ['-H']
    # dialog and whiptail draw the UI on the terminal. Capture only the user's
    # selections on a dedicated file descriptor, never the terminal screen.
    # Redirecting stderr to PIPE hides the UI (regression in the first release).
    def screen(*args):
        with tempfile.TemporaryFile(mode='w+b') as output:
            proc = subprocess.run(
                [program, '--output-fd', str(output.fileno()),
                 '--title', 'zwhois ' + __version__, *args],
                pass_fds=(output.fileno(),),
                check=False,
            )
            output.seek(0)
            selected = output.read().decode('utf-8', errors='replace').strip()
        return proc.returncode, selected
    while True:
        code, choice = screen('--menu', 'Current target: ' + (target or '(none)') + '\nOptions: ' + ' '.join(flags), '19', '76', '8', '1', 'Change domain or hostname', '2', 'Select tests', '3', 'Run selected tests', '4', 'View last report', '5', 'Exit')
        if code != 0 or choice == '5':
            return 0
        if choice == '1':
            code, new_target = screen('--inputbox', 'Enter a domain, hostname, IPv4/IPv6 address or AS number:', '10', '76', target)
            if code == 0 and new_target.strip():
                target = new_target.strip()
        elif choice == '2':
            choices = [('-m','Mail'), ('-w','Web'), ('-H','Hosting'), ('-s','Subdomains'), ('-S','Email-security'), ('-b','DNSBL'), ('-ns','Nameservers'), ('-f','Full')]
            args = ['--separate-output', '--checklist', 'Select any tests (SPACE to toggle, ENTER to save):', '20', '76', '9']
            for flag, label in choices:
                args.extend([flag, label, 'on' if flag in flags else 'off'])
            code, selected = screen(*args)
            if code == 0:
                flags = selected.replace('"','').split()
        elif choice == '3':
            if not target:
                screen('--msgbox', 'Enter a target first.', '7', '50')
                continue
            try:
                report = audit(target, tuple(f in flags for f in ('-w','-m','-H','-s','-S','-b','-ns','-f')), cfg)
            except (LookupError_, ValueError) as exc:
                report = 'Lookup failed: ' + str(exc)
            last_report = report
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.txt', prefix='zwhois-', delete=False) as f:
                f.write(report + '\n')
                filename = f.name
            try:
                screen('--textbox', filename, '22', '90')
            finally:
                os.unlink(filename)
        elif choice == '4':
            if 'last_report' not in locals():
                screen('--msgbox', 'Run a report first.', '7', '50')
            else:
                with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.txt', prefix='zwhois-', delete=False) as f:
                    f.write(last_report + '\n')
                    filename = f.name
                try:
                    screen('--textbox', filename, '22', '90')
                finally:
                    os.unlink(filename)


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if not args.targets and not args.dialog and sys.stdin.isatty():
        p.print_help()
        return 0
    try:
        cfg = load_config(args.config)
    except LookupError_ as exc:
        print('zwhois: ' + str(exc), file=sys.stderr)
        return 2
    if args.dialog:
        return dialog_ui(cfg)
    targets = args.targets if args.targets else [x.strip() for x in sys.stdin if x.strip() and not x.lstrip().startswith('#')]
    if not targets:
        p.print_help()
        return 0
    flags = (args.web, args.mail, args.hosting, args.subdomains, args.security, args.blocklists, args.nameservers, args.full)
    errors = 0
    for target in targets:
        try:
            print(audit(target, flags, cfg))
        except (LookupError_, ValueError, OSError) as exc:
            print(f'zwhois: {target}: {exc}', file=sys.stderr)
            errors += 1
        print()
    return 1 if errors else 0
