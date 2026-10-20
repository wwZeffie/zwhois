Name:           zwhois
Version:        0.1.5
Release:        1%{?dist}
Summary:        WHOIS-style RDAP client with optional DNS and hosting auditing
License:        MIT
URL:            https://github.com/wwZeffie/zwhois
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
BuildRequires:  python3
Requires:       python3
Requires:       bind-utils
Requires:       dialog
# Dialog interface is a supported, installed feature, not an unfulfilled option.

%description
zwhois shows separate registry and registrar expiry dates and nameservers in a familiar
WHOIS-style format. Optional hosting, mail, DNS and DNSBL checks are
available. Interactive dialog mode is optional.

%prep
%setup -q

%build
# No build step (Python standard library).

%install
make install PREFIX=%{_prefix} DESTDIR=%{buildroot}

%check
python3 -m unittest discover -s tests -v

%files
%license LICENSE
%doc %{_datadir}/doc/zwhois/
%{_bindir}/zwhois
%{_prefix}/lib/zwhois/
%{_mandir}/man1/zwhois.1*

%changelog
* Tue Oct 20 2026 Zeffie <zeffie@invalid.example> - 0.1.5-1
- Fix registrar RDAP fractional timestamp parsing on Python 3.9 / AlmaLinux 9
- Add compatibility tests and preserve original timestamps in output

* Tue Oct 20 2026 Zeffie <zeffie@invalid.example> - 0.1.5-1
- Preserve both expiration timestamps but suppress warning for same-day sub-minute differences
- Regression tests for eNom ten-second offset and material mismatches

* Tue Oct 20 2026 Zeffie <zeffie@invalid.example> - 0.1.3-1
- Retrieve registrar expiration from registrar RDAP using IANA registrar IDs
- Report registry and registrar expiration separately; warn on mismatches
- Retain registry lookup on registrar RDAP failures

* Tue Oct 20 2026 Zeffie <zeffie@invalid.example> - 0.1.2-1
- Parent authoritative referral and glue checks, improved docs and DNSBL error handling

* Tue Oct 20 2026 Zeffie <zeffie@invalid.example> - 0.1.1-1
- Restore visible dialog UI; use dedicated output file descriptor
- Fix duplicate RPM documentation entries; depend on dialog
* Tue Oct 20 2026 Zeffie <zeffie@invalid.example> - 0.1.0-1
- Initial test source packaging
