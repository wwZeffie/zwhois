PREFIX ?= /usr/local
DESTDIR ?=
.PHONY: all install uninstall test dist
all:
	@echo 'Run make install (no compilation necessary)'
install:
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/zwhois/zwhois_lib $(DESTDIR)$(PREFIX)/share/man/man1 $(DESTDIR)$(PREFIX)/share/doc/zwhois $(DESTDIR)$(PREFIX)/share/doc/zwhois/docs
	install -m 755 zwhois $(DESTDIR)$(PREFIX)/lib/zwhois/zwhois-cli
	install -m 644 zwhois_lib/*.py $(DESTDIR)$(PREFIX)/lib/zwhois/zwhois_lib/
	printf '#!/bin/sh\nexec python3 "$(PREFIX)/lib/zwhois/zwhois-cli" "$$@"\n' > $(DESTDIR)$(PREFIX)/bin/zwhois
	chmod 755 $(DESTDIR)$(PREFIX)/bin/zwhois
	install -m 644 man/zwhois.1 $(DESTDIR)$(PREFIX)/share/man/man1/
	install -m 644 README.md LICENSE CHANGELOG.md config/example.json $(DESTDIR)$(PREFIX)/share/doc/zwhois/
	install -m 644 docs/*.md $(DESTDIR)$(PREFIX)/share/doc/zwhois/docs/
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/zwhois $(DESTDIR)$(PREFIX)/share/man/man1/zwhois.1
	rm -rf $(DESTDIR)$(PREFIX)/lib/zwhois $(DESTDIR)$(PREFIX)/share/doc/zwhois $(DESTDIR)$(PREFIX)/share/doc/zwhois/docs
test:
	python3 -m unittest discover -s tests -v
