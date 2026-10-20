#!/bin/sh
# Readable report with best-effort LIVE probes. No local configuration changed.
set -u
printf 'zwhois installed smoke test UTC: '; date -u
printf '\n=== INSTALLED COMMAND ===\n'
command -v zwhois || exit 2
printf '\n=== VERSION ===\n'
zwhois --version || exit 2
printf '\n=== HELP ===\n'
zwhois -h || exit 2
printf '\n=== RDAP DOMAIN ===\n'
zwhois example.com || echo 'LIVE LOOKUP FAILED or service unavailable'
printf '\n=== TWO EXPIRY EVENTS (registrar RDAP) ===\n'
zwhois thelinuxpros.com || echo 'LIVE REGISTRAR EXPIRY LOOKUP FAILED or service unavailable'
printf '\n=== RDAP IPv4 ===\n'
zwhois 8.8.8.8 || echo 'LIVE LOOKUP FAILED or service unavailable'
printf '\n=== PARENT GLUE AND DNS TRANSPORT ===\n'
zwhois -ns example.com || echo 'LIVE LOOKUP FAILED or service unavailable'
printf '\n=== REPORT COMPLETE ===\n'
