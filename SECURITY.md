# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately through GitHub's
[private vulnerability reporting](https://github.com/ZachGSnow/ad-health-check/security/advisories/new).
Include what you found, how to reproduce it, and the impact you expect.

You can expect an acknowledgement within 7 days. Fixes are released as a patch version
and credited in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Secrets

This repository never contains real credentials. The script takes none: it runs as the
signed-in administrator and has no configuration file.
Every push is scanned with [gitleaks](https://github.com/gitleaks/gitleaks).
