# Security Policy

## Supported Versions

Only the latest released version of ZeeCrypt is supported with security fixes. Older versions, and volumes encrypted with them, may not be compatible with the latest release — see [Changelog.md](Changelog.md) for breaking changes between versions.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting for this repository:

1. Go to the [Security tab](https://github.com/TheZeekA/ZeeCrypt/security)
2. Click **Report a vulnerability**

This opens a private conversation with the maintainer that isn't visible to the public until it's resolved.

If you'd rather not use GitHub's reporting tool, you can contact [@TheZeekA](https://github.com/TheZeekA) directly.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce it, or a proof of concept if possible
- The version of ZeeCrypt affected

You should expect an initial response within a few days. There's no bug bounty program, but you'll be credited (if you'd like) once a fix is released.

## Scope

ZeeCrypt is designed for the offline security of encrypted volumes and assumes the host machine it runs on is trusted — see the [Security section of the README](README.md#security) and [Internals.md](Internals.md) for the threat model and known limitations (including PCC-004, an already-documented low-severity issue). Reports about that specific documented limitation don't need to be filed again, but new findings are always welcome.
