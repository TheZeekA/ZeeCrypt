# Contributing to ZeeCrypt

Thanks for wanting to contribute! ZeeCrypt is actively maintained and open to bug reports, feature requests, and pull requests.

## Before you start

- For anything beyond a small fix, consider opening an issue first to discuss the change — this avoids wasted work if the approach needs adjusting.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead of opening a public issue or PR.
- Read the [Code of Conduct](CODE_OF_CONDUCT.md).

## Building from source

See [src/README.md](src/README.md) for full build instructions. In short:
```
cd src
go build -ldflags="-s -w -H=windowsgui -extldflags=-static" .
```
Note the `.` at the end rather than naming `ZeeCrypt.go` directly — Go only auto-links the `.syso` icon resource files when building the package as a whole.

## Making changes

This repo uses two long-lived branches:
- **`testing`** — active development. Push feature branches and open PRs against this.
- **`main`** — release branch. Protected: changes only land here via PR from `testing` (or a fix branch), typically once a batch of work on `testing` is ready to ship.

Workflow for a change:
1. Branch off `testing`
2. Make your change, and if you touch the encryption/decryption code, actually build and round-trip test it (encrypt then decrypt) — normal mode, paranoid mode, keyfiles, deniability, Reed-Solomon, and split/recombine as relevant to your change. This is cryptographic software; a change that looks correct but silently breaks decryption is worse than no change at all.
3. Open a PR into `testing`
4. Once merged, a maintainer will fold `testing` into `main` via a separate PR when it's ready for release

## Reporting bugs

Please include:
- ZeeCrypt version (shown in the window title)
- Steps to reproduce
- What you expected vs. what happened

## Style

This is a single-file Go application (`src/ZeeCrypt.go`). Match the existing style — run `gofmt` before committing. There's no test suite; changes to the cryptographic code path need to be manually verified by actually building and round-tripping real files (see above), since it can't be validated by reading the diff alone.
