## Summary
<!-- What does this PR change, and why? -->

## Testing
<!-- This is cryptographic software - a change that looks correct in the diff can still silently
break encryption/decryption. Delete lines that don't apply to this PR. -->
- [ ] Build succeeds (`go build .` from `src/`, not naming `ZeeCrypt.go` directly)
- [ ] Encrypt → decrypt round-trip: normal mode
- [ ] Encrypt → decrypt round-trip: paranoid mode
- [ ] Encrypt → decrypt round-trip: keyfiles (ordered and unordered)
- [ ] Encrypt → decrypt round-trip: deniability
- [ ] Encrypt → decrypt round-trip: Reed-Solomon
- [ ] Encrypt → decrypt round-trip: split/recombine
- [ ] Wrong password on decrypt still fails as expected
- [ ] Not applicable (docs/CI/packaging-only change)

## Breaking changes
<!-- Does this change the on-disk volume format, or anything else that breaks compatibility
with volumes from earlier versions? If so, call it out explicitly here. -->
