# ZeeCrypt v3 feature plan

Five features, plus one security item left open by the v2.1.0 audit fixes. Each one is modelled on how an established tool does it; the tool is named in each section.

| # | Feature | Modelled on | Format change | Size |
|---|---|---|---|---|
| 0 | Groundwork: split `work()`, v3 header with key "stanzas" | age | yes (new header version) | L |
| 1 | Public-key recipients | age, Kryptor | uses #0 | L |
| 2 | Hardware second factor (FIDO2) | KeePassXC, age-plugin-fido2-hmac, VeraCrypt tokens | uses #0 | M |
| 3 | Explorer "Encrypt" / "Decrypt" verbs | 7-Zip, AxCrypt | no | S (classic menu), M (Windows 11 top-level menu) |
| 4 | Sender signatures | minisign, Kryptor | uses #0 and #1 | M |
| 5 | Faster / stronger compression | 7-Zip (zstd/LZMA2), Windows 11 archive support | no (container choice only) | S–M |
| 6 | Signed updates (left open from the audit) | minisign, Authenticode | no | S |

Suggested order: **3 → 5 → 6 → 0 → 1 → 4 → 2**. Items 3, 5 and 6 don't touch the volume format, so they can ship as v2.x releases. Items 0, 1, 4 and 2 depend on each other and should ship together as v3.0.0.

## Status (2026-11-13)

Implemented on branch `feat/v3-features`, one commit per feature, with the defaults recommended below:

| # | Feature | State | Not done |
|---|---|---|---|
| 3 | Explorer verbs | Phase A: `--encrypt`/`--decrypt`/`--`, Encrypt/Decrypt verbs, quoted `"%1"`, single instance over a named pipe | Phase B (Windows 11 top-level menu) needs code signing |
| 5 | Compression | zstd Fast/Balanced/Maximum in `.tar.zst`; auto-unzip reads it | xz/LZMA2 (zstd's maximum level was judged enough); skipping already-compressed files (zstd stores incompressible blocks quickly anyway) |
| 6 | Signed updates | Ed25519 `.sig` per release, `cmd/zeecrypt-sign`, CI step | Generating the release key (owner); Authenticode |
| 0 | v3 format | `src/volume`: file key + stanzas, chunked MACs (**PCC-004 fixed**), per-chunk Reed-Solomon repair, authenticated comments | |
| 1 | Public-key recipients | X25519 + ML-KEM-768 stanza, `src/keys` identities and contacts, UI | |
| 4 | Signatures | Ed25519, encrypted signature block | ML-DSA (post-quantum) signatures |
| 2 | Security keys | FIDO2 hmac-secret via `webauthn.dll`, second factor only, PIN required | **Untested on real hardware**; TPM alternative |

Decisions taken: (1) v3 fixes PCC-004: yes. (2) "Open with ZeeCrypt" kept alongside the new verbs. (3) Security key = second factor only, PIN (user verification) required. (4) No code-signing certificate assumed. (5) The one-file convention is broken: `src/volume`, `src/keys`, `src/fido2`, `src/internal/releasesig`, plus `instance.go`, `archive.go`, `v3work.go`, `keysui.go` in package main.

Correction to section 1 below: public keys and deniability don't conflict because stanzas are distinguishable (the deniability layer encrypts the whole volume, stanzas included). They conflict because that layer is opened with the password alone, which recipients don't have.

---

## 0. Groundwork (do this before 1, 2 and 4)

**Why.** `work()` is about 1,450 lines in a single function that reads its options from package globals. Recipients, hardware keys and signatures all change how the *file key* is obtained. Adding three new key paths inside `work()` would be very hard to review or test.

**Steps**
1. Move the volume format into its own package, `src/volume/`, with no UI or globals. For example: `Encrypt(r io.Reader, w io.WriteSeeker, opts Options, keys []KeySource)` and `Decrypt(...)`, reporting progress through a callback. The current one-file convention in `CONTEXT.md` gets an explicit exception for this.
2. Keep `ZeeCrypt.go` as the UI. `work()` becomes the glue: zip, recombine, call `volume.*`, split.
3. Pin current behaviour first: the existing end-to-end tests plus the v1.51/v2.0.0 fixtures in `src/testdata/` must keep passing after the move.

**v3 header: a random file key wrapped by one or more "stanzas" (the age design).** Today the data key *is* `argon2(password) XOR keyfileKey`. In v3:
- A random 32-byte **file key** encrypts the data, using the same XChaCha20 (+ Serpent in paranoid mode), MAC and Reed-Solomon pipeline as now.
- The header holds a list of **stanzas**. Each one wraps the file key for one way of unlocking it:
  - **`argon2`**: password (+ keyfiles), the same parameters as today.
  - **`x25519-mlkem768`**: a public-key recipient (#1).
  - **`fido2`**: a hardware key (#2), used *in addition to* a password stanza (see #2).
- Each stanza wraps the file key with XChaCha20-Poly1305 under a key derived from that stanza's secret.
- Decryption tries each stanza until one opens. No key IDs are stored (as in age), so the header doesn't reveal who the recipients are.
- The header MAC is keyed from the file key and covers every stanza, so stanzas can't be added, removed or reordered without detection.
- Version string: `v3.00`. The decrypt path keeps the v1.5x/v2.x reader so older volumes still open.

**Decide now (open question):** should v3 also fix PCC-004 (decrypt-then-verify), using STREAM-style chunked AEAD (as in age and Tink)? Every chunk would be authenticated before it's written. The cost is the RS repair path, which then works per chunk. Doing it in the same format break is much cheaper than another break later.

**Tests:** round trips for each stanza type; mixed stanzas (password + 2 recipients); tampering with each stanza and header field is rejected; old fixtures still open.

---

## 1. Public-key recipients (age, Kryptor)

**What users get.** Encrypt "to Alice and Bob" using their public keys. No shared password is exchanged, and each recipient opens the file with their own private key.

**Crypto**
- Hybrid **X25519 + ML-KEM-768**, both in the Go standard library (`crypto/ecdh`, `crypto/mlkem`). The wrap key is `HKDF-SHA3(x25519_shared || mlkem_shared, transcript)`. X25519 alone is not quantum-resistant, and the README FAQ promises quantum security, so the post-quantum half is required, not optional.
- The transcript includes both ephemeral public keys and the recipient's public key, which binds the wrap to that recipient.

**Keys**
- Public key: a Bech32 string such as `zeecrypt1…`, safe to paste into chat or email.
- Identity (private key): a file encrypted with the existing password stanza (Argon2), the same way age protects passphrase-encrypted identities. Stored wherever the user chooses; ZeeCrypt keeps no keyring by default.
- UI: a new "Keys" modal with Generate identity, Copy my public key and Export. The encrypt screen gets a "Recipients" button that opens a list modal: paste a key or load a `.pub` file. A volume can mix recipients with a password.

**Limits to document**
- **Not compatible with deniability.** The deniability layer is opened with the password alone, which recipients don't have. Disable the combination in the UI.
- Anyone can encrypt *to* you, so a recipient-encrypted file says nothing about who sent it. That's what #4 solves.

**Tests:** KAT vectors for the wrap; wrong identity is rejected; a stanza for another recipient is skipped; an encrypted identity with the wrong password fails cleanly.

---

## 2. Hardware second factor (KeePassXC, age-plugin-fido2-hmac)

**Recommendation: FIDO2 `hmac-secret` / PRF through the Windows WebAuthn API (`webauthn.dll`).** It works with any FIDO2 key (YubiKey 5, SoloKey, Google Titan, …) and needs no drivers, no admin rights and no vendor SDK, which matches ZeeCrypt's "Permissions: None" promise. The YubiKey-only HMAC-SHA1 challenge-response that KeePassXC uses would need raw HID access and vendor-specific code, so it's not recommended.

**Design**
- Enrolment (during encryption): `WebAuthNAuthenticatorMakeCredential` with the hmac-secret extension. Store the **credential ID** and a random 32-byte **salt** in a `fido2` stanza.
- Unlock: `WebAuthNAuthenticatorGetAssertion` with that salt returns a 32-byte secret, which needs touch and/or PIN on the key.
- **Second factor, not a replacement:** the `fido2` stanza wraps the file key under `HKDF(argon2(password) || hmac_secret)`, so both are needed. (A hardware-only mode could be offered later.)
- **Lost-key safety:** require either two enrolled keys or an explicit "I have a backup" checkbox. Optionally print a one-time recovery code, which would be another password stanza.
- Calls are made through `syscall.NewLazyDLL("webauthn.dll")`, the same approach as the new clipboard code. Check `WebAuthNGetApiVersionNumber()`: hmac-secret needs API v3 or later (present on Windows 11), and PRF needs a later version.

**Alternative worth listing:** TPM-bound keys via the Windows Hello / NCrypt platform provider ("only this PC can open it"). This is simpler for users, but the volume becomes unrecoverable if the machine dies. Only offer it alongside a password stanza.

**Open questions:** require a PIN as well as touch? Allow hardware-only volumes?

**Tests:** the WebAuthn calls sit behind an interface with a fake authenticator in tests; one manual test on real hardware per release.

---

## 3. Explorer "Encrypt" / "Decrypt" verbs (7-Zip, AxCrypt)

**What exists today:** a single "Open with ZeeCrypt" verb on `*` and `Directory` (`dist/windows/installer.wxs`), with auto-detection in `onDrop()`.

**Check first:** the verb's command is `"…ZeeCrypt.exe" %1` with `%1` **unquoted**. Paths containing spaces are probably being split into several arguments. Reproduce on a real install before changing it, because the multi-select behaviour (`MultiSelectModel=Player`) depends on how the arguments are passed.

**Phase A: classic menu (small, no signing needed)**
1. CLI: add `--encrypt`, `--decrypt` and `--` (end of options) to `main()`. Parse only these, and treat every other argument as a path (the v2.1.0 fix removed `flag` so paths starting with `-` work; keep that). `--encrypt` on a `.pcv` file forces encryption, for example double-encrypting with a different key. `--decrypt` on a non-volume shows "not a ZeeCrypt volume".
2. WiX verbs:
   - `*\shell\ZeeCrypt.Encrypt` and `Directory\shell\ZeeCrypt.Encrypt`: "Encrypt with ZeeCrypt", hidden on `.pcv` files with an `AppliesTo` condition like `NOT System.FileExtension:=.pcv`.
   - `ZeeCrypt.pcv\shell\ZeeCrypt.Decrypt`, plus a `.pcv.*` chunk rule via `AppliesTo`: "Decrypt with ZeeCrypt".
   - Keep "Open with ZeeCrypt" (or drop it in favour of the two verbs; product decision).
3. **Single instance:** right-clicking several selections in quick succession currently opens several windows. Add a named mutex plus a named pipe, so a second launch forwards its arguments to the running window, which applies them through `onWindowDrop` (so they're also ignored while busy).

**Phase B: Windows 11 top-level menu (medium)**
On Windows 11, classic verbs only appear under "Show more options". Showing in the compact menu needs an `IExplorerCommand` COM handler registered through a **sparse MSIX package**. That requires a code-signing certificate, and the handler is a small C++ DLL, because Go can't easily build a COM in-process server. Only worth doing once releases are code-signed (see #6).

**Tests:** argument-parser unit tests (including `-dash` file names and `--`); a manual install/uninstall checklist covering spaces, Unicode names, multi-select and folders.

---

## 4. Sender signatures (minisign, Kryptor)

**What users get.** On decryption: "Signed by Alice ✓", "Signed by an unknown key (fingerprint …)" or "Not signed".

**Design**
- **Ed25519** signing identity, kept in the same identity file as the #1 keys (a separate key pair, never reused for X25519). Optionally hybrid with ML-DSA-65 for post-quantum signatures: use `crypto/mldsa` if the Go version in use has it, otherwise `cloudflare/circl`.
- **What's signed:** `"zeecrypt-sig-v1" || headerMAC || authTag || hash(recipient stanzas)`. That covers the whole header and all the ciphertext. Including the recipient list stops *surreptitious forwarding* (Bob re-encrypting Alice's signed message to Carol while it still appears to come from Alice).
- **Where it goes:** encrypted with a subkey of the file key in a trailing signature block, so only recipients learn who signed. A plaintext signature would let anyone with Alice's public key confirm she sent the file.
- A "Trusted senders" list (name → public key) lives in the identity file. Unknown signers show their fingerprint so it can be checked over another channel.
- Signing is optional per volume and requires #0. It doesn't depend on #1: password-only volumes can be signed too.

**Tests:** verify OK; tampered body or header fails; a signature moved to a re-encrypted copy for a different recipient fails; unknown signer is reported.

---

## 5. Faster and stronger compression (7-Zip)

**Today:** "Compress files" uses Deflate inside a `.zip`. That's slow, gives weak compression, and spends time recompressing files that are already compressed (JPEG, MP4, ZIP, …).

**Plan**
- When compression is on, use **zstd** via `github.com/klauspost/compress/zstd` (pure Go, multi-threaded, roughly 5–10× faster than Deflate at a similar or better ratio). Offer levels **Fast** (zstd 1), **Balanced** (zstd 3, the default) and **Maximum** (zstd 19, or `xz`/LZMA2 via `github.com/ulikunitz/xz`, which 7-Zip users will recognise).
- **Container:** a zip entry using zstd (method 93) can't be opened by Windows Explorer, which would break manual extraction. Use **`.tar.zst`** instead (`.tar.xz` for Maximum): Windows 11 Explorer opens both natively (libarchive support since 23H2). Keep the uncompressed `.zip` (Store) as the default when compression is off: it's fastest and opens everywhere.
- **Skip already-compressed files:** store `.jpg/.png/.mp4/.mkv/.zip/.7z/.docx/…` without recompressing (7-Zip does the same in its "analysis" mode). This gives a large speedup on photo and video folders.
- Auto-unzip gains tar extraction, using the same path checks as `zipEntryPathOK` (no `..`, absolute paths, drive letters, `:` or device names) and the same free-space check.
- **Security note for the README:** compressing before encrypting leaks a little about the content through the output size. That only matters for attacker-influenced data that is re-encrypted many times (CRIME-style attacks), which isn't ZeeCrypt's use case, but worth one sentence.

**Tests:** round trips at each level; mixed compressible and incompressible inputs; a malicious tar (with `..`, absolute paths or symlinks) is rejected; Explorer opening a `.tar.zst` is checked manually once.

---

## 6. Signed updates (left open from the audit)

**Problem:** the updater checks the SHA-256 published in the **same GitHub release** as the exe. That catches a corrupted download but not a tampered release (a compromised account or CI token).

**Plan (minisign-style, small)**
1. Generate an Ed25519 release key offline. The private key goes into a GitHub Actions secret, ideally an environment requiring manual approval. The **public key is compiled into ZeeCrypt**.
2. CI signs `ZeeCrypt.exe` and uploads `ZeeCrypt.exe.sig`.
3. The updater downloads both, verifies the signature against the built-in key, and also checks the version inside the signed message so an old build can't be served again (downgrade protection).
4. Transition: one release that ships the public key while still accepting checksum-only updates, after which checksum-only updates are refused.
5. Later: **Authenticode** signing (a certificate costs money). It also reduces SmartScreen and antivirus false positives, which the README already mentions, and is needed for #3 Phase B.

---

## Decisions needed from you
1. Should v3 fix PCC-004 with chunked authenticated encryption while the format is breaking anyway? (Recommended: yes.)
2. Drop "Open with ZeeCrypt" once Encrypt/Decrypt verbs exist, or keep all three?
3. Hardware key: second factor only, or also allow hardware-only volumes? Require a PIN?
4. Is a code-signing certificate in budget? It gates the Windows 11 top-level menu and Authenticode updates.
5. OK to break the one-file convention (`src/volume/` package) for v3?
