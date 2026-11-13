# Internals
If you're wondering about how ZeeCrypt handles cryptography, you've come to the right place! This page contains the technical details about the cryptographic algorithms and parameters used, as well as how cryptographic values are stored in the header format.

# Core Cryptography
ZeeCrypt uses the following cryptographic primitives:
- XChaCha20 (cascaded with Serpent in counter mode for paranoid mode)
- Keyed-BLAKE2b for normal mode, HMAC-SHA3 for paranoid mode (256-bit key, 512-bit digest)
- HKDF-SHA3 for deriving a subkey for the MAC above, a key for Serpent, and a subkey for the header HMAC below
- Argon2id:
    - Normal mode: 4 passes, 1 GiB memory, 4 threads
    - Paranoid mode: 8 passes, 1 GiB memory, 8 threads

All primitives used are from the well-known [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) module.

# Volume Format v3
Since v3.0.0, new volumes use format v3 (`src/volume`). Volumes in the older formats still open (see "Header Format (v2)" below), but older versions of ZeeCrypt can't open v3 volumes.

**A random file key.** The data is encrypted under a random 32-byte file key, not directly under the password. The header holds one or more *stanzas*, each of which wraps the file key for one way of opening the volume (the design of [age](https://age-encryption.org)). Decryption tries each stanza until one opens; no key IDs are stored. Stanza types:
- **Password** (type 1): Argon2id(password) with the same parameters as before (4 passes / 1 GiB / 4 threads, or 8 / 1 GiB / 8 in paranoid mode), combined with the keyfile key if keyfiles are used, through HKDF-SHA3. The file key is wrapped with ChaCha20-Poly1305 under that key. Body: Argon2 salt (16) | wrapped key (48).
- **Recipient** (type 2): see "Public-Key Recipients" below. **FIDO2** (type 3): see "Hardware Keys" below.

**Keys.** HKDF-SHA3-256 (salt: a random 32-byte value in the header) derives from the file key: the header MAC key, the XChaCha20 key, the Serpent key and the chunk MAC key.

**Header MAC.** HMAC-SHA3-256 over the version, comments, flags and every stanza, each length-prefixed. Unlike v2, the comments are authenticated: they're still readable without the password, but can't be changed without detection. Stanzas can't be added, removed or reordered.

**Chunks (closes PCC-004).** The data is split into chunks of 1 MiB − 32 bytes of plaintext (1 MiB − 160 with Reed-Solomon). For chunk *i*:
```
ciphertext = XChaCha20(key, nonce = 0^16 | i)( Serpent-CTR(key, iv = i | 0^8)(plaintext) )   Serpent only in paranoid mode
tag        = MAC(i | last | ciphertext)          keyed BLAKE2b-256, or HMAC-SHA3-256 in paranoid mode
stored     = ciphertext | tag                    with Reed-Solomon: PKCS#7-padded to 128 bytes, then 128+8 encoded
```
Each chunk's tag is checked **before** it's decrypted or written, so damaged or modified data never reaches the output (unless "Force decrypt" is on). The *last* bit marks the final chunk, so a volume can't be cut short at a chunk boundary, and the index stops chunks being reordered. With Reed-Solomon, a chunk is first checked as stored and only repaired if that fails, so repair now happens per chunk instead of in a second pass over the whole file.

**Layout.** The first four fields are the same as v2, so comments and flags read the same way for every version:

| Encoded size | Decoded size | Description
| ------------ | ------------ | -----------
| 15           | 5            | Volume format version, "v3.00"
| 15           | 5            | Length of comments, zero-padded to 5 bytes
| 3C           | C            | Comments
| 15           | 5            | Flags: paranoid, keyfiles, keyfile order, Reed-Solomon, signed
| 15           | 5            | Header block length L (big-endian)
| 3·⌈L/32⌉·32  | L            | Header block, Reed-Solomon encoded in 32-byte units: HKDF salt (32), stanza count (2), stanzas (type 1, length 4, body), header MAC (32)
| 384          | 128          | Signature block, only if signed (see "Sender Signatures")
|              |              | Data chunks

Deniability works as before: the whole v3 volume is wrapped in a headerless XChaCha20 layer keyed by Argon2id(password).


# Public-Key Recipients
A volume can be encrypted to people's public keys instead of, or as well as, a password. Each person has an *identity*: a file holding their private keys, encrypted with their own password (as a v3 volume, paranoid mode with Reed-Solomon). Their public key, a `zeecrypt1…` string or `.pub` file, is safe to share.

A public key bundles three keys: X25519 and ML-KEM-768 (to encrypt to you) and Ed25519 (to check your signatures). It's encoded as Bech32, so a typo is caught by the checksum. The fingerprint shown in the app is the first 80 bits of SHA-256 of the Ed25519 key, in base32; compare it over another channel (a call, in person) before trusting a key you received.

**Recipient stanza** (type 2), hybrid so that it stays secure if either X25519 or ML-KEM is broken (X25519 alone would fall to a large quantum computer):
```
ephemeral X25519 key (32) | ML-KEM-768 ciphertext (1088) | wrapped file key (48)
wrap key = HKDF-SHA3-256(X25519 shared secret | ML-KEM shared secret,
                         salt = SHA3-256(ephemeral key | ciphertext | recipient's X25519 key | recipient's ML-KEM key),
                         info = "zeecrypt v3 recipient stanza")
```
Stanzas don't name their recipient: each recipient tries every stanza. Public-key volumes can't use deniability: its outer layer is opened with the password alone, which recipients don't have.

# Sender Signatures
A volume can be signed with the sender's identity. A signed volume has a 128-byte signature block (384 bytes on disk) after the header block: the signer's Ed25519 public key and a signature over
```
"zeecrypt v3 signature" | header MAC | SHA3-256(every chunk tag, in order)
```
The header MAC covers every stanza and the chunk tags cover all the data, so the signature can't be moved to another volume, and a recipient can't re-encrypt the volume to someone else and keep the signature (surreptitious forwarding). The block is encrypted with ChaCha20-Poly1305 under a key derived from the file key, so only people who can open the volume see who signed it. On decryption the app shows "signed by <contact>" for a contact, "signed by unknown <fingerprint>" otherwise, and warns if a signature doesn't verify. Signatures are Ed25519 only (not yet post-quantum).

# Hardware Keys
A volume can require a FIDO2 security key (YubiKey, SoloKey, Google Titan, …) on top of its password. ZeeCrypt uses the key's `hmac-secret` extension (WebAuthn PRF) through the Windows WebAuthn API (`webauthn.dll`), so Windows shows its own touch and PIN prompts, and no drivers, admin rights or vendor software are needed. It needs Windows 11 22H2 or later and a key with a PIN: user verification is always required, because a key derives a different secret with and without it.

When encrypting, ZeeCrypt registers a credential on the key (one touch) and asks it for a secret from a random 32-byte salt (a second touch). The **FIDO2 stanza** (type 3) wraps the file key under
```
HKDF-SHA3-256(Argon2id(password) | keyfile key | key secret, salt = Argon2 salt, info = "zeecrypt v3 fido2 stanza")
```
Body: Argon2 salt (16) | PRF salt (32) | credential ID length (2) | credential ID | wrapped key (48). The password alone, or the key alone, opens nothing. Losing the key means losing the volume, so the app suggests also encrypting to your own public key as a backup. Security keys work with deniability (the outer layer only needs the password).
# Counter Overflow (v2)
In the v2 format, since XChaCha20 has a max message size of 256 GiB, ZeeCrypt will use the HKDF-SHA3 mentioned above to generate a new nonce for XChaCha20 and a new IV for Serpent if the total encrypted data is more than 60 GiB. While this threshold can be increased up to 256 GiB, ZeeCrypt uses 60 GiB to prevent any edge cases with blocks or the counter used by Serpent.

# Header Format (v2)
Volumes made before v3.0.0 (header version v1.50 to v1.52) use this format; ZeeCrypt still reads it. Its header is encoded with Reed-Solomon by default since it is, after all, the most important part of the entire file. An encoded value will take up three times the size of the unencoded value.

**All offsets and sizes below are in bytes.**
| Offset | Encoded size | Decoded size | Description
| ------ | ------------ | ------------ | -----------
| 0      | 15           | 5            | Volume format version (ex. "v1.52"). Since v2.0.0 this is independent of the app version and stays "v1.52" until the format changes
| 15     | 15           | 5            | Length of comments, zero-padded to 5 bytes
| 30     | 3C           | C            | Comments with a length of C characters
| 30+3C  | 15           | 5            | Flags (paranoid mode, use keyfiles, etc.)
| 45+3C  | 48           | 16           | Salt for Argon2
| 93+3C  | 96           | 32           | Salt for HKDF-SHA3
| 189+3C | 48           | 16           | IV for Serpent
| 237+3C | 72           | 24           | Nonce for XChaCha20
| 309+3C | 192          | 64           | HMAC-SHA3-512 of the header (flags, salts, IVs), keyed by a subkey derived from the password and keyfiles
| 501+3C | 96           | 32           | SHA3-256 of keyfile key, or zeros (see "Keyfile Design")
| 597+3C | 192          | 64           | Authentication tag (BLAKE2b/HMAC-SHA3)
| 789+3C |              |              | Encrypted contents of input data

As of v1.50, this header HMAC replaces a bare SHA3-512 hash of the encryption key. Verifying it before any data is processed both detects an incorrect password and detects tampering with the header's decryption parameters (flags, salts, IVs) — closing findings PCC-001 and PCC-006 from the original Picocrypt security audit (Radically Open Security, September 2024). The comment field is deliberately excluded from this HMAC (see the in-app tooltip: comments are neither encrypted nor tamper-protected). This is a breaking format change — ZeeCrypt v1.50 cannot open volumes created by Picocrypt or by ZeeCrypt versions prior to 1.50.

As of v2.0.0, the header HMAC subkey is derived (HKDF-SHA3, info `zeecrypt-header-mac`) from the final encryption key, i.e. after the Argon2 output has been XORed with the keyfile key. In v1.50–1.51 it was derived before that XOR, so for a keyfile-only volume (empty password) the subkey depended only on `argon2id("", salt)` — computable from the header alone — and anyone could rewrite the header parameters and recompute a valid HMAC. Because the data MAC authenticates the ciphertext but not the nonce/IV, a rewritten nonce then decrypted "successfully" to garbage. This is another breaking change, but only for volumes that use keyfiles: keyfile volumes made with v1.50 or v1.51 must be decrypted with an existing copy of v1.51 before upgrading, then re-encrypted. Password-only volumes are unaffected.

# Keyfile Design
ZeeCrypt allows the use of keyfiles as an additional form of authentication. ZeeCrypt's unique "Require correct order" feature enforces the user to drop keyfiles into the window in the same order as they did when encrypting in order to decrypt the volume successfully. Here's how it works:

If correct order is not required, ZeeCrypt will take the SHA3-256 of each keyfile individually and XOR the hashes together. Finally, the result is XORed with the master key. Because the XOR operation is both commutative and associative, the order in which the keyfile hashes are XORed with each other doesn't matter - the end result is the same.

If correct order is required, ZeeCrypt will concatenate the keyfiles together in the order they were dropped into the window and take the SHA3-256 of the combined keyfiles. If the order is not correct, the keyfiles, when appended to each other, will result in a different file, and thus a different hash. So, the correct order of keyfiles is required to decrypt the volume successfully.

Because unordered keyfile hashes are XORed, two keyfiles with identical contents cancel each other out. Since v3.0.0, encryption refuses unordered keyfiles whose contents are identical (decryption still accepts them, for older volumes).

Volumes made before v3.0.0 store the SHA3-256 of the keyfile key in the header, so the app could tell "wrong keyfiles" from "wrong password". That hash lets an attacker test candidate keyfiles at SHA3 speed without the password or Argon2, so the password and keyfiles can be guessed one after the other rather than together. The v3 format has no such field: the header MAC alone verifies the keyfiles (and ZeeCrypt's v2 writer, which only tests use now, writes zeros there). On decryption of an older volume, the stored hash is still checked, so older volumes keep their more specific error messages.

Deniability requires a password since v3.0.0: the deniability layer is keyed by `argon2id(password, salt)` only, so with an empty password anyone could remove it.

# Reed-Solomon
By default, all ZeeCrypt volume headers are encoded with Reed-Solomon to improve resiliency against bit rot. The header uses N+2N encoding, where N is the size of a particular header field such as the version number, and 2N is the number of parity bytes added. Using the Berlekamp-Welch algorithm, ZeeCrypt is able to automatically detect and correct up to 2N/2=N broken bytes.

If Reed-Solomon is to be used with the input data itself, the data will be encoded using 128+8 encoding, with the data being read in 1 MiB chunks and encoded in 128-byte blocks, and the final block padded to 128 bytes using PKCS#7.

To address the edge case where the final 128-byte block happens to be padded so that it completes a full 1 MiB chunk, a flag is used to distinguish whether the last 128-byte block was padded originally or if it is just a full 128-byte block of data.

# Deniability
Plausible deniability in ZeeCrypt is achieved by simply re-encrypting the volume but without storing any identifiable header data. A new Argon2 salt and XChaCha20 nonce will be generated and stored in the deniable volume, but since both values are random, they don't reveal anything. A deniable volume will look something like this:
```
[argon2 salt][xchacha20 nonce][encrypted stream of bytes]
```

# Decrypt-Then-Verify (v2 volumes only)
Fixed in format v3, which authenticates each chunk before decrypting it (see "Volume Format v3"). For v2 volumes, ZeeCrypt computes the data's authentication tag incrementally as it decrypts each block, and only compares it against the stored tag after the entire file has been processed (this is PCC-004 from the Picocrypt security audit). A true fix requires reading the input twice — once to verify the tag before decrypting anything — which touches the Reed-Solomon repair path, the deniability temp-zip decryption wrapper, and split/recombine handling all at once, and was judged too risky to rewrite without a way to test it end-to-end.

For those volumes the impact is limited: decrypted output is always written to a `.incomplete` temp file and is only renamed to the final output path after the tag check succeeds, so tampered/attacker-controlled plaintext is never exposed to you as a finished, trusted file. The residual risk is a low-severity, side-channel-class theoretical concern (per the original audit) from decrypting attacker-controlled ciphertext into memory before the tag comparison completes. To get rid of it for an old volume, decrypt it and encrypt it again.

# Just Read the Code
The v3 format lives in `src/volume` (no UI code), the app in `src/ZeeCrypt.go`, which still contains the v2 reader. So if you need more information about how ZeeCrypt works, just read the code. It's not long, and it is well commented and will explain what happens under the hood better than a document can.
