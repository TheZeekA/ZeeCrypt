package volume

// Sender signatures (minisign/Kryptor style).
//
// A signed volume has a fixed-size signature block right after the header
// block. It holds the signer's Ed25519 public key and a signature over
//
//	"zeecrypt v3 signature" | header MAC | SHA3-256(every chunk tag, in order)
//
// The header MAC covers every stanza, so a recipient can't re-encrypt the
// signed file to someone else and keep the signature (surreptitious
// forwarding); the chunk tags cover all the data. The block is encrypted
// under the file key, so only people who can open the volume learn who
// signed it.
//
// On disk: XChaCha20-Poly1305 (public key 32 | signature 64), zero-padded to
// 128 bytes, Reed-Solomon encoded as four 32-byte units.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	sigPlainSize        = ed25519.PublicKeySize + ed25519.SignatureSize
	sigSealedSize       = sigPlainSize + chacha20poly1305.Overhead
	sigBlockEncodedSize = 128 / 32 * 96
)

// Signer signs volumes with an Ed25519 key
type Signer struct {
	Key ed25519.PrivateKey
}

// TrustedSigner is a known sender
type TrustedSigner struct {
	Name string
	Key  ed25519.PublicKey
}

// SignatureStatus is what Decrypt found
type SignatureStatus struct {
	Signed bool
	// Valid: the signature matches this volume's contents
	Valid bool
	// Key is the signer's public key (when Signed and the block opened)
	Key ed25519.PublicKey
	// Name is the TrustedSigner's name, if the key is a trusted one
	Name string
}

// Fingerprint is a short, readable form of a signing key, for comparing
// over another channel (e.g. reading it out on a call)
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10])
	var groups []string
	for i := 0; i < len(s); i += 4 {
		groups = append(groups, s[i:min(i+4, len(s))])
	}
	return strings.Join(groups, "-")
}

type tagHasher struct{ h hash.Hash }

func newTagHasher() *tagHasher      { return &tagHasher{sha3.New256()} }
func (t *tagHasher) add(tag []byte) { t.h.Write(tag) }
func (t *tagHasher) sum() []byte    { return t.h.Sum(nil) }

func signedMessage(mac, tagsHash []byte) []byte {
	msg := []byte("zeecrypt v3 signature")
	msg = append(msg, mac...)
	return append(msg, tagsHash...)
}

func sigKey(k keys) []byte {
	key := make([]byte, 32)
	// derived from the header key so it's bound to the same file key
	if _, err := io.ReadFull(hkdf.New(sha3.New256, k.header, nil, []byte("zeecrypt v3 signature block")), key); err != nil {
		panic(err)
	}
	return key
}

func (s *Signer) sign(k keys, mac, tagsHash []byte, _ []Stanza) ([]byte, error) {
	sig := ed25519.Sign(s.Key, signedMessage(mac, tagsHash))
	plain := append(append([]byte{}, s.Key.Public().(ed25519.PublicKey)...), sig...)
	aead, err := chacha20poly1305.New(sigKey(k))
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), plain, []byte("signature"))
	padded := make([]byte, 128)
	copy(padded, sealed)
	var out []byte
	for i := 0; i < 128; i += 32 {
		out = append(out, rsEncode(rs32, padded[i:i+32])...)
	}
	return out, nil
}

func checkSignature(h *Header, k keys, tagsHash []byte, trusted []TrustedSigner) SignatureStatus {
	if !h.Flags.Signed {
		return SignatureStatus{}
	}
	st := SignatureStatus{Signed: true}
	var padded []byte
	for i := 0; i < len(h.sigBlock); i += 96 {
		d, _ := rsDecode(rs32, h.sigBlock[i:i+96])
		padded = append(padded, d...)
	}
	aead, err := chacha20poly1305.New(sigKey(k))
	if err != nil {
		return st
	}
	plain, err := aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), padded[:sigSealedSize], []byte("signature"))
	if err != nil || len(plain) != sigPlainSize {
		return st
	}
	pub := ed25519.PublicKey(plain[:ed25519.PublicKeySize])
	st.Key = pub
	st.Valid = ed25519.Verify(pub, signedMessage(h.MAC, tagsHash), plain[ed25519.PublicKeySize:])
	if st.Valid {
		for _, t := range trusted {
			if t.Key.Equal(pub) {
				st.Name = t.Name
				break
			}
		}
	}
	return st
}
