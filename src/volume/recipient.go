package volume

// Public-key recipient stanzas: hybrid X25519 + ML-KEM-768.
//
// X25519 alone would fall to a large quantum computer; ML-KEM-768 (FIPS 203)
// is designed to resist one, and X25519 keeps the stanza secure even if
// ML-KEM turns out to be weak. The wrap key needs both shared secrets.
//
// Stanza body (1168 bytes):
//
//	ephemeral X25519 public key (32) | ML-KEM-768 ciphertext (1088) | wrapped file key (32 + 16)
//
// wrap key = HKDF-SHA3-256(x25519 secret | ML-KEM secret,
//                          salt = SHA3-256(ephemeral key | ciphertext | recipient X25519 key | recipient ML-KEM key),
//                          info = "zeecrypt v3 recipient stanza")
//
// The salt binds the wrap to this recipient and this encapsulation. Stanzas
// carry no key ID: a recipient finds theirs by trying to open each one, so
// the header doesn't say who the recipients are.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const recipientBodySize = 32 + mlkem.CiphertextSize768 + 32 + 16

// HybridRecipient encrypts to someone's public key
type HybridRecipient struct {
	X25519 *ecdh.PublicKey
	MLKEM  *mlkem.EncapsulationKey768
}

// HybridIdentity is the matching private key
type HybridIdentity struct {
	X25519 *ecdh.PrivateKey
	MLKEM  *mlkem.DecapsulationKey768
}

func recipientWrapKey(xShared, kShared, ephemeral, ct []byte, x *ecdh.PublicKey, k *mlkem.EncapsulationKey768) []byte {
	t := sha3.New256()
	t.Write(ephemeral)
	t.Write(ct)
	t.Write(x.Bytes())
	t.Write(k.Bytes())
	ikm := append(append([]byte{}, xShared...), kShared...)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha3.New256, ikm, t.Sum(nil), []byte("zeecrypt v3 recipient stanza")), key); err != nil {
		panic(err)
	}
	return key
}

func (r HybridRecipient) Wrap(fileKey []byte, _ Flags) (Stanza, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Stanza{}, err
	}
	xShared, err := eph.ECDH(r.X25519)
	if err != nil {
		return Stanza{}, err // a low-order public key
	}
	kShared, ct := r.MLKEM.Encapsulate()
	ephPub := eph.PublicKey().Bytes()
	k := recipientWrapKey(xShared, kShared, ephPub, ct, r.X25519, r.MLKEM)
	body := append(append(append([]byte{}, ephPub...), ct...), seal(k, fileKey, StanzaRecipient)...)
	return Stanza{Type: StanzaRecipient, Body: body}, nil
}

func (id HybridIdentity) Unwrap(stanzas []Stanza, _ Flags) ([]byte, error) {
	xPub := id.X25519.PublicKey()
	kPub := id.MLKEM.EncapsulationKey()
	for _, s := range stanzas {
		if s.Type != StanzaRecipient || len(s.Body) != recipientBodySize {
			continue
		}
		ephPub := s.Body[:32]
		ct := s.Body[32 : 32+mlkem.CiphertextSize768]
		wrapped := s.Body[32+mlkem.CiphertextSize768:]
		eph, err := ecdh.X25519().NewPublicKey(ephPub)
		if err != nil {
			continue
		}
		xShared, err := id.X25519.ECDH(eph)
		if err != nil || bytes.Equal(xShared, make([]byte, 32)) {
			continue
		}
		// ML-KEM decapsulation never fails on a well-formed ciphertext; a
		// stanza for someone else just gives a different secret, and the
		// wrapped key then doesn't open
		kShared, err := id.MLKEM.Decapsulate(ct)
		if err != nil {
			continue
		}
		k := recipientWrapKey(xShared, kShared, ephPub, ct, xPub, kPub)
		if fk, ok := open(k, wrapped, StanzaRecipient); ok {
			return fk, nil
		}
	}
	return nil, ErrIncorrect
}
