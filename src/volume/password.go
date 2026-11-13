package volume

import (
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Password opens or creates a password stanza: the file key wrapped under
// Argon2id(password), combined with the keyfile key if keyfiles are used.
// Argon2id parameters are the same as v1.5x/v2: 4 passes / 1 GiB / 4
// threads, or 8 / 1 GiB / 8 in paranoid mode.
//
// Stanza body: Argon2 salt (16) | wrapped file key (32 + 16-byte tag)
type Password struct {
	Password   []byte
	KeyfileKey []byte // 32 bytes, or nil without keyfiles
	// Extra is mixed into the wrap key; the FIDO2 stanza uses it for the
	// hardware key's secret
	Extra []byte
}

const passwordBodySize = 16 + 32 + chacha20poly1305.Overhead

func (p Password) wrapKey(salt []byte, paranoid bool, info string) []byte {
	var a []byte
	if paranoid {
		a = argon2.IDKey(p.Password, salt, 8, 1<<20, 8, 32)
	} else {
		a = argon2.IDKey(p.Password, salt, 4, 1<<20, 4, 32)
	}
	kf := p.KeyfileKey
	if kf == nil {
		kf = make([]byte, 32)
	}
	ikm := append(append(append([]byte{}, a...), kf...), p.Extra...)
	k := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha3.New256, ikm, salt, []byte(info)), k); err != nil {
		panic(err)
	}
	return k
}

// seal and open wrap a file key under a single-use key, so a fixed nonce is
// safe; the stanza type is authenticated as associated data
func seal(key, fileKey []byte, stanzaType byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), fileKey, []byte{stanzaType})
}

func open(key, wrapped []byte, stanzaType byte) ([]byte, bool) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	fk, err := aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), wrapped, []byte{stanzaType})
	return fk, err == nil && len(fk) == 32
}

func (p Password) Wrap(fileKey []byte, flags Flags) (Stanza, error) {
	salt := randBytes(16)
	k := p.wrapKey(salt, flags.Paranoid, "zeecrypt v3 password stanza")
	return Stanza{Type: StanzaPassword, Body: append(salt, seal(k, fileKey, StanzaPassword)...)}, nil
}

func (p Password) Unwrap(stanzas []Stanza, flags Flags) ([]byte, error) {
	for _, s := range stanzas {
		if s.Type != StanzaPassword || len(s.Body) != passwordBodySize {
			continue
		}
		k := p.wrapKey(s.Body[:16], flags.Paranoid, "zeecrypt v3 password stanza")
		if fk, ok := open(k, s.Body[16:], StanzaPassword); ok {
			return fk, nil
		}
	}
	return nil, ErrIncorrect
}
