package volume

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
)

// fakeKey behaves like a FIDO2 key with hmac-secret: a per-credential
// secret, HMAC'd with the salt
type fakeKey struct {
	creds   map[string][]byte
	touches int
}

func newFakeKey() *fakeKey { return &fakeKey{creds: map[string][]byte{}} }

func (k *fakeKey) Register() ([]byte, error) {
	k.touches++
	id := randBytes(64)
	k.creds[string(id)] = randBytes(32)
	return id, nil
}

func (k *fakeKey) Secret(ids [][]byte, salt []byte) ([]byte, []byte, error) {
	k.touches++
	for _, id := range ids {
		if cr, ok := k.creds[string(id)]; ok {
			m := hmac.New(sha256.New, cr)
			m.Write(salt)
			return id, m.Sum(nil), nil
		}
	}
	return nil, nil, ErrNoMatchingKey
}

func TestFIDO2(t *testing.T) {
	if testing.Short() {
		t.Skip("Argon2 with 1 GiB")
	}
	key := newFakeKey()
	pw := FIDO2Password{Password: []byte("pw"), Device: key}
	data := randData(3000)
	vol := encrypt(t, data, []Recipient{pw}, EncryptOptions{})
	if key.touches != 2 {
		t.Fatalf("encrypting took %d touches, want 2 (register + secret)", key.touches)
	}

	got, _, err := decrypt(vol, []Identity{pw}, DecryptOptions{})
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("decrypt: %v", err)
	}

	// The password alone (as a plain password stanza) opens nothing
	if _, _, err := decrypt(vol, []Identity{Password{Password: []byte("pw")}}, DecryptOptions{}); !errors.Is(err, ErrIncorrect) {
		t.Fatalf("password only: %v", err)
	}
	// Right key, wrong password
	if _, _, err := decrypt(vol, []Identity{FIDO2Password{Password: []byte("nope"), Device: key}}, DecryptOptions{}); !errors.Is(err, ErrIncorrect) {
		t.Fatalf("wrong password: %v", err)
	}
	// Right password, another security key
	if _, _, err := decrypt(vol, []Identity{FIDO2Password{Password: []byte("pw"), Device: newFakeKey()}}, DecryptOptions{}); !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("other key: %v", err)
	}
}

func TestFIDO2StanzaParsing(t *testing.T) {
	good := append(append(make([]byte, 48), 0, 3), append([]byte{1, 2, 3}, make([]byte, 48)...)...)
	if f, ok := parseFIDO2(good); !ok || !bytes.Equal(f.credID, []byte{1, 2, 3}) {
		t.Fatal("valid stanza rejected")
	}
	for _, bad := range [][]byte{nil, good[:60], append(good, 0), append(append(make([]byte, 48), 0, 0), make([]byte, 48)...)} {
		if _, ok := parseFIDO2(bad); ok {
			t.Errorf("malformed stanza (%d bytes) accepted", len(bad))
		}
	}
	if !FIDO2Stanzas([]Stanza{{Type: StanzaPassword}, {Type: StanzaFIDO2}}) || FIDO2Stanzas([]Stanza{{Type: StanzaPassword}}) {
		t.Fatal("FIDO2Stanzas")
	}
}
