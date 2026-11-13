package keys

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ZeeCrypt/volume"
)

func TestBech32RoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 32, 100, 1248} {
		data := make([]byte, n)
		rand.Read(data)
		for _, hrp := range []string{"zeecrypt", "ZEECRYPT-SECRET-KEY-"} {
			s := encode(hrp, data)
			h, got, err := decode(s)
			if err != nil || h != strings.ToLower(hrp) || !bytes.Equal(got, data) {
				t.Fatalf("n=%d hrp=%s: %v", n, hrp, err)
			}
		}
	}
	// BIP 173 test vector
	if _, _, err := decode("A12UEL5L"); err != nil {
		t.Errorf("BIP 173 vector: %v", err)
	}
}

func TestPublicKeyEncoding(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	s := id.Public().String()
	if !strings.HasPrefix(s, "zeecrypt1") {
		t.Fatalf("public key %q", s[:20])
	}
	p, err := ParsePublicKey(s)
	if err != nil || !p.Equal(id.Public()) {
		t.Fatalf("parse: %v", err)
	}
	// Uppercase, and wrapped across lines in an email
	wrapped := strings.ToUpper(s[:60]) + "\n  " + strings.ToUpper(s[60:])
	if p, err := ParsePublicKey(wrapped); err != nil || !p.Equal(id.Public()) {
		t.Fatalf("wrapped: %v", err)
	}
	// A typo is caught by the checksum
	typo := []byte(s)
	if typo[100] == 'q' {
		typo[100] = 'p'
	} else {
		typo[100] = 'q'
	}
	if _, err := ParsePublicKey(string(typo)); err == nil {
		t.Fatal("typo accepted")
	}
	if _, err := ParsePublicKey(encode("zeecrypt", []byte("short"))); err == nil {
		t.Fatal("short key accepted")
	}
	if len(id.Public().Fingerprint()) != 19 {
		t.Fatal("fingerprint")
	}
}

func TestEncryptToRecipients(t *testing.T) {
	alice, _ := Generate()
	bob, _ := Generate()
	eve, _ := Generate()
	data := make([]byte, 50000)
	rand.Read(data)

	var vol bytes.Buffer
	err := volume.Encrypt(&vol, bytes.NewReader(data),
		[]volume.Recipient{alice.Public().Recipient(), bob.Public().Recipient()}, volume.EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]*Identity{"alice": alice, "bob": bob} {
		var out bytes.Buffer
		if _, err := volume.Decrypt(&out, bytes.NewReader(vol.Bytes()), []volume.Identity{id.Opener()}, volume.DecryptOptions{}); err != nil || !bytes.Equal(out.Bytes(), data) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	var out bytes.Buffer
	if _, err := volume.Decrypt(&out, bytes.NewReader(vol.Bytes()), []volume.Identity{eve.Opener()}, volume.DecryptOptions{}); !errors.Is(err, volume.ErrIncorrect) {
		t.Fatalf("eve: %v", err)
	}
	if out.Len() != 0 {
		t.Fatal("eve got output")
	}
}

// A recipient stanza whose ciphertext or ephemeral key was changed doesn't open
func TestRecipientStanzaTampering(t *testing.T) {
	bob, _ := Generate()
	fileKey := make([]byte, 32)
	rand.Read(fileKey)
	s, err := bob.Public().Recipient().Wrap(fileKey, volume.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	if fk, err := bob.Opener().Unwrap([]volume.Stanza{s}, volume.Flags{}); err != nil || !bytes.Equal(fk, fileKey) {
		t.Fatal("untampered stanza didn't open")
	}
	for _, off := range []int{0, 31, 32, 500, 1119, 1120, len(s.Body) - 1} {
		body := append([]byte{}, s.Body...)
		body[off] ^= 1
		if _, err := bob.Opener().Unwrap([]volume.Stanza{{Type: s.Type, Body: body}}, volume.Flags{}); err == nil {
			t.Errorf("tampered byte %d accepted", off)
		}
	}
	// A low-order ephemeral key is refused, not used
	body := append([]byte{}, s.Body...)
	copy(body, make([]byte, 32))
	if _, err := bob.Opener().Unwrap([]volume.Stanza{{Type: s.Type, Body: body}}, volume.Flags{}); err == nil {
		t.Error("all-zero ephemeral key accepted")
	}
}

func TestContacts(t *testing.T) {
	me, _ := Generate()
	alice, _ := Generate()
	if err := me.AddContact("Alice", alice.Public()); err != nil {
		t.Fatal(err)
	}
	if err := me.AddContact("Alice B.", alice.Public()); err != nil || len(me.Contacts) != 1 || me.Contacts[0].Name != "Alice B." {
		t.Fatalf("rename: %v %+v", err, me.Contacts)
	}
	for _, bad := range []string{"", "  ", "a\nb", strings.Repeat("x", 65)} {
		if me.AddContact(bad, alice.Public()) == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	if me.AddContact("me", me.Public()) == nil {
		t.Error("own key accepted as a contact")
	}
	ts := me.TrustedSigners()
	if len(ts) != 2 || ts[0].Name != "you" || ts[1].Name != "Alice B." {
		t.Fatalf("trusted signers %+v", ts)
	}
	me.RemoveContact(0)
	if len(me.Contacts) != 0 {
		t.Fatal("remove")
	}
}

func TestIdentityFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Argon2 with 1 GiB")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "me.zeecrypt-identity")
	me, _ := Generate()
	alice, _ := Generate()
	me.AddContact("Alice Smith", alice.Public())
	if err := me.Save(path, ""); err == nil {
		t.Fatal("saved without a password")
	}
	if err := me.Save(path, "secret"); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("ZEECRYPT-SECRET")) || bytes.Contains(raw, []byte("Alice")) {
		t.Fatal("identity file isn't encrypted")
	}

	if _, err := Load(path, "wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	got, err := Load(path, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Public().Equal(me.Public()) || len(got.Contacts) != 1 || got.Contacts[0].Name != "Alice Smith" ||
		!got.Contacts[0].Key.Equal(alice.Public()) || !got.Created.Equal(me.Created) {
		t.Fatalf("loaded identity differs: %+v", got)
	}

	// A volume encrypted to the saved identity opens with the loaded one
	var vol, out bytes.Buffer
	volume.Encrypt(&vol, strings.NewReader("hi"), []volume.Recipient{me.Public().Recipient()}, volume.EncryptOptions{})
	if _, err := volume.Decrypt(&out, &vol, []volume.Identity{got.Opener()}, volume.DecryptOptions{}); err != nil || out.String() != "hi" {
		t.Fatal(err)
	}
}

func TestUnmarshalRejectsJunk(t *testing.T) {
	for _, s := range []string{"", "hello\n", "contact: zeecrypt1abc name\n", "ZEECRYPT-SECRET-KEY-1QQQQQQ\n"} {
		if _, err := unmarshal([]byte(s)); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	me, _ := Generate()
	if got, err := unmarshal(me.marshal()); err != nil || !got.Public().Equal(me.Public()) {
		t.Fatalf("own output: %v", err)
	}
}
