// Package keys manages ZeeCrypt identities: key pairs for public-key
// recipients and sender signatures, and the list of trusted contacts.
//
// A public key ("zeecrypt1…") bundles everything others need: an X25519 and
// an ML-KEM-768 key to encrypt to you, and an Ed25519 key to check your
// signatures. The identity file holds the matching private keys and your
// contacts, encrypted with a password as a v3 volume, the way age protects
// passphrase-encrypted identities.
package keys

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ZeeCrypt/volume"
)

const (
	publicHRP = "zeecrypt"
	secretHRP = "ZEECRYPT-SECRET-KEY-"

	publicKeySize = 32 + ed25519.PublicKeySize + mlkem.EncapsulationKeySize768
	secretKeySize = 32 + ed25519.SeedSize + mlkem.SeedSize
)

// PublicKey is someone's ZeeCrypt public key
type PublicKey struct {
	X25519  *ecdh.PublicKey
	Ed25519 ed25519.PublicKey
	MLKEM   *mlkem.EncapsulationKey768
}

// String is the "zeecrypt1…" form to share
func (p PublicKey) String() string {
	b := append(append(append([]byte{}, p.X25519.Bytes()...), p.Ed25519...), p.MLKEM.Bytes()...)
	return encode(publicHRP, b)
}

// Fingerprint is a short form to compare over another channel. It's the
// same fingerprint shown for a volume's signer.
func (p PublicKey) Fingerprint() string { return volume.Fingerprint(p.Ed25519) }

// Recipient encrypts to this key
func (p PublicKey) Recipient() volume.Recipient {
	return volume.HybridRecipient{X25519: p.X25519, MLKEM: p.MLKEM}
}

// Equal compares two public keys
func (p PublicKey) Equal(o PublicKey) bool {
	return p.Ed25519.Equal(o.Ed25519) && p.X25519.Equal(o.X25519) && bytes.Equal(p.MLKEM.Bytes(), o.MLKEM.Bytes())
}

// ParsePublicKey reads a "zeecrypt1…" key. Surrounding spaces and line
// breaks (e.g. from wrapping in an email) are ignored.
func ParsePublicKey(s string) (PublicKey, error) {
	s = strings.Join(strings.Fields(s), "")
	hrp, b, err := decode(s)
	if err != nil {
		return PublicKey{}, err
	}
	if hrp != publicHRP || len(b) != publicKeySize {
		return PublicKey{}, errors.New("not a ZeeCrypt public key")
	}
	x, err := ecdh.X25519().NewPublicKey(b[:32])
	if err != nil {
		return PublicKey{}, err
	}
	k, err := mlkem.NewEncapsulationKey768(b[64:])
	if err != nil {
		return PublicKey{}, errors.New("not a ZeeCrypt public key")
	}
	return PublicKey{X25519: x, Ed25519: ed25519.PublicKey(b[32:64]), MLKEM: k}, nil
}

// Contact is a trusted person: their volumes' signatures show their name
type Contact struct {
	Name string
	Key  PublicKey
}

// Identity is your private keys and contacts
type Identity struct {
	x25519   *ecdh.PrivateKey
	ed25519  ed25519.PrivateKey
	mlkem    *mlkem.DecapsulationKey768
	Contacts []Contact
	Created  time.Time
}

// Generate creates a new identity
func Generate() (*Identity, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	k, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &Identity{x25519: x, ed25519: ed, mlkem: k, Created: time.Now().UTC().Truncate(time.Second)}, nil
}

// Public returns the identity's public key
func (id *Identity) Public() PublicKey {
	return PublicKey{X25519: id.x25519.PublicKey(), Ed25519: id.ed25519.Public().(ed25519.PublicKey), MLKEM: id.mlkem.EncapsulationKey()}
}

// Opener opens volumes encrypted to this identity
func (id *Identity) Opener() volume.Identity {
	return volume.HybridIdentity{X25519: id.x25519, MLKEM: id.mlkem}
}

// Signer signs volumes as this identity
func (id *Identity) Signer() *volume.Signer { return &volume.Signer{Key: id.ed25519} }

// TrustedSigners lists the identity's contacts, and the identity itself as
// "you", for checking signatures
func (id *Identity) TrustedSigners() []volume.TrustedSigner {
	ts := []volume.TrustedSigner{{Name: "you", Key: id.Public().Ed25519}}
	for _, c := range id.Contacts {
		ts = append(ts, volume.TrustedSigner{Name: c.Name, Key: c.Key.Ed25519})
	}
	return ts
}

// AddContact adds or renames a contact. Names are one line, at most 64 bytes.
func (id *Identity) AddContact(name string, key PublicKey) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\r\n") {
		return errors.New("enter a name of up to 64 characters")
	}
	if key.Equal(id.Public()) {
		return errors.New("that's your own key")
	}
	for i, c := range id.Contacts {
		if c.Key.Equal(key) {
			id.Contacts[i].Name = name
			return nil
		}
	}
	id.Contacts = append(id.Contacts, Contact{Name: name, Key: key})
	return nil
}

// RemoveContact removes the contact at index i
func (id *Identity) RemoveContact(i int) {
	if i >= 0 && i < len(id.Contacts) {
		id.Contacts = append(id.Contacts[:i], id.Contacts[i+1:]...)
	}
}

// ---------- Identity file ----------

// marshal is the identity file's plaintext:
//
//	# ZeeCrypt identity
//	# created: 2026-11-13T10:00:00Z
//	# public key: zeecrypt1…
//	ZEECRYPT-SECRET-KEY-1…
//	contact: <public key> <name>
func (id *Identity) marshal() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# ZeeCrypt identity\n# created: %s\n# public key: %s\n", id.Created.Format(time.RFC3339), id.Public())
	secret := append(append(append([]byte{}, id.x25519.Bytes()...), id.ed25519.Seed()...), id.mlkem.Bytes()...)
	fmt.Fprintf(&b, "%s\n", encode(secretHRP, secret))
	for _, c := range id.Contacts {
		fmt.Fprintf(&b, "contact: %s %s\n", c.Key, c.Name)
	}
	return b.Bytes()
}

func unmarshal(data []byte) (*Identity, error) {
	var id *Identity
	var created time.Time
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
		case strings.HasPrefix(line, "# created: "):
			created, _ = time.Parse(time.RFC3339, strings.TrimPrefix(line, "# created: "))
		case strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, secretHRP+"1"):
			hrp, b, err := decode(line)
			if err != nil || hrp != strings.ToLower(secretHRP) || len(b) != secretKeySize {
				return nil, errors.New("the identity file is damaged")
			}
			x, err := ecdh.X25519().NewPrivateKey(b[:32])
			if err != nil {
				return nil, err
			}
			k, err := mlkem.NewDecapsulationKey768(b[64:])
			if err != nil {
				return nil, err
			}
			id = &Identity{x25519: x, ed25519: ed25519.NewKeyFromSeed(b[32:64]), mlkem: k}
		case strings.HasPrefix(line, "contact: "):
			if id == nil {
				return nil, errors.New("the identity file is damaged")
			}
			rest := strings.TrimPrefix(line, "contact: ")
			keyStr, name, ok := strings.Cut(rest, " ")
			if !ok {
				return nil, errors.New("the identity file is damaged")
			}
			key, err := ParsePublicKey(keyStr)
			if err != nil {
				return nil, err
			}
			id.Contacts = append(id.Contacts, Contact{Name: name, Key: key})
		default:
			return nil, errors.New("the identity file is damaged")
		}
	}
	if id == nil {
		return nil, errors.New("not a ZeeCrypt identity file")
	}
	id.Created = created
	return id, nil
}

// Save writes the identity to 'path', encrypted with 'password' (paranoid
// mode, with Reed-Solomon so a few damaged bytes don't lose your key). The
// file is written to a temporary name and renamed, so a failed save never
// destroys an existing identity file.
func (id *Identity) Save(path string, password string) error {
	if password == "" {
		return errors.New("an identity needs a password")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".zeecrypt-identity-*")
	if err != nil {
		return err
	}
	err = volume.Encrypt(tmp, bytes.NewReader(id.marshal()),
		[]volume.Recipient{volume.Password{Password: []byte(password)}},
		volume.EncryptOptions{Comments: "ZeeCrypt identity", Flags: volume.Flags{Paranoid: true, ReedSolomon: true}})
	if errC := tmp.Close(); err == nil {
		err = errC
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// ErrWrongPassword means the identity file didn't open with that password
var ErrWrongPassword = errors.New("wrong password for this identity")

// Load opens an identity file
func Load(path string, password string) (*Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out bytes.Buffer
	_, err = volume.Decrypt(&limitedWriter{&out, 4 << 20}, f,
		[]volume.Identity{volume.Password{Password: []byte(password)}}, volume.DecryptOptions{})
	if errors.Is(err, volume.ErrIncorrect) {
		return nil, ErrWrongPassword
	}
	if errors.Is(err, volume.ErrNotV3) {
		return nil, errors.New("not a ZeeCrypt identity file")
	}
	if err != nil {
		return nil, err
	}
	return unmarshal(out.Bytes())
}

// limitedWriter stops a huge file posing as an identity from filling memory
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("not a ZeeCrypt identity file")
	}
	l.n -= len(p)
	return l.w.Write(p)
}
