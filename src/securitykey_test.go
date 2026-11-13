package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"ZeeCrypt/volume"
)

// fakeSecurityKey stands in for a FIDO2 key with hmac-secret
type fakeSecurityKey struct {
	creds     map[string][]byte
	cancelled bool
}

func (k *fakeSecurityKey) Register() ([]byte, error) {
	if k.cancelled {
		return nil, errors.New("cancelled at the security key prompt")
	}
	id := []byte{byte(len(k.creds)), 1, 2, 3}
	k.creds[string(id)] = []byte("credential secret " + string(id))
	return id, nil
}

func (k *fakeSecurityKey) Secret(ids [][]byte, salt []byte) ([]byte, []byte, error) {
	if k.cancelled {
		return nil, nil, errors.New("cancelled at the security key prompt")
	}
	for _, id := range ids {
		if cr, ok := k.creds[string(id)]; ok {
			m := hmac.New(sha256.New, cr)
			m.Write(salt)
			return id, m.Sum(nil), nil
		}
	}
	return nil, nil, volume.ErrNoMatchingKey
}

func useFakeSecurityKey(t *testing.T) *fakeSecurityKey {
	k := &fakeSecurityKey{creds: map[string][]byte{}}
	testSecurityKey = k
	t.Cleanup(func() { testSecurityKey = nil; useSecurityKey = false })
	return k
}

func TestSecurityKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 5000)
	writeFile(t, in, data)
	key := useFakeSecurityKey(t)

	vol, st := encrypt(t, []string{in}, "pw", nil, func() { useSecurityKey = true })
	mustStatus(t, st, "Completed")
	useSecurityKey = false
	os.Remove(in)

	setup()
	onDrop([]string{vol})
	waitScan()
	if !volumeHasFIDO2 || publicKeysLabel() != "Password + security key" {
		t.Fatalf("preview: fido2=%v label=%q", volumeHasFIDO2, publicKeysLabel())
	}

	out, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
	os.Remove(out)

	_, st = decrypt(t, vol, "wrong", nil, nil)
	mustStatus(t, st, "incorrect")

	key.cancelled = true
	_, st = decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Cancelled at the security key prompt")
	key.cancelled = false

	useFakeSecurityKey(t) // a different key
	_, st = decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "This security key can't open the volume")
	mustOnly(t, dir, "f.bin.pcv")
}

func TestSecurityKeyNeedsPassword(t *testing.T) {
	setup()
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, []byte("x"))
	withIdentity(t)
	useFakeSecurityKey(t)
	onDrop([]string{in})
	waitScan()
	useSecurityKey = true // encrypting to yourself, but no password
	onClickStartButton()
	mustStatus(t, mainStatus, "used together with a password")
	if showProgress || working {
		t.Fatal("started anyway")
	}
}

// A security key can be combined with deniability: the deniability layer
// uses the password, which the user has
func TestSecurityKeyWithDeniability(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 3000)
	writeFile(t, in, data)
	useFakeSecurityKey(t)
	vol, st := encrypt(t, []string{in}, "pw", nil, func() { useSecurityKey = true; deniability = true })
	mustStatus(t, st, "Completed")
	useSecurityKey = false
	os.Remove(in)
	out, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
}
