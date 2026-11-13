package main

import (
	"os"
	"path/filepath"
	"testing"

	"ZeeCrypt/keys"
	"ZeeCrypt/volume"
)

func withIdentity(t *testing.T) *keys.Identity {
	t.Helper()
	id, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	useIdentity(id, "", "")
	t.Cleanup(func() {
		closeIdentity()
		extraRecipients = nil
	})
	return id
}

func TestEncryptToPublicKeyOnly(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 200000)
	writeFile(t, in, data)
	me := withIdentity(t)

	// No password: only the identity opens it
	vol, st := encrypt(t, []string{in}, "", nil, nil)
	mustStatus(t, st, "Completed")
	os.Remove(in)

	setup()
	onDrop([]string{vol})
	waitScan()
	if !volumeHasRecipients || volumeHasPassword || !hasCredentials() {
		t.Fatalf("preview: recipients=%v password=%v creds=%v", volumeHasRecipients, volumeHasPassword, hasCredentials())
	}
	out, st := decrypt(t, vol, "", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
	os.Remove(out)

	// Without the identity
	closeIdentity()
	_, st = decrypt(t, vol, "", nil, nil)
	mustStatus(t, st, "open your identity first")

	// With someone else's identity
	withIdentity(t)
	_, st = decrypt(t, vol, "", nil, nil)
	mustStatus(t, st, "can't open this volume")
	mustOnly(t, dir, "f.bin.pcv")

	useIdentity(me, "", "")
	out, st = decrypt(t, vol, "", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
}

func TestPasswordAndRecipients(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 5000)
	writeFile(t, in, data)
	withIdentity(t)
	friend, _ := keys.Generate()
	if err := identity.AddContact("Friend", friend.Public()); err != nil {
		t.Fatal(err)
	}
	contactSelected = []bool{true}

	vol, st := encrypt(t, []string{in}, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	os.Remove(in)

	// The password still works on its own
	closeIdentity()
	out, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
	os.Remove(out)

	// So does the friend's identity, without the password
	useIdentity(friend, "", "")
	out, st = decrypt(t, vol, "", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
}

func TestSignedVolumeStatus(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 5000)
	writeFile(t, in, data)

	alice := withIdentity(t)
	signVolumes = true
	bob, _ := keys.Generate()
	identity.AddContact("Bob", bob.Public())
	contactSelected = []bool{true}
	vol, st := encrypt(t, []string{in}, "", nil, nil)
	mustStatus(t, st, "Completed")
	os.Remove(in)

	// Bob, who doesn't know Alice yet
	useIdentity(bob, "", "")
	out, st := decrypt(t, vol, "", nil, nil)
	mustStatus(t, st, "signed by unknown "+alice.Public().Fingerprint())
	if mainStatusColor != YELLOW {
		t.Fatal("unknown signer not shown as a warning")
	}
	mustContent(t, out, data)
	os.Remove(out)

	// After adding Alice as a contact
	bob.AddContact("Alice", alice.Public())
	_, st = decrypt(t, vol, "", nil, nil)
	mustStatus(t, st, "signed by Alice")
	if mainStatusColor != GREEN {
		t.Fatal("trusted signer not shown as success")
	}
}

func TestDeniabilityRefusesPublicKeys(t *testing.T) {
	setup()
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, []byte("x"))
	withIdentity(t)
	onDrop([]string{in})
	waitScan()
	password, cpassword, deniability = "pw", "pw", true
	onClickStartButton()
	mustStatus(t, mainStatus, "can't be combined with public keys")
	if showProgress || working {
		t.Fatal("started anyway")
	}
}

func TestSignatureStatusMessages(t *testing.T) {
	alice, _ := keys.Generate()
	pub := alice.Public().Ed25519
	for _, c := range []struct {
		s    volume.SignatureStatus
		want string
		col  string
	}{
		{volume.SignatureStatus{}, "Completed", "green"},
		{volume.SignatureStatus{Signed: true}, "signature is invalid", "yellow"},
		{volume.SignatureStatus{Signed: true, Valid: true, Key: pub, Name: "you"}, "signed by you", "green"},
		{volume.SignatureStatus{Signed: true, Valid: true, Key: pub}, "unknown " + alice.Public().Fingerprint(), "yellow"},
	} {
		msg, col := signatureStatus(c.s)
		mustStatus(t, msg, c.want)
		if (c.col == "green") != (col == GREEN) {
			t.Errorf("%q: wrong colour", msg)
		}
	}
}

func TestPublicKeysLabel(t *testing.T) {
	setup()
	mode = "encrypt"
	if publicKeysLabel() != "None" {
		t.Fatal(publicKeysLabel())
	}
	withIdentity(t)
	mode = "encrypt"
	if publicKeysLabel() != "To you" {
		t.Fatal(publicKeysLabel())
	}
	signVolumes = true
	if publicKeysLabel() != "To you, signed" {
		t.Fatal(publicKeysLabel())
	}
	mode = "decrypt"
	volumeHasRecipients = true
	if publicKeysLabel() != "Using your identity" {
		t.Fatal(publicKeysLabel())
	}
}
