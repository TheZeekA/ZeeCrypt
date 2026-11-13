package main

import (
	"os"
	"path/filepath"
	"testing"

	"ZeeCrypt/volume"
)

func TestNewVolumesAreV3(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 100))
	vol, st := encrypt(t, []string{in}, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	if !isV3Volume(vol) {
		t.Fatal("new volume isn't v3")
	}

	// The v2 writer still exists for tests, and its volumes still open
	os.Remove(vol)
	vol, st = encrypt(t, []string{in}, "pw", nil, func() { legacyFormat = true })
	mustStatus(t, st, "Completed")
	if isV3Volume(vol) {
		t.Fatal("legacyFormat wrote v3")
	}
	os.Remove(in)
	out, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	if out != in {
		t.Fatalf("output %q", out)
	}
}

func TestV3PreviewShowsCommentsAndKeyfileFlag(t *testing.T) {
	dir := t.TempDir()
	in, kf := filepath.Join(dir, "f.bin"), filepath.Join(dir, "k.key")
	writeFile(t, in, randBytes(t, 100))
	writeFile(t, kf, randBytes(t, 64))
	vol, st := encrypt(t, []string{in}, "pw", []string{kf}, func() { comments = "hello v3"; keyfileOrdered = true })
	mustStatus(t, st, "Completed")
	setup()
	onDrop([]string{vol})
	waitScan()
	if comments != "hello v3" || !keyfile || !keyfileOrdered || mode != "decrypt" {
		t.Fatalf("preview: comments=%q keyfile=%v ordered=%v mode=%q", comments, keyfile, keyfileOrdered, mode)
	}
}

func TestV3WrongCredentials(t *testing.T) {
	dir := t.TempDir()
	in, kf := filepath.Join(dir, "f.bin"), filepath.Join(dir, "k.key")
	writeFile(t, in, randBytes(t, 100))
	writeFile(t, kf, randBytes(t, 64))
	vol, _ := encrypt(t, []string{in}, "pw", nil, nil)
	_, st := decrypt(t, vol, "nope", nil, nil)
	mustStatus(t, st, "password is incorrect")
	os.Remove(vol)

	vol, _ = encrypt(t, []string{in}, "pw", []string{kf}, nil)
	_, st = decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "requires keyfiles")
	other := filepath.Join(dir, "other.key")
	writeFile(t, other, randBytes(t, 64))
	_, st = decrypt(t, vol, "pw", []string{other}, nil)
	mustStatus(t, st, "password or keyfiles are incorrect")
	os.Remove(in)
	mustOnly(t, dir, "f.bin.pcv", "k.key", "other.key")
}

// Every chunk is checked before it's written: a damaged second chunk leaves
// no output at all (the verified first chunk only ever reached .incomplete)
func TestV3DamagedDataLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 3*volume.ChunkSize))
	vol, st := encrypt(t, []string{in}, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	os.Remove(in)
	fi, _ := os.Stat(vol)
	flipByte(t, vol, fi.Size()-volume.MiB-100)
	_, st = decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "damaged or modified")
	mustOnly(t, dir, "f.bin.pcv")

	// Force decrypt still gets everything out, with a warning
	_, st = decrypt(t, vol, "pw", nil, func() { keep = true })
	mustStatus(t, st, "modified")
	mustOnly(t, dir, "f.bin.pcv", "f.bin")
}

func TestV3AppendedTailRejected(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 5000))
	vol, _ := encrypt(t, []string{in}, "pw", nil, func() { reedsolo = true })
	os.Remove(in)
	f, _ := os.OpenFile(vol, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte("0123456789"))
	f.Close()
	_, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "damaged or modified")
	mustOnly(t, dir, "f.bin.pcv")
}

func TestV3HeaderFieldsChecked(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "m.bin")
	writeFile(t, in, randBytes(t, 1000))
	vol, st := encrypt(t, []string{in}, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	orig, _ := os.ReadFile(vol)
	for _, bad := range []string{"-0001", "12a45", "99999"} {
		b := append([]byte(nil), orig...)
		copy(b[15:30], rsEncode(rs5, []byte(bad)))
		writeFile(t, vol, b)
		_, st := decrypt(t, vol, "pw", nil, nil)
		if st == "" || st == "Completed" {
			t.Fatalf("%q: status %q", bad, st)
		}
		mustOnly(t, dir, "m.bin", "m.bin.pcv")
	}
}

// Keyfile-only volumes: anyone can compute Argon2 of the empty password,
// but the header MAC needs the file key, which needs the keyfiles
func TestV3KeyfileOnlyHeaderTamperRejected(t *testing.T) {
	dir := t.TempDir()
	in, kf := filepath.Join(dir, "s.bin"), filepath.Join(dir, "k.key")
	writeFile(t, in, randBytes(t, 5000))
	writeFile(t, kf, randBytes(t, 64))
	vol, st := encrypt(t, []string{in}, "", []string{kf}, nil)
	mustStatus(t, st, "Completed")
	os.Remove(in)

	b, _ := os.ReadFile(vol)
	// The hkdf salt is the first 32 bytes of the header block, which starts
	// after version, comments length, flags and block length (4 x 15 bytes)
	salt, err := rsDecode(rs32, b[60:156])
	if err != nil {
		t.Fatal(err)
	}
	salt[0] ^= 1
	copy(b[60:156], rsEncode(rs32, salt))
	writeFile(t, vol, b)
	_, st = decrypt(t, vol, "", []string{kf}, nil)
	mustStatus(t, st, "header has been modified")
	mustOnly(t, dir, "s.bin.pcv", "k.key")
}

func TestV3RepairSplit(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 50000)
	writeFile(t, in, data)
	vol, st := encrypt(t, []string{in}, "pw", nil, func() { reedsolo = true; split = true; splitSize = "16"; splitSelected = 0 })
	mustStatus(t, st, "Completed")
	os.Remove(in)
	flipByte(t, vol+".0", 20)   // header
	flipByte(t, vol+".1", 5000) // data
	flipByte(t, vol+".2", 3)
	out, st := decrypt(t, vol+".1", "pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
}

func TestV3DeniableRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 70000)
	writeFile(t, in, data)
	vol, st := encrypt(t, []string{in}, "pw", nil, func() { deniability = true; paranoid = true })
	mustStatus(t, st, "Completed")
	os.Remove(in)
	out, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
}
