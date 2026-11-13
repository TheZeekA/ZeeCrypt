package volume

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// rawKey is a cheap Recipient/Identity for tests (no Argon2)
type rawKey struct{ k []byte }

const stanzaTest byte = 200

func (r rawKey) Wrap(fileKey []byte, _ Flags) (Stanza, error) {
	return Stanza{Type: stanzaTest, Body: seal(r.k, fileKey, stanzaTest)}, nil
}

func (r rawKey) Unwrap(stanzas []Stanza, _ Flags) ([]byte, error) {
	for _, s := range stanzas {
		if s.Type == stanzaTest {
			if fk, ok := open(r.k, s.Body, stanzaTest); ok {
				return fk, nil
			}
		}
	}
	return nil, ErrIncorrect
}

func newRawKey() rawKey { return rawKey{randBytes(32)} }

// seekBuffer is an in-memory io.WriteSeeker
type seekBuffer struct {
	b   []byte
	pos int
}

func (s *seekBuffer) Write(p []byte) (int, error) {
	if end := s.pos + len(p); end > len(s.b) {
		s.b = append(s.b, make([]byte, end-len(s.b))...)
	}
	copy(s.b[s.pos:], p)
	s.pos += len(p)
	return len(p), nil
}

func (s *seekBuffer) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		s.pos = int(off)
	case io.SeekCurrent:
		s.pos += int(off)
	case io.SeekEnd:
		s.pos = len(s.b) + int(off)
	}
	return int64(s.pos), nil
}

func encrypt(t *testing.T, data []byte, recips []Recipient, opts EncryptOptions) []byte {
	t.Helper()
	var out seekBuffer
	if err := Encrypt(&out, bytes.NewReader(data), recips, opts); err != nil {
		t.Fatal(err)
	}
	return out.b
}

func decrypt(vol []byte, ids []Identity, opts DecryptOptions) ([]byte, Result, error) {
	var out bytes.Buffer
	res, err := Decrypt(&out, bytes.NewReader(vol), ids, opts)
	return out.Bytes(), res, err
}

func randData(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestRoundTrips(t *testing.T) {
	sizes := []int{0, 1, 127, ChunkSizeRS, ChunkSizeRS + 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 2 * ChunkSize, 2*ChunkSize + 77}
	for _, flags := range []Flags{{}, {Paranoid: true}, {ReedSolomon: true}, {Paranoid: true, ReedSolomon: true}} {
		for _, n := range sizes {
			key := newRawKey()
			data := randData(n)
			vol := encrypt(t, data, []Recipient{key}, EncryptOptions{Comments: "hi", Flags: flags})
			got, res, err := decrypt(vol, []Identity{key}, DecryptOptions{})
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("flags %+v size %d: err=%v equal=%v", flags, n, err, bytes.Equal(got, data))
			}
			if res.Header.Comments != "hi" || res.Header.Flags != flags || res.Damaged || res.Repaired {
				t.Fatalf("flags %+v size %d: result %+v", flags, n, res)
			}
		}
	}
}

// Every chunk boundary case the Reed-Solomon padding has to get right: the
// last chunk's ciphertext+tag lands on, just under and just over 128 bytes
func TestReedSolomonPaddingEdges(t *testing.T) {
	key := newRawKey()
	for _, n := range []int{ChunkSizeRS, ChunkSizeRS - 1, ChunkSizeRS + 1, ChunkSize, 2 * ChunkSizeRS, 96, 95, 97} {
		data := randData(n)
		vol := encrypt(t, data, []Recipient{key}, EncryptOptions{Flags: Flags{ReedSolomon: true}})
		if got, _, err := decrypt(vol, []Identity{key}, DecryptOptions{}); err != nil || !bytes.Equal(got, data) {
			t.Fatalf("size %d: %v", n, err)
		}
	}
}

func TestMultipleRecipients(t *testing.T) {
	a, b, c := newRawKey(), newRawKey(), newRawKey()
	data := randData(5000)
	vol := encrypt(t, data, []Recipient{a, b}, EncryptOptions{})
	for _, id := range []rawKey{a, b} {
		if got, _, err := decrypt(vol, []Identity{id}, DecryptOptions{}); err != nil || !bytes.Equal(got, data) {
			t.Fatalf("recipient couldn't open: %v", err)
		}
	}
	if _, _, err := decrypt(vol, []Identity{c}, DecryptOptions{}); !errors.Is(err, ErrIncorrect) {
		t.Fatalf("stranger: %v", err)
	}
	// An identity that fails is skipped in favour of one that works
	if _, _, err := decrypt(vol, []Identity{c, b}, DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestHeaderTamperingDetected(t *testing.T) {
	key := newRawKey()
	data := randData(3000)
	vol := encrypt(t, data, []Recipient{key}, EncryptOptions{Comments: "abc"})
	h, err := ReadHeader(bytes.NewReader(vol), false)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite fields with valid Reed-Solomon, so only the MAC can notice
	rewrite := func(off int, field []byte) []byte {
		v := append([]byte{}, vol...)
		copy(v[off:], field)
		return v
	}
	commentOff := 30
	flagsOff := 30 + 9
	blockOff := flagsOff + 15 + 15
	for name, v := range map[string][]byte{
		"comment": rewrite(commentOff, rsEncode(rs1, []byte{'x'})),
		"flags":   rewrite(flagsOff, rsEncode(rs5, Flags{Paranoid: true}.bytes()[:5])),
		"hkdf salt": func() []byte {
			unit := append([]byte{}, h.HKDFSalt...)
			unit[0] ^= 1
			return rewrite(blockOff, rsEncode(rs32, unit))
		}(),
	} {
		if name == "flags" {
			// paranoid changes the cipher; the MAC still has to catch it first
		}
		_, _, err := decrypt(v, []Identity{key}, DecryptOptions{})
		if !errors.Is(err, ErrHeaderModified) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDataTamperingDetectedBeforeOutput(t *testing.T) {
	key := newRawKey()
	data := randData(3 * ChunkSize)
	vol := encrypt(t, data, []Recipient{key}, EncryptOptions{})
	h, _ := ReadHeader(bytes.NewReader(vol), false)

	// Flip a byte in the second chunk: the first chunk is output, nothing after
	v := append([]byte{}, vol...)
	v[h.Size+MiB+10] ^= 1
	got, _, err := decrypt(v, []Identity{key}, DecryptOptions{})
	if !errors.Is(err, ErrDamaged) {
		t.Fatalf("err = %v", err)
	}
	if !bytes.Equal(got, data[:ChunkSize]) {
		t.Fatalf("output %d bytes, want only the verified first chunk", len(got))
	}

	// Force keeps going and flags it
	got, res, err := decrypt(v, []Identity{key}, DecryptOptions{Force: true})
	if err != nil || !res.Damaged || len(got) != len(data) {
		t.Fatalf("force: err=%v damaged=%v len=%d", err, res.Damaged, len(got))
	}
}

func TestTruncationAndReordering(t *testing.T) {
	key := newRawKey()
	data := randData(3 * ChunkSize)
	vol := encrypt(t, data, []Recipient{key}, EncryptOptions{})
	h, _ := ReadHeader(bytes.NewReader(vol), false)
	start := int(h.Size)

	cases := map[string][]byte{
		"cut at chunk boundary": vol[:start+2*MiB],
		"cut mid chunk":         vol[:start+MiB+500],
		"header only":           vol[:start],
		"appended byte":         append(append([]byte{}, vol...), 0),
		"swapped chunks": func() []byte {
			v := append([]byte{}, vol...)
			copy(v[start:], vol[start+MiB:start+2*MiB])
			copy(v[start+MiB:], vol[start:start+MiB])
			return v
		}(),
	}
	for name, v := range cases {
		if _, _, err := decrypt(v, []Identity{key}, DecryptOptions{}); !errors.Is(err, ErrDamaged) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReedSolomonRepairsData(t *testing.T) {
	key := newRawKey()
	data := randData(2*ChunkSize + 1000)
	vol := encrypt(t, data, []Recipient{key}, EncryptOptions{Flags: Flags{ReedSolomon: true}})
	h, _ := ReadHeader(bytes.NewReader(vol), false)
	v := append([]byte{}, vol...)
	// a few damaged bytes in each chunk, including the padded last one
	for _, off := range []int{5, 1000, MiB / 128 * 136 * 2, len(vol) - 3 - int(h.Size)} {
		v[int(h.Size)+off] ^= 0xff
	}
	// and in the header
	v[3] ^= 0xff
	v[int(h.Size)-50] ^= 0xff
	got, res, err := decrypt(v, []Identity{key}, DecryptOptions{})
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("err=%v equal=%v", err, bytes.Equal(got, data))
	}
	if !res.Repaired {
		t.Fatal("repair not reported")
	}
}

func TestWithoutReedSolomonDamageIsDetected(t *testing.T) {
	key := newRawKey()
	vol := encrypt(t, randData(1000), []Recipient{key}, EncryptOptions{})
	v := append([]byte{}, vol...)
	v[len(v)-1] ^= 1 // in the tag
	if _, _, err := decrypt(v, []Identity{key}, DecryptOptions{}); !errors.Is(err, ErrDamaged) {
		t.Fatal(err)
	}
}

func TestReadHeaderErrors(t *testing.T) {
	key := newRawKey()
	vol := encrypt(t, nil, []Recipient{key}, EncryptOptions{})
	if _, err := ReadHeader(bytes.NewReader(vol[:20]), false); !errors.Is(err, ErrTooShort) {
		t.Errorf("short: %v", err)
	}
	legacy := rsEncode(rs5, []byte("v1.52"))
	if _, err := ReadHeader(bytes.NewReader(legacy), false); !errors.Is(err, ErrNotV3) {
		t.Errorf("legacy: %v", err)
	}
	if !IsV3(vol) || IsV3(legacy) || IsV3(nil) {
		t.Error("IsV3")
	}
	future := append(rsEncode(rs5, []byte("v3.01")), vol[15:]...)
	if _, err := ReadHeader(bytes.NewReader(future), false); err == nil {
		t.Error("future version accepted")
	}
}

func TestSignatures(t *testing.T) {
	key := newRawKey()
	pub, priv, _ := ed25519.GenerateKey(nil)
	data := randData(ChunkSize + 10)
	for _, flags := range []Flags{{}, {ReedSolomon: true}} {
		vol := encrypt(t, data, []Recipient{key}, EncryptOptions{Flags: flags, Signer: &Signer{Key: priv}})

		got, res, err := decrypt(vol, []Identity{key}, DecryptOptions{TrustedSigners: []TrustedSigner{{"Alice", pub}}})
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal(err)
		}
		if s := res.Signature; !s.Signed || !s.Valid || s.Name != "Alice" || !s.Key.Equal(pub) {
			t.Fatalf("status %+v", s)
		}
		// Unknown signer: valid, no name
		_, res, _ = decrypt(vol, []Identity{key}, DecryptOptions{})
		if s := res.Signature; !s.Valid || s.Name != "" {
			t.Fatalf("unknown signer status %+v", s)
		}
	}

	// Unsigned volume
	vol := encrypt(t, data, []Recipient{key}, EncryptOptions{})
	if _, res, _ := decrypt(vol, []Identity{key}, DecryptOptions{}); res.Signature.Signed {
		t.Fatal("unsigned volume reported as signed")
	}
}

// A recipient re-encrypting a signed volume to someone else (new stanzas,
// same file key and data) must not keep a valid signature
func TestSignatureForwardingFails(t *testing.T) {
	bob, carol := newRawKey(), newRawKey()
	_, priv, _ := ed25519.GenerateKey(nil)
	data := randData(2000)
	var out seekBuffer
	if err := Encrypt(&out, bytes.NewReader(data), []Recipient{bob}, EncryptOptions{Signer: &Signer{Key: priv}}); err != nil {
		t.Fatal(err)
	}
	vol := out.b

	// Bob knows the file key: rebuild the header for Carol around the same
	// data and signature block
	h, k, err := unlock(bytes.NewReader(vol), []Identity{bob}, false)
	if err != nil {
		t.Fatal(err)
	}
	fileKey, _ := bob.Unwrap(h.Stanzas, h.Flags)
	carolStanza, _ := carol.Wrap(fileKey, h.Flags)
	var nh bytes.Buffer
	if _, err := writeHeader(&nh, h.Comments, h.Flags, h.HKDFSalt, []Stanza{carolStanza}, k); err != nil {
		t.Fatal(err)
	}
	forged := nh.Bytes()
	copy(forged[len(forged)-sigBlockEncodedSize:], h.sigBlock)
	forged = append(forged, vol[h.Size:]...)

	_, res, err := decrypt(forged, []Identity{carol}, DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Signature.Valid {
		t.Fatal("forwarded volume kept a valid signature")
	}
}

func TestPasswordStanza(t *testing.T) {
	if testing.Short() {
		t.Skip("Argon2 with 1 GiB")
	}
	kf := randBytes(32)
	p := Password{Password: []byte("correct horse"), KeyfileKey: kf}
	data := randData(100)
	vol := encrypt(t, data, []Recipient{p}, EncryptOptions{Flags: Flags{Keyfiles: true}})
	if got, _, err := decrypt(vol, []Identity{p}, DecryptOptions{}); err != nil || !bytes.Equal(got, data) {
		t.Fatal(err)
	}
	for name, wrong := range map[string]Password{
		"password": {Password: []byte("wrong"), KeyfileKey: kf},
		"keyfiles": {Password: []byte("correct horse")},
	} {
		if _, _, err := decrypt(vol, []Identity{wrong}, DecryptOptions{}); !errors.Is(err, ErrIncorrect) {
			t.Errorf("wrong %s: %v", name, err)
		}
	}
}

func TestFingerprint(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	f := Fingerprint(pub)
	if len(f) != 19 || f != Fingerprint(pub) { // 16 chars in 4 groups
		t.Fatalf("fingerprint %q", f)
	}
}
