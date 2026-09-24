package main

// Direct tests for the non-GUI building blocks (Reed-Solomon, padding, header
// MAC, comment-length handling). The end-to-end tests in work_test.go cover the
// same code through work(); these pin down the edge cases individually.

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Picocrypt/infectious"
)

var rsCodecs = []struct {
	name string
	rs   *infectious.FEC
}{
	{"rs1", rs1}, {"rs5", rs5}, {"rs16", rs16}, {"rs24", rs24},
	{"rs32", rs32}, {"rs64", rs64}, {"rs128", rs128},
}

// corrupt changes n distinct bytes of b to different values.
func corrupt(b []byte, n int) {
	for _, i := range mrand.Perm(len(b))[:n] {
		b[i] ^= byte(1 + mrand.IntN(255))
	}
}

func TestRSCorrectsUpToThreshold(t *testing.T) {
	fastDecode = false
	for _, c := range rsCodecs {
		n, total := c.rs.Required(), c.rs.Total()
		limit := (total - n) / 2 // Berlekamp-Welch corrects up to half the parity bytes
		for errs := 0; errs <= limit; errs++ {
			data := make([]byte, n)
			rand.Read(data)
			enc := rsEncode(c.rs, data)
			if len(enc) != total {
				t.Fatalf("%s: encoded %d bytes, want %d", c.name, len(enc), total)
			}
			corrupt(enc, errs)
			got, err := rsDecode(c.rs, enc)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("%s: %d errors not corrected (err=%v)", c.name, errs, err)
			}
		}
	}
}

func TestRSFailsPastThreshold(t *testing.T) {
	fastDecode = false
	for _, c := range rsCodecs {
		n, total := c.rs.Required(), c.rs.Total()
		errs := (total-n)/2 + 1
		for trial := 0; trial < 20; trial++ {
			data := make([]byte, n)
			rand.Read(data)
			enc := rsEncode(c.rs, data)
			corrupt(enc, errs)
			got, err := rsDecode(c.rs, enc)
			// Past the limit the decoder must not hand back the original as if repaired
			// silently; it either reports an error or (rarely) lands on another codeword.
			if err == nil && bytes.Equal(got, data) {
				t.Fatalf("%s: %d errors decoded to the original without error", c.name, errs)
			}
			if err != nil && len(got) != n {
				t.Fatalf("%s: force-decode returned %d bytes, want %d", c.name, len(got), n)
			}
		}
	}
}

func TestRSFastDecodeSkipsCorrection(t *testing.T) {
	fastDecode = true
	defer func() { fastDecode = false }()
	data := make([]byte, 128)
	rand.Read(data)
	enc := rsEncode(rs128, data)
	enc[0] ^= 0xff
	got, err := rsDecode(rs128, enc)
	if err != nil || !bytes.Equal(got, enc[:128]) {
		t.Fatalf("fast decode should return the raw first 128 bytes (err=%v)", err)
	}
}

func TestPadUnpad(t *testing.T) {
	for n := 0; n < 128; n++ {
		data := make([]byte, n)
		rand.Read(data)
		p := pad(append([]byte(nil), data...))
		if len(p) != 128 {
			t.Fatalf("pad(%d bytes) = %d bytes, want 128", n, len(p))
		}
		if got := unpad(p); !bytes.Equal(got, data) {
			t.Fatalf("unpad(pad(%d bytes)) mismatch", n)
		}
	}
	// A corrupted final byte is left alone, so the MAC check fails instead of a crash
	for _, bad := range []byte{0, 129, 255} {
		b := make([]byte, 128)
		b[127] = bad
		if got := unpad(b); len(got) != 128 {
			t.Fatalf("unpad with final byte %d returned %d bytes, want 128", bad, len(got))
		}
	}
}

func TestHeaderMAC(t *testing.T) {
	rb := func(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
	key, hkdfSalt := rb(32), rb(32)
	// Same shape as work(): flags, salt, hkdfSalt, serpentIV, nonce
	parts := [][]byte{rb(5), rb(16), hkdfSalt, rb(16), rb(24)}
	ref := computeHeaderMAC(key, hkdfSalt, parts...)
	if len(ref) != 64 {
		t.Fatalf("MAC is %d bytes, want 64", len(ref))
	}
	if !bytes.Equal(ref, computeHeaderMAC(key, hkdfSalt, parts...)) {
		t.Fatal("MAC is not deterministic")
	}
	for p := range parts {
		for i := range parts[p] {
			parts[p][i] ^= 1
			if bytes.Equal(ref, computeHeaderMAC(key, hkdfSalt, parts...)) {
				t.Fatalf("flipping part %d byte %d didn't change the MAC", p, i)
			}
			parts[p][i] ^= 1
		}
	}
	key[0] ^= 1
	if bytes.Equal(ref, computeHeaderMAC(key, hkdfSalt, parts...)) {
		t.Fatal("changing the key didn't change the MAC")
	}
	key[0] ^= 1
	if bytes.Equal(ref, computeHeaderMAC(key, rb(32), parts...)) {
		t.Fatal("changing the HKDF salt didn't change the MAC")
	}
}

func TestCommentLengthLimit(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "c.bin")
	writeFile(t, in, randBytes(t, 1000))

	long := strings.Repeat("x", 100000)
	_, st := encrypt(t, []string{in}, "pw", nil, func() { comments = long })
	mustStatus(t, st, "maximum length of 99,999")
	mustOnly(t, dir, "c.bin")

	max := strings.Repeat("y", 99999)
	vol, st := encrypt(t, []string{in}, "pw", nil, func() { comments = max })
	mustStatus(t, st, "Completed")
	setup()
	onDrop([]string{vol})
	waitScan()
	if comments != max {
		t.Fatalf("99,999-char comment read back as %d chars", len(comments))
	}
}

func TestMalformedCommentLengthRejected(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "m.bin")
	writeFile(t, in, randBytes(t, 1000))
	vol, st := encrypt(t, []string{in}, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	orig, err := os.ReadFile(vol)
	if err != nil {
		t.Fatal(err)
	}

	// Validly Reed-Solomon encoded, so only the ^\d{5}$ check can catch them
	for _, bad := range []string{"-0001", "+1234", " 1234", "1234 ", "12a45", "abcde", "\x00\x00\x00\x00\x00"} {
		b := append([]byte(nil), orig...)
		copy(b[15:30], rsEncode(rs5, []byte(bad)))
		writeFile(t, vol, b)
		_, st := decrypt(t, vol, "pw", nil, nil)
		mustStatus(t, st, "Unable to read comments length")
		if comments != "Comments are corrupted" {
			t.Fatalf("%q: comments = %q, want the corrupted notice", bad, comments)
		}
		mustOnly(t, dir, "m.bin", "m.bin.pcv")
	}
}
