package main

import (
	"crypto/hmac"
	"os"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// forgeKeyfileOnlyHeader rewrites the nonce of a keyfile-only (empty password),
// comment-less, non-paranoid volume and recomputes the header MAC the way an
// attacker without the keyfiles could: from argon2id("", salt) alone.
func forgeKeyfileOnlyHeader(t *testing.T, vol string) {
	t.Helper()
	b, err := os.ReadFile(vol)
	if err != nil {
		t.Fatal(err)
	}
	must := func(d []byte, err error) []byte {
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	flags := must(rsDecode(rs5, b[30:45]))
	salt := must(rsDecode(rs16, b[45:93]))
	hkdfSalt := must(rsDecode(rs32, b[93:189]))
	serpentIV := must(rsDecode(rs16, b[189:237]))
	nonce := randBytes(t, 24)
	copy(b[237:309], rsEncode(rs24, nonce))

	key := argon2.IDKey([]byte(""), salt, 4, 1<<20, 4, 32)
	sub := make([]byte, 32)
	if _, err := hkdf.New(sha3.New256, key, hkdfSalt, []byte("zeecrypt-header-mac")).Read(sub); err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha3.New512, sub)
	for _, p := range [][]byte{flags, salt, hkdfSalt, serpentIV, nonce} {
		m.Write(p)
	}
	copy(b[309:501], rsEncode(rs64, m.Sum(nil)))
	writeFile(t, vol, b)
}
