package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"ZeeCrypt/internal/releasesig"
)

func TestVerifyUpdate(t *testing.T) {
	defer func(old string) { releasePublicKey = old }(releasePublicKey)
	pub, priv, _ := ed25519.GenerateKey(nil)
	sum := sha256.Sum256([]byte("new exe"))
	sig := releasesig.Sign(priv, "ZeeCrypt.exe", "2.2.0", sum[:])

	releasePublicKey = ""
	if verifyUpdate(nil, "2.2.0", sum[:]) != nil {
		t.Fatal("without a release key, updates must not need a signature")
	}

	releasePublicKey = base64.StdEncoding.EncodeToString(pub)
	if err := verifyUpdate(sig, "2.2.0", sum[:]); err != nil {
		t.Fatalf("valid update rejected: %v", err)
	}
	if verifyUpdate(nil, "2.2.0", sum[:]) == nil {
		t.Fatal("missing signature accepted")
	}
	if verifyUpdate(sig, "2.3.0", sum[:]) == nil {
		t.Fatal("old signed release accepted as a newer version")
	}
	other := sha256.Sum256([]byte("tampered exe"))
	if verifyUpdate(sig, "2.2.0", other[:]) == nil {
		t.Fatal("signature accepted for a different exe")
	}
}
