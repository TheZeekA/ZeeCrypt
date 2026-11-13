package releasesig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sum := sha256.Sum256([]byte("exe"))
	sig := Sign(priv, "ZeeCrypt.exe", "2.1.0", sum[:])

	if err := Verify(pub, sig, "ZeeCrypt.exe", "v2.1.0", sum[:]); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Windows line endings (e.g. after a manual download through a browser)
	if err := Verify(pub, bytes.ReplaceAll(sig, []byte("\n"), []byte("\r\n")), "ZeeCrypt.exe", "2.1.0", sum[:]); err != nil {
		t.Fatalf("CRLF signature rejected: %v", err)
	}

	other := sha256.Sum256([]byte("other"))
	otherPub, _, _ := ed25519.GenerateKey(nil)
	for name, err := range map[string]error{
		"downgrade (old version served as new)": Verify(pub, sig, "ZeeCrypt.exe", "2.2.0", sum[:]),
		"different file":                        Verify(pub, sig, "ZeeCrypt-Installer.msi", "2.1.0", sum[:]),
		"different hash":                        Verify(pub, sig, "ZeeCrypt.exe", "2.1.0", other[:]),
		"different key":                         Verify(otherPub, sig, "ZeeCrypt.exe", "2.1.0", sum[:]),
		"tampered signature":                    Verify(pub, tamper(priv, sum[:]), "ZeeCrypt.exe", "2.1.0", sum[:]),
		"trailing junk":                         Verify(pub, append(append([]byte{}, sig...), "extra\n"...), "ZeeCrypt.exe", "2.1.0", sum[:]),
		"empty":                                 Verify(pub, nil, "ZeeCrypt.exe", "2.1.0", sum[:]),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseKeys(t *testing.T) {
	if _, err := ParsePublicKey("not base64!"); err == nil {
		t.Error("bad public key accepted")
	}
	if _, err := ParsePrivateKey(base64.StdEncoding.EncodeToString(make([]byte, 32))); err != nil {
		t.Errorf("32-byte seed rejected: %v", err)
	}
	if _, err := ParsePrivateKey("AAAA"); err == nil {
		t.Error("short seed accepted")
	}
}

// tamper returns a .sig whose signature has one bit flipped
func tamper(priv ed25519.PrivateKey, sum []byte) []byte {
	msg := Message("ZeeCrypt.exe", "2.1.0", sum)
	sig := ed25519.Sign(priv, msg)
	sig[0] ^= 1
	return append(msg, []byte("signature: "+base64.StdEncoding.EncodeToString(sig)+"\n")...)
}
