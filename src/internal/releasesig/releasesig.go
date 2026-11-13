// Package releasesig signs and verifies ZeeCrypt release files (minisign
// style): an Ed25519 signature over a short text naming the file, its
// version and its SHA-256. Signing the version stops an old release from
// being served again as a newer one (a downgrade).
//
// A .sig file is human-readable: the signed text, then a "signature:" line.
package releasesig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const header = "zeecrypt-release-signature-v1"

// Message is the exact text that gets signed
func Message(fileName, version string, sha256sum []byte) []byte {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	return []byte(fmt.Sprintf("%s\nfile: %s\nversion: %s\nsha256: %x\n", header, fileName, v, sha256sum))
}

// Sign returns the contents of the .sig file
func Sign(priv ed25519.PrivateKey, fileName, version string, sha256sum []byte) []byte {
	msg := Message(fileName, version, sha256sum)
	sig := ed25519.Sign(priv, msg)
	return append(msg, []byte("signature: "+base64.StdEncoding.EncodeToString(sig)+"\n")...)
}

// Verify checks a .sig file against the file the caller downloaded: it must
// name exactly this file, version and hash, and carry a valid signature
func Verify(pub ed25519.PublicKey, sigFile []byte, fileName, version string, sha256sum []byte) error {
	sigFile = bytes.ReplaceAll(sigFile, []byte("\r\n"), []byte("\n"))
	want := Message(fileName, version, sha256sum)
	if !bytes.HasPrefix(sigFile, want) {
		return errors.New("signature is for a different file, version or hash")
	}
	rest := strings.TrimSuffix(string(sigFile[len(want):]), "\n")
	b64, ok := strings.CutPrefix(rest, "signature: ")
	if !ok {
		return errors.New("malformed signature file")
	}
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("malformed signature")
	}
	if !ed25519.Verify(pub, want, sig) {
		return errors.New("invalid signature")
	}
	return nil
}

// ParsePublicKey decodes a base64 Ed25519 public key
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not an Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey decodes a base64 Ed25519 seed (32 bytes)
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("not an Ed25519 private key (base64 32-byte seed)")
	}
	return ed25519.NewKeyFromSeed(b), nil
}
