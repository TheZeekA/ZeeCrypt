// zeecrypt-sign creates the release signing key, signs release files in CI,
// and lets anyone verify a download.
//
//	go run ./cmd/zeecrypt-sign keygen release.key
//	    Writes a new private key to release.key and prints the public key.
//	    Put the public key in releasePublicKey (src/ZeeCrypt.go) and the
//	    contents of release.key in the ZEECRYPT_SIGNING_KEY Actions secret,
//	    then keep release.key offline.
//
//	ZEECRYPT_SIGNING_KEY=... go run ./cmd/zeecrypt-sign sign <version> <file>...
//	    Writes <file>.sig next to each file.
//
//	go run ./cmd/zeecrypt-sign verify <public key> <version> <file>
//	    Checks <file> against <file>.sig.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"ZeeCrypt/internal/releasesig"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		if len(os.Args) != 3 {
			usage()
		}
		err = keygen(os.Args[2])
	case "sign":
		if len(os.Args) < 4 {
			usage()
		}
		err = sign(os.Args[2], os.Args[3:])
	case "verify":
		if len(os.Args) != 5 {
			usage()
		}
		err = verify(os.Args[2], os.Args[3], os.Args[4])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: zeecrypt-sign keygen <private key file>")
	fmt.Fprintln(os.Stderr, "       zeecrypt-sign sign <version> <file>...   (key in ZEECRYPT_SIGNING_KEY)")
	fmt.Fprintln(os.Stderr, "       zeecrypt-sign verify <public key> <version> <file>")
	os.Exit(2)
}

func keygen(path string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println("Public key:", base64.StdEncoding.EncodeToString(pub))
	return nil
}

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func sign(version string, files []string) error {
	priv, err := releasesig.ParsePrivateKey(os.Getenv("ZEECRYPT_SIGNING_KEY"))
	if err != nil {
		return fmt.Errorf("ZEECRYPT_SIGNING_KEY: %w", err)
	}
	for _, path := range files {
		sum, err := hashFile(path)
		if err != nil {
			return err
		}
		sig := releasesig.Sign(priv, filepath.Base(path), version, sum)
		if err := os.WriteFile(path+".sig", sig, 0644); err != nil {
			return err
		}
		fmt.Println("Signed", path)
	}
	return nil
}

func verify(pubKey, version, path string) error {
	pub, err := releasesig.ParsePublicKey(pubKey)
	if err != nil {
		return err
	}
	sum, err := hashFile(path)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		return err
	}
	if err := releasesig.Verify(pub, sig, filepath.Base(path), version, sum); err != nil {
		return err
	}
	fmt.Println("Good signature:", filepath.Base(path), version)
	return nil
}
