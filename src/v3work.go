package main

// The v3 core of work(): encrypts inputFile, or decrypts a v3 volume, into
// outputFile (through outputFile + ".incomplete"). Everything around it
// (zipping, recombining split chunks, deniability, splitting, deleting
// inputs, auto-unzip) stays in work().

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"ZeeCrypt/volume"

	"github.com/Picocrypt/giu"
)

// legacyFormat makes encryption write the v2 format (header version v1.52)
// instead of v3. Only tests set it, to keep exercising the v2 reader with
// freshly made volumes.
var legacyFormat bool

// isV3Volume reports whether 'path' starts with a v3 version field
func isV3Volume(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	first := make([]byte, 15)
	if _, err := io.ReadFull(f, first); err != nil {
		return false
	}
	return volume.IsV3(first)
}

// v3Identities builds the identities to try on a v3 volume from what the
// user entered. 'keyfileKey' is nil without keyfiles.
func v3Identities(keyfileKey []byte) []volume.Identity {
	return []volume.Identity{volume.Password{Password: []byte(password), KeyfileKey: keyfileKey}}
}

// workV3 returns false if it failed; mainStatus then says why and all
// temporary files are gone
func workV3(wrapInput func(io.Reader) io.Reader) bool {
	stat, err := os.Stat(inputFile)
	if err != nil {
		removeTempInput()
		resetUI()
		accessDenied("Read")
		return false
	}
	total := stat.Size()

	fin, err := os.Open(inputFile)
	if err != nil {
		removeTempInput()
		resetUI()
		accessDenied("Read")
		return false
	}

	if mode == "encrypt" && split {
		if _, err := os.Stat(outputFile); err == nil {
			fin.Close()
			removeTempInput()
			mainStatus = "Please remove " + filepath.Base(outputFile)
			mainStatusColor = RED
			return false
		}
	}

	// A deniable volume only reveals its flags once unwrapped
	if mode == "decrypt" {
		if h, err := volume.ReadHeader(fin, true); err == nil {
			keyfile, keyfileOrdered = h.Flags.Keyfiles, h.Flags.KeyfilesOrdered
		}
		if _, err := fin.Seek(0, io.SeekStart); err != nil {
			fin.Close()
			removeTempInput()
			accessDenied("Read")
			return false
		}
		if keyfile && len(keyfiles) == 0 {
			broken(fin, nil, "This volume requires keyfiles, please select them", true)
			return false
		}
	}

	// Keyfiles
	var keyfileKey []byte
	if len(keyfiles) > 0 {
		popupStatus = "Reading keyfiles..."
		giu.Update()
		key, duplicate, err := hashKeyfiles(keyfiles, keyfileOrdered)
		if err != nil {
			fin.Close()
			removeTempInput()
			accessDenied("Keyfile read")
			return false
		}
		// Unordered keyfiles are XORed together, so identical contents
		// cancel out: refuse them when encrypting
		if mode == "encrypt" && (duplicate || bytes.Equal(key, make([]byte, 32))) {
			fin.Close()
			removeTempInput()
			mainStatus = "Duplicate keyfiles detected"
			mainStatusColor = RED
			return false
		}
		keyfileKey = key
	}

	fout, err := os.Create(outputFile + ".incomplete")
	if err != nil {
		fin.Close()
		removeTempInput()
		accessDenied("Write")
		return false
	}

	startTime := time.Now()
	cancelled := func() bool { return !working }
	reportProgress := func(verb string) func(int64) {
		return func(done int64) {
			progress, speed, eta = statify(done, total, startTime)
			progressInfo = fmt.Sprintf("%.2f%%", progress*100)
			popupStatus = fmt.Sprintf("%s at %.2f MiB/s (ETA: %s)", verb, speed, eta)
			giu.Update()
		}
	}

	if mode == "encrypt" {
		popupStatus = "Deriving key..."
		giu.Update()
		flags := volume.Flags{
			Paranoid:        paranoid,
			Keyfiles:        keyfileKey != nil,
			KeyfilesOrdered: keyfileKey != nil && keyfileOrdered,
			ReedSolomon:     reedsolo,
		}
		recipient := volume.Password{Password: []byte(password), KeyfileKey: keyfileKey}
		err = volume.Encrypt(fout, wrapInput(fin), []volume.Recipient{recipient}, volume.EncryptOptions{
			Comments:  comments,
			Flags:     flags,
			Progress:  reportProgress("Encrypting"),
			Cancelled: cancelled,
		})
		if err != nil {
			fail := v3Fail(fin, fout)
			switch {
			case errors.Is(err, volume.ErrCancelled):
				cancel(nil, nil)
			case errors.Is(err, volume.ErrCommentsTooLong):
				mainStatus = "Comment exceeds the maximum length of 99,999 characters"
				mainStatusColor = RED
			default:
				insufficientSpace(nil, nil)
			}
			fail()
			return false
		}
	} else {
		popupStatus = "Deriving key..."
		giu.Update()
		res, err := volume.Decrypt(fout, wrapInput(fin), v3Identities(keyfileKey), volume.DecryptOptions{
			Force:     keep,
			Progress:  reportProgress("Decrypting"),
			Cancelled: cancelled,
		})
		if err != nil {
			fail := v3Fail(fin, fout)
			switch {
			case errors.Is(err, volume.ErrCancelled):
				cancel(nil, nil)
			case errors.Is(err, volume.ErrIncorrect):
				if keyfile || keyfileKey != nil {
					mainStatus = "The password or keyfiles are incorrect, or the file has been tampered with"
				} else {
					mainStatus = "The provided password is incorrect, or the file has been tampered with"
				}
				mainStatusColor = RED
			case errors.Is(err, volume.ErrHeaderModified):
				mainStatus = "The volume header has been modified"
				mainStatusColor = RED
			case errors.Is(err, volume.ErrDamaged):
				mainStatus = "The input file is damaged or modified"
				mainStatusColor = RED
			case errors.Is(err, volume.ErrHeaderDamaged):
				mainStatus = "The volume header is damaged"
				mainStatusColor = RED
			case errors.Is(err, volume.ErrTooShort):
				mainStatus = "The file is too short to be a volume"
				mainStatusColor = RED
			default:
				if res.Header != nil {
					insufficientSpace(nil, nil)
				} else {
					mainStatus = err.Error()
					mainStatusColor = RED
				}
			}
			fail()
			return false
		}
		if res.Damaged {
			kept = true
		}
	}

	fin.Close()
	if err := fout.Close(); err != nil {
		insufficientSpace(nil, nil)
		removeTempInput()
		os.Remove(fout.Name())
		return false
	}
	if err := os.Rename(outputFile+".incomplete", outputFile); err != nil {
		// Usually the file being replaced is open in another program
		os.Remove(outputFile + ".incomplete")
		removeTempInput()
		mainStatus = "Couldn't save " + filepath.Base(outputFile) + " (is it open in another program?)"
		mainStatusColor = RED
		return false
	}
	return true
}

// v3Fail returns the cleanup for a failed v3 operation: close both files,
// delete the partial output and any temporary input. mainStatus is set by
// the caller.
func v3Fail(fin, fout *os.File) func() {
	return func() {
		fin.Close()
		fout.Close()
		os.Remove(fout.Name())
		removeTempInput()
	}
}
