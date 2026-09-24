package main

// Headless test harness: drives onDrop()/work() the way the UI does, without a
// window. Tests share the app's globals, so they must not run in parallel.
// Each encrypt/decrypt runs Argon2id with 1 GiB of memory; the suite takes ~1 min.

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Picocrypt/imgui-go"
)

func TestMain(m *testing.M) {
	imgui.CreateContext(nil) // resetUI() calls imgui.ClearActiveID()
	os.Exit(m.Run())
}

func setup() {
	resetUI()
	working = false
	fastDecode = true
	showProgress = false
}

func waitScan() {
	for scanning {
		time.Sleep(5 * time.Millisecond)
	}
}

func randBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func writeFile(t *testing.T, path string, data []byte) {
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// encrypt drops 'paths', applies options and runs work(). Returns the output path and status.
func encrypt(t *testing.T, paths []string, pw string, kf []string, opt func()) (string, string) {
	t.Helper()
	setup()
	onDrop(paths)
	waitScan()
	password, cpassword = pw, pw
	keyfiles = kf
	if opt != nil {
		opt()
	}
	out := outputFile
	work(false)
	working = false
	return out, mainStatus
}

// decrypt drops 'vol', applies options and runs work(). Returns the output path and status.
func decrypt(t *testing.T, vol string, pw string, kf []string, opt func()) (string, string) {
	t.Helper()
	setup()
	onDrop([]string{vol})
	waitScan()
	password = pw
	keyfiles = kf
	if opt != nil {
		opt()
	}
	out := outputFile
	work(false)
	working = false
	return out, mainStatus
}

func mustStatus(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("status = %q, want it to contain %q", got, want)
	}
}

func mustContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: content mismatch (%d vs %d bytes)", path, len(got), len(want))
	}
}

// listDir returns the base names in dir, for asserting no leftovers.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func mustOnly(t *testing.T, dir string, want ...string) {
	t.Helper()
	got := listDir(t, dir)
	set := map[string]bool{}
	for _, w := range want {
		set[w] = true
	}
	for _, g := range got {
		if !set[g] {
			t.Fatalf("unexpected leftover %q in %v (want only %v)", g, got, want)
		}
	}
	for _, w := range want {
		if _, err := os.Stat(filepath.Join(dir, w)); err != nil {
			t.Fatalf("expected %q to exist; dir = %v", w, got)
		}
	}
}

func flipByte(t *testing.T, path string, off int64) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if off < 0 {
		off += int64(len(b))
	}
	b[off] ^= 0x5a
	writeFile(t, path, b)
}
