package main

// Regression tests for the v2.1.0 audit fixes

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func waitIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for showProgress && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if showProgress {
		t.Fatal("operation did not finish")
	}
}

func zipNames(t *testing.T, path string) []string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	return names
}

// ---------- Dropping files mid-operation must not touch work()'s state ----------

func TestDropIgnoredWhileWorking(t *testing.T) {
	setup()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.bin"), filepath.Join(dir, "b.bin")
	writeFile(t, a, []byte("a"))
	writeFile(t, b, []byte("b"))
	onDrop([]string{a})
	waitScan()
	password = "pw"
	for _, state := range []*bool{&working, &showProgress, &showOverwrite} {
		*state = true
		onWindowDrop([]string{b})
		*state = false
		if inputFile != a || outputFile != a+".pcv" || password != "pw" {
			t.Fatalf("drop changed state: input=%q output=%q", inputFile, outputFile)
		}
	}
	onWindowDrop([]string{b}) // idle: accepted
	if inputFile != b {
		t.Fatalf("idle drop ignored: input=%q", inputFile)
	}
}

// ---------- Recursive mode never overwrites existing outputs ----------

func TestRecursiveSkipsExistingOutputs(t *testing.T) {
	setup()
	dir := t.TempDir()
	b, c := filepath.Join(dir, "b.txt"), filepath.Join(dir, "c.txt")
	writeFile(t, b, []byte("bbb"))
	writeFile(t, c, []byte("ccc"))
	writeFile(t, b+".pcv", []byte("OLD VOLUME")) // must survive

	onDrop([]string{b, c})
	waitScan()
	password, cpassword = "pw", "pw"
	recursively = true
	onClickStartButton()
	waitIdle(t)

	mustStatus(t, mainStatus, "Processed 1 of 2 files; 1 skipped")
	mustContent(t, b+".pcv", []byte("OLD VOLUME"))
	if _, err := os.Stat(c + ".pcv"); err != nil {
		t.Fatal("c.txt was not encrypted")
	}
}

// ---------- Deniability can't be keyed by an empty password ----------

func TestDeniabilityRequiresPassword(t *testing.T) {
	dir := t.TempDir()
	in, kf := filepath.Join(dir, "f.bin"), filepath.Join(dir, "k.key")
	writeFile(t, in, randBytes(t, 1000))
	writeFile(t, kf, randBytes(t, 32))
	_, st := encrypt(t, []string{in}, "", []string{kf}, func() { deniability = true })
	mustStatus(t, st, "Deniability requires a password")
	mustOnly(t, dir, "f.bin", "k.key")
}

// ---------- Keyfiles: no stored hash, no silent cancellation ----------

func TestKeyfileHashNotStored(t *testing.T) {
	dir := t.TempDir()
	in, kf := filepath.Join(dir, "f.bin"), filepath.Join(dir, "k.key")
	data := randBytes(t, 3000)
	writeFile(t, in, data)
	writeFile(t, kf, randBytes(t, 32))
	vol, st := encrypt(t, []string{in}, "pw", []string{kf}, nil)
	mustStatus(t, st, "Completed")
	os.Remove(in)

	b, err := os.ReadFile(vol)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := rsDecode(rs32, b[501:597]) // no comments: field starts at 309+192
	if err != nil || !bytes.Equal(stored, make([]byte, 32)) {
		t.Fatalf("keyfile hash field = %x (err %v), want zeros", stored, err)
	}

	out, st := decrypt(t, vol, "pw", []string{kf}, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
}

func TestDuplicateKeyfileContentsAmongOthers(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	k1, k2, k3 := filepath.Join(dir, "1.key"), filepath.Join(dir, "copy.key"), filepath.Join(dir, "3.key")
	writeFile(t, in, []byte("x"))
	writeFile(t, k1, []byte("same"))
	writeFile(t, k2, []byte("same"))
	writeFile(t, k3, []byte("different"))
	_, st := encrypt(t, []string{in}, "pw", []string{k1, k2, k3}, nil)
	mustStatus(t, st, "Duplicate keyfiles")
	mustOnly(t, dir, "f.bin", "1.key", "copy.key", "3.key")

	// Order-required keyfiles don't cancel, so identical contents are fine
	vol, st := encrypt(t, []string{in}, "pw", []string{k1, k2, k3}, func() { keyfileOrdered = true })
	mustStatus(t, st, "Completed")
	_, st = decrypt(t, vol, "pw", []string{k1, k2, k3}, nil)
	mustStatus(t, st, "Completed")
}

// ---------- A newer drop supersedes an older, still-running folder scan ----------

func TestNewerDropSupersedesScan(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "A"), filepath.Join(dir, "B")
	for _, d := range []string{a, b} {
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 1500; i++ {
		writeFile(t, filepath.Join(a, fmt.Sprintf("%04d", i)), nil)
	}
	writeFile(t, filepath.Join(b, "only.txt"), []byte("b"))

	setup()
	onDrop([]string{a})
	onDrop([]string{b}) // while A is (likely) still being scanned
	waitScan()
	time.Sleep(200 * time.Millisecond) // give a stale scan time to misbehave
	if len(allFiles) != 1 || allFiles[0] != filepath.Join(b, "only.txt") {
		t.Fatalf("allFiles = %d entries, first %v", len(allFiles), allFiles[:min(len(allFiles), 3)])
	}
	if scanning {
		t.Fatal("still scanning")
	}
}

// ---------- Zip contents: mixed folders, name clashes, empty folders ----------

func TestZipFromDifferentFoldersAndEmptyDirs(t *testing.T) {
	dir := t.TempDir()
	d1, d2 := filepath.Join(dir, "one"), filepath.Join(dir, "two")
	tree := filepath.Join(d1, "tree")
	for _, d := range []string{d1, d2, filepath.Join(tree, "empty"), filepath.Join(tree, "sub")} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(d1, "x.txt"), []byte("1"))
	writeFile(t, filepath.Join(d2, "x.txt"), []byte("2"))
	writeFile(t, filepath.Join(tree, "sub", "s.txt"), []byte("s"))

	// Like dropping Explorer search results from different folders
	vol, st := encrypt(t, []string{filepath.Join(d1, "x.txt"), filepath.Join(d2, "x.txt"), tree}, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	out, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	got := strings.Join(zipNames(t, out), ",")
	want := "tree/,tree/empty/,tree/sub/,tree/sub/s.txt,x (2).txt,x.txt"
	if got != want {
		t.Fatalf("zip entries = %s, want %s", got, want)
	}
}

func TestAutoUnzipKeepsTree(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(filepath.Join(tree, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tree, "a.txt"), []byte("aaa"))
	vol, st := encrypt(t, []string{tree}, "pw", nil, nil)
	mustStatus(t, st, "Completed")

	extracted := strings.TrimSuffix(vol, ".zip.pcv")
	_, st = decrypt(t, vol, "pw", nil, func() { autoUnzip = true })
	mustStatus(t, st, "Completed")
	mustContent(t, filepath.Join(extracted, "tree", "a.txt"), []byte("aaa"))
	if fi, err := os.Stat(filepath.Join(extracted, "tree", "empty")); err != nil || !fi.IsDir() {
		t.Fatal("empty folder not restored")
	}
}

// ---------- Cleanup must not touch the user's files ----------

func TestDeniableZipKeepsSameNamedUserFile(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	writeFile(t, a, []byte("a"))
	writeFile(t, b, []byte("b"))
	var userZip string
	_, st := encrypt(t, []string{a, b}, "pw", nil, func() {
		deniability = true
		userZip = strings.TrimSuffix(outputFile, ".pcv") // "encrypted-<time>.zip"
		writeFile(t, userZip, []byte("USER ZIP"))
	})
	mustStatus(t, st, "Completed")
	mustContent(t, userZip, []byte("USER ZIP"))
}

func TestForcedDecryptKeepsVolumeDespiteDelete(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 5000))
	vol, _ := encrypt(t, []string{in}, "pw", nil, nil)
	os.Remove(in)
	flipByte(t, vol, 789+10)
	_, st := decrypt(t, vol, "pw", nil, func() { keep = true; delete = true })
	mustStatus(t, st, "modified. Please be careful")
	if _, err := os.Stat(vol); err != nil {
		t.Fatal("unverified decryption deleted the volume")
	}
}

func TestSplitKeepsUnrelatedSameNamedFiles(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 5000))
	notes := filepath.Join(dir, "f.bin.pcv.notes.txt")
	writeFile(t, notes, []byte("mine"))
	_, st := encrypt(t, []string{in}, "pw", nil, func() { split = true; splitSize = "2"; splitSelected = 0 })
	mustStatus(t, st, "Completed")
	mustContent(t, notes, []byte("mine"))
}

func TestTruncatedHeaderReportedAsTooShort(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 100))
	vol, _ := encrypt(t, []string{in}, "pw", nil, nil)
	os.Remove(in)
	b, _ := os.ReadFile(vol)
	writeFile(t, vol, b[:400]) // header cut inside the MAC fields
	_, st := decrypt(t, vol, "pw", nil, func() { keep = true })
	mustStatus(t, st, "too short")
}

// ---------- Pure helpers ----------

func TestZipEntryPathOK(t *testing.T) {
	for name, want := range map[string]bool{
		"a.txt": true, "dir/": true, "a/b/c.txt": true, "a..b.txt": true,
		"../x": false, "a/../../x": false, `a\..\..\x`: false, "/abs": false,
		"C:/x": false, "a:stream": false, "NUL": false, "": false,
	} {
		if got := zipEntryPathOK(name); got != want {
			t.Errorf("zipEntryPathOK(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestOutputNameFromDialog(t *testing.T) {
	setup()
	mode, inputFile = "encrypt", `C:\d\report.txt`
	for in, want := range map[string]string{
		`C:\d\backup.2026.11`: `C:\d\backup.2026.11.txt.pcv`,
		`C:\d\x.txt.pcv`:      `C:\d\x.txt.pcv`,
		`C:\d\x.pcv`:          `C:\d\x.txt.pcv`,
	} {
		if got := outputNameFromDialog(in); got != want {
			t.Errorf("encrypt %q -> %q, want %q", in, got, want)
		}
	}
	mode, inputFile = "decrypt", `C:\d\a.zip.pcv`
	for in, want := range map[string]string{
		`C:\d\out`:     `C:\d\out.zip`,
		`C:\d\out.zip`: `C:\d\out.zip`,
		`C:\d\v1.2`:    `C:\d\v1.2.zip`,
	} {
		if got := outputNameFromDialog(in); got != want {
			t.Errorf("decrypt %q -> %q, want %q", in, got, want)
		}
	}
	setup()
}

func TestSplitChunkDetection(t *testing.T) {
	for name, want := range map[string]bool{
		"a.pcv.0": true, "a.pcv.12": true, "a.pcv.2024x": false, "a.pcv.notes": false, "a.pcv": false,
	} {
		if got := splitChunkRegex.MatchString(name); got != want {
			t.Errorf("%q: %v, want %v", name, got, want)
		}
	}
	dir := t.TempDir()
	base := filepath.Join(dir, "v[1].pcv")
	for _, n := range []string{"v[1].pcv.0", "v[1].pcv.1", "v[1].pcv.notes", "v[1].pcv.1.bak"} {
		writeFile(t, filepath.Join(dir, n), nil)
	}
	if got := existingChunks(base); len(got) != 2 {
		t.Fatalf("existingChunks = %v", got)
	}
}

func TestStatifyEdgeCases(t *testing.T) {
	if p, s, e := statify(0, 0, time.Now()); p != 0 || s != 0 || e != "00:00:00" {
		t.Fatalf("zero total: %v %v %v", p, s, e)
	}
	start := time.Now().Add(-2 * time.Second)
	_, s, _ := statify(4*MiB, 8*MiB, start)
	if s < 1.9 || s > 2.1 { // 4 MiB in 2 s
		t.Fatalf("speed = %.3f MiB/s, want ~2", s)
	}
}

func TestRecursiveSummary(t *testing.T) {
	if s, c := recursiveSummary(3, 0, 0); s != "Completed" || c != GREEN {
		t.Fatal(s)
	}
	if s, _ := recursiveSummary(5, 2, 1); s != "Processed 2 of 5 files; 2 skipped (output already exists), 1 failed" {
		t.Fatal(s)
	}
}
