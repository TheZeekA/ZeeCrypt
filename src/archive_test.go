package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func TestCompressedRoundTripWithAutoUnzip(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	for _, d := range []string{filepath.Join(tree, "empty"), filepath.Join(tree, "sub")} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	text := bytes.Repeat([]byte("compress me "), 50000)
	random := randBytes(t, 300000)
	writeFile(t, filepath.Join(tree, "a.txt"), text)
	writeFile(t, filepath.Join(tree, "sub", "r.bin"), random)
	writeFile(t, filepath.Join(tree, "sub", "é ü.txt"), []byte("unicode"))

	vol, st := encrypt(t, []string{tree}, "pw", nil, func() { setCompression(2) })
	mustStatus(t, st, "Completed")
	if !strings.HasSuffix(vol, ".tar.zst.pcv") {
		t.Fatalf("volume name %q", vol)
	}
	if fi, _ := os.Stat(vol); fi.Size() > int64(len(random))+200000 {
		t.Fatalf("volume is %d bytes; text wasn't compressed", fi.Size())
	}

	extracted := strings.TrimSuffix(vol, ".tar.zst.pcv")
	_, st = decrypt(t, vol, "pw", nil, func() { autoUnzip = true })
	mustStatus(t, st, "Completed")
	mustContent(t, filepath.Join(extracted, "tree", "a.txt"), text)
	mustContent(t, filepath.Join(extracted, "tree", "sub", "r.bin"), random)
	mustContent(t, filepath.Join(extracted, "tree", "sub", "é ü.txt"), []byte("unicode"))
	if fi, err := os.Stat(filepath.Join(extracted, "tree", "empty")); err != nil || !fi.IsDir() {
		t.Fatal("empty folder not restored")
	}
	if _, err := os.Stat(strings.TrimSuffix(vol, ".pcv")); !os.IsNotExist(err) {
		t.Fatal("the .tar.zst was not removed after unpacking")
	}
}

// Every level writes an archive that unpackTarZst reads back
func TestTarZstLevels(t *testing.T) {
	defer func() { compress, compressLevel = false, 0 }()
	data := bytes.Repeat([]byte("level test "), 10000)
	for level := int32(1); level <= 3; level++ {
		compress, compressLevel = true, level
		dir := t.TempDir()
		path := filepath.Join(dir, "x.tar.zst")
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		w, err := newArchiveWriter(f)
		if err != nil {
			t.Fatal(err)
		}
		mod := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
		if err := w.addDir("d/", mod); err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(dir, "src.txt")
		writeFile(t, src, data)
		stat, _ := os.Stat(src)
		entry, err := w.addFile("d/f.txt", stat)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write(data)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		f.Close()

		sameLevel = false
		if err := unpackArchive(path); err != nil {
			t.Fatalf("level %d: %v", level, err)
		}
		mustContent(t, filepath.Join(dir, "x", "d", "f.txt"), data)
		if fi, err := os.Stat(filepath.Join(dir, "x", "d")); err != nil || !fi.ModTime().Equal(mod) {
			t.Errorf("level %d: folder date not restored", level)
		}
	}
}

// writeTarZst builds a .tar.zst from raw headers, for malicious archives
func writeTarZst(t *testing.T, path string, headers []*tar.Header) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw, _ := zstd.NewWriter(f)
	tw := tar.NewWriter(zw)
	for _, h := range headers {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			tw.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	tw.Close()
	zw.Close()
}

func TestMaliciousTarRejected(t *testing.T) {
	sameLevel = false
	cases := map[string]*tar.Header{
		"dotdot":   {Typeflag: tar.TypeReg, Name: "../evil.txt", Size: 1},
		"absolute": {Typeflag: tar.TypeReg, Name: "C:/evil.txt", Size: 1},
		"rooted":   {Typeflag: tar.TypeReg, Name: "/evil.txt", Size: 1},
		"device":   {Typeflag: tar.TypeReg, Name: "CON", Size: 1},
		"symlink":  {Typeflag: tar.TypeSymlink, Name: "link", Linkname: "C:/Windows"},
		"hardlink": {Typeflag: tar.TypeLink, Name: "hl", Linkname: "x"},
	}
	for name, h := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "m.tar.zst")
		// a good entry first: nothing at all may be written for a bad archive
		writeTarZst(t, path, []*tar.Header{{Typeflag: tar.TypeReg, Name: "ok.txt", Size: 2}, h})
		if err := unpackArchive(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(filepath.Join(dir, "m")); !os.IsNotExist(err) {
			t.Errorf("%s: extracted something before rejecting", name)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil.txt")); err == nil {
			t.Errorf("%s: wrote outside the folder", name)
		}
	}
}

func TestArchiveNaming(t *testing.T) {
	setup()
	defer setup()
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	writeFile(t, a, []byte("a"))
	writeFile(t, b, []byte("b"))
	onDrop([]string{a, b})
	waitScan()
	if !strings.HasSuffix(outputFile, ".zip.pcv") {
		t.Fatalf("output %q", outputFile)
	}
	setCompression(1)
	if !strings.HasSuffix(outputFile, ".tar.zst.pcv") {
		t.Fatalf("compressed output %q", outputFile)
	}
	if got := outputNameFromDialog(filepath.Join(dir, "backup.2026")); got != filepath.Join(dir, "backup.2026.tar.zst.pcv") {
		t.Errorf("dialog name %q", got)
	}
	setCompression(0)
	if !strings.HasSuffix(outputFile, ".zip.pcv") || strings.Contains(outputFile, ".tar") {
		t.Fatalf("uncompressed output %q", outputFile)
	}

	// A single file: in its own .tar.zst when compressing, its name kept
	// otherwise (even when it looks like an archive)
	setup()
	z := filepath.Join(dir, "photos.tar.zst")
	writeFile(t, z, []byte("z"))
	onDrop([]string{z})
	waitScan()
	if outputFile != z+".pcv" {
		t.Errorf("single file output %q", outputFile)
	}
	setCompression(2)
	if outputFile != z+".tar.zst.pcv" {
		t.Errorf("compressed single file output %q", outputFile)
	}
	setCompression(1)
	if outputFile != z+".tar.zst.pcv" {
		t.Errorf("level change output %q", outputFile)
	}
	setCompression(0)
	if outputFile != z+".pcv" {
		t.Errorf("uncompressed again: output %q", outputFile)
	}

	if !isArchiveVolume("x.tar.zst.pcv") || !isArchiveVolume("x.zip.pcv") || isArchiveVolume("x.txt.pcv") {
		t.Error("isArchiveVolume")
	}
}

func TestCompressSingleFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "report.txt")
	text := bytes.Repeat([]byte("one file, very compressible "), 40000)
	writeFile(t, in, text)
	vol, st := encrypt(t, []string{in}, "pw", nil, func() { setCompression(3); delete = true })
	mustStatus(t, st, "Completed")
	if vol != in+".tar.zst.pcv" {
		t.Fatalf("volume %q", vol)
	}
	if fi, _ := os.Stat(vol); fi.Size() > int64(len(text))/10 {
		t.Fatalf("volume is %d bytes for %d bytes of text", fi.Size(), len(text))
	}
	mustOnly(t, dir, "report.txt.tar.zst.pcv") // "Delete files" removed only the input

	_, st = decrypt(t, vol, "pw", nil, func() { autoUnzip = true; sameLevel = true })
	mustStatus(t, st, "Completed")
	mustContent(t, in, text)
	mustOnly(t, dir, "report.txt.tar.zst.pcv", "report.txt")
}

func TestEntryPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	for _, ok := range []string{"a.txt", "sub/b.txt", "sub/", "a..b.txt"} {
		p, err := entryPath(dir, ok)
		if err != nil || !strings.HasPrefix(p, dir+string(filepath.Separator)) {
			t.Errorf("%q: %q %v", ok, p, err)
		}
	}
	for _, bad := range []string{"../x", "sub/../../x", "/x", "C:/x", "C:x", "", "CON"} {
		if _, err := entryPath(dir, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
