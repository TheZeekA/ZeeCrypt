package main

// Archives for multi-file encryption, and auto-unzip after decryption.
//
// Without compression, inputs go into a .zip with every entry stored
// (fastest, opens everywhere). With compression they go into a .tar.zst:
// zstd is several times faster than Deflate at a better ratio, and Windows 11
// Explorer and 7-Zip open .tar.zst natively, whereas a .zip using zstd
// (method 93) doesn't open in Explorer.

import (
	"archive/tar"
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Picocrypt/giu"
	"github.com/klauspost/compress/zstd"
)

// Compression levels offered in the UI. Index 0 is off.
var compressLevels = []string{"Don't compress", "Compress: fast", "Compress: balanced", "Compress: maximum"}
var compressLevel int32

// usesArchive reports whether encryption first packs the input into an
// archive: always for several files or a folder, and for a single file
// when compressing
func usesArchive() bool {
	return len(allFiles) > 1 || len(onlyFolders) > 0 || (mode == "encrypt" && compress)
}

// setCompression applies a choice from the compression combo: it sets
// 'compress' and gives the output the matching extension
func setCompression(level int32) {
	wasCompressed := compress
	compressLevel = level
	compress = level > 0
	if mode != "encrypt" || outputFile == "" {
		return
	}
	if len(allFiles) > 1 || len(onlyFolders) > 0 {
		outputFile = withArchiveExt(outputFile)
		return
	}
	// A single file: in its own .tar.zst when compressing, as is otherwise
	base := strings.TrimSuffix(outputFile, ".pcv")
	if wasCompressed {
		base = strings.TrimSuffix(base, ".tar.zst")
	}
	if compress {
		outputFile = base + ".tar.zst.pcv"
	} else {
		outputFile = base + ".pcv"
	}
}

func zstdLevel() zstd.EncoderLevel {
	switch compressLevel {
	case 1:
		return zstd.SpeedFastest
	case 3:
		return zstd.SpeedBestCompression
	default: // 2, or 'compress' set without a level
		return zstd.SpeedDefault
	}
}

// archiveExt is the container the current options produce
func archiveExt() string {
	if compress {
		return ".tar.zst"
	}
	return ".zip"
}

// withArchiveExt gives an archive volume name ("x.zip.pcv" or
// "x.tar.zst.pcv") the extension for the current compression choice
func withArchiveExt(out string) string {
	for _, e := range []string{".zip.pcv", ".tar.zst.pcv"} {
		if strings.HasSuffix(out, e) {
			return strings.TrimSuffix(out, e) + archiveExt() + ".pcv"
		}
	}
	return out
}

// isArchiveVolume reports whether decrypting 'volume' gives an archive that
// auto-unzip can extract
func isArchiveVolume(volume string) bool {
	return strings.HasSuffix(volume, ".zip.pcv") || strings.HasSuffix(volume, ".tar.zst.pcv")
}

// ---------- Writing ----------

type archiveWriter interface {
	addDir(name string, modified time.Time) error
	addFile(name string, stat os.FileInfo) (io.Writer, error)
	Close() error
}

func newArchiveWriter(w io.Writer) (archiveWriter, error) {
	if !compress {
		return zipArchive{zip.NewWriter(w)}, nil
	}
	zw, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstdLevel()))
	if err != nil {
		return nil, err
	}
	return &tarArchive{tar.NewWriter(zw), zw}, nil
}

type zipArchive struct{ w *zip.Writer }

func (a zipArchive) addDir(name string, modified time.Time) error {
	_, err := a.w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store, Modified: modified})
	return err
}

func (a zipArchive) addFile(name string, stat os.FileInfo) (io.Writer, error) {
	header, err := zip.FileInfoHeader(stat)
	if err != nil {
		return nil, err
	}
	header.Name = name
	header.Method = zip.Store
	return a.w.CreateHeader(header)
}

func (a zipArchive) Close() error { return a.w.Close() }

type tarArchive struct {
	tw *tar.Writer
	zw *zstd.Encoder
}

// PAX headers keep Unicode and long names intact
func (a *tarArchive) addDir(name string, modified time.Time) error {
	return a.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: 0o755, ModTime: modified, Format: tar.FormatPAX})
}

func (a *tarArchive) addFile(name string, stat os.FileInfo) (io.Writer, error) {
	err := a.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: stat.Size(), ModTime: stat.ModTime(), Format: tar.FormatPAX})
	return a.tw, err
}

func (a *tarArchive) Close() error {
	errT := a.tw.Close()
	errZ := a.zw.Close()
	return errors.Join(errT, errZ)
}

// ---------- Auto unzip ----------

func unpackArchive(path string) error {
	if strings.HasSuffix(path, ".tar.zst") {
		return unpackTarZst(path)
	}
	return unpackZip(path)
}

// extractDirFor is where an archive's contents go: next to it with "Same
// level", otherwise in a folder named after it
func extractDirFor(path, ext string) string {
	if sameLevel {
		return filepath.Dir(path)
	}
	return filepath.Join(filepath.Dir(path), strings.TrimSuffix(filepath.Base(path), ext))
}

// entryPath is where an archive entry goes inside 'dir'. Names were
// already checked with zipEntryPathOK before extracting; this checks the
// joined path again where it's used, so nothing can land outside 'dir'.
func entryPath(dir, name string) (string, error) {
	if !zipEntryPathOK(name) {
		return "", errors.New("potentially malicious archive item path")
	}
	p := filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(name, "/")))
	rel, err := filepath.Rel(dir, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("potentially malicious archive item path")
	}
	return p, nil
}

// extractEntry writes one file from an archive, reporting progress
func extractEntry(r io.Reader, outPath string, modified time.Time, progressFn func(n int)) error {
	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil {
		return err
	}
	dstFile, err := os.Create(outPath)
	if err != nil {
		return err
	}
	buffer := make([]byte, MiB)
	for {
		n, readErr := r.Read(buffer)
		if n > 0 {
			if _, err := dstFile.Write(buffer[:n]); err != nil {
				dstFile.Close()
				os.Remove(outPath)
				return err
			}
			progressFn(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			dstFile.Close()
			os.Remove(outPath)
			return readErr
		}
	}
	if err := dstFile.Close(); err != nil {
		os.Remove(outPath)
		return err
	}
	if !modified.IsZero() {
		os.Chtimes(outPath, modified, modified)
	}
	return nil
}

func unpackZip(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Check every entry before writing anything, so a bad archive doesn't
	// leave a half-extracted folder behind
	var totalSize int64
	for _, f := range reader.File {
		if !zipEntryPathOK(f.Name) {
			return errors.New("potentially malicious zip item path")
		}
		totalSize += int64(f.UncompressedSize64)
	}
	extractDir := extractDirFor(zipPath, ".zip")

	// archive/zip refuses to read past an entry's declared size, so this
	// also stops a "zip bomb" from filling the disk
	if free := diskFree(filepath.Dir(zipPath)); free >= 0 && totalSize > free {
		return errors.New("not enough disk space to unzip")
	}

	for _, f := range reader.File {
		if f.FileInfo().IsDir() {
			dir, err := entryPath(extractDir, f.Name)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(dir, 0700); err != nil {
				return err
			}
		}
	}

	var done int64
	startTime := time.Now()
	for i, f := range reader.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		outPath, err := entryPath(extractDir, f.Name)
		if err != nil {
			rc.Close()
			return err
		}
		err = extractEntry(rc, outPath, f.Modified, func(n int) {
			done += int64(n)
			unpackProgress(done, totalSize, startTime, i+1, len(reader.File))
		})
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func unpackProgress(done, total int64, start time.Time, item, items int) {
	progress, speed, eta = statify(done, total, start)
	progressInfo = fmt.Sprintf("%d/%d", item, items)
	popupStatus = fmt.Sprintf("Unpacking at %.2f MiB/s (ETA: %s)", speed, eta)
	giu.Update()
}

// openTarZst opens a .tar.zst for reading; 'closeFn' releases it
func openTarZst(path string) (tr *tar.Reader, closeFn func(), err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	zr, err := zstd.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return tar.NewReader(zr), func() { zr.Close(); f.Close() }, nil
}

// unpackTarZst reads the archive twice: once to check every entry (names,
// types, total size) before writing anything, then to extract. Decompressing
// zstd is fast enough that this costs little.
func unpackTarZst(path string) error {
	tr, closeFn, err := openTarZst(path)
	if err != nil {
		return err
	}
	var totalSize int64
	files := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			closeFn()
			return err
		}
		switch h.Typeflag {
		case tar.TypeReg:
			if h.Size < 0 {
				closeFn()
				return errors.New("bad tar entry size")
			}
			totalSize += h.Size
			files++
		case tar.TypeDir:
		default: // links, devices and the like are never extracted
			closeFn()
			return errors.New("unsupported tar entry: " + h.Name)
		}
		if !zipEntryPathOK(h.Name) {
			closeFn()
			return errors.New("potentially malicious tar item path")
		}
	}
	closeFn()

	extractDir := extractDirFor(path, ".tar.zst")
	if free := diskFree(filepath.Dir(path)); free >= 0 && totalSize > free {
		return errors.New("not enough disk space to unpack")
	}

	tr, closeFn, err = openTarZst(path)
	if err != nil {
		return err
	}
	defer closeFn()
	var done int64
	startTime := time.Now()
	item := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// Checked in the first pass; checked again in case the file changed
		if (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir) || !zipEntryPathOK(h.Name) {
			return errors.New("potentially malicious tar item")
		}
		outPath, err := entryPath(extractDir, h.Name)
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(outPath, 0700); err != nil {
				return err
			}
			if !h.ModTime.IsZero() {
				defer os.Chtimes(outPath, h.ModTime, h.ModTime) // after its contents are written
			}
			continue
		}
		item++
		// tar.Reader stops at the entry's declared size, which the first
		// pass already checked against the free space
		err = extractEntry(tr, outPath, h.ModTime, func(n int) {
			done += int64(n)
			unpackProgress(done, totalSize, startTime, item, files)
		})
		if err != nil {
			return err
		}
	}
}
