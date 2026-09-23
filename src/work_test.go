package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- Regression: normal round trips must keep working ----------

func TestRoundTrips(t *testing.T) {
	cases := []struct {
		name string
		pw   string
		nkf  int
		opt  func()
	}{
		{"password", "pw-1", 0, nil},
		{"paranoid", "pw-2", 0, func() { paranoid = true }},
		{"reedsolo", "pw-3", 0, func() { reedsolo = true }},
		{"keyfile-only", "", 1, nil},
		{"pw+2 keyfiles ordered", "pw-4", 2, func() { keyfileOrdered = true }},
		{"paranoid+rs+keyfiles+comment", "pw-5", 2, func() { paranoid = true; reedsolo = true; comments = "hello" }},
		{"deniable", "pw-6", 0, func() { deniability = true }},
		{"deniable+keyfile", "pw-7", 1, func() { deniability = true }},
		{"deniable+rs+split", "pw-8", 0, func() { deniability = true; reedsolo = true; split = true; splitSize = "2"; splitSelected = 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "f.bin")
			data := randBytes(t, 70000)
			writeFile(t, in, data)
			var kf []string
			for i := 0; i < c.nkf; i++ {
				p := filepath.Join(dir, "k"+string(rune('0'+i))+".key")
				writeFile(t, p, randBytes(t, 100))
				kf = append(kf, p)
			}
			vol, st := encrypt(t, []string{in}, c.pw, kf, c.opt)
			mustStatus(t, st, "Completed")
			os.Remove(in)
			isSplit := strings.Contains(c.name, "split")
			drop := vol
			if isSplit {
				drop = vol + ".0"
			}
			out, st := decrypt(t, drop, c.pw, kf, nil)
			mustStatus(t, st, "Completed")
			mustContent(t, out, data)
			for _, n := range listDir(t, dir) {
				if strings.HasSuffix(n, ".tmp") || strings.HasSuffix(n, ".incomplete") || (isSplit && n == "f.bin.pcv") {
					t.Fatalf("leftover %s in %v", n, listDir(t, dir))
				}
			}
		})
	}
}

func TestMultiFileZipKeepsInputs(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	writeFile(t, a, []byte("aaa"))
	writeFile(t, b, []byte("bbb"))
	vol, st := encrypt(t, []string{a, b}, "pw", nil, func() { compress = true })
	mustStatus(t, st, "Completed")
	mustContent(t, a, []byte("aaa"))
	mustContent(t, b, []byte("bbb"))
	out, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if len(zr.File) != 2 {
		t.Fatalf("zip has %d entries", len(zr.File))
	}
	mustOnly(t, dir, "a.txt", "b.txt", filepath.Base(vol), filepath.Base(out))
}

func TestWrongCredentialsMessages(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	k1, k2, k3 := filepath.Join(dir, "1.key"), filepath.Join(dir, "2.key"), filepath.Join(dir, "3.key")
	writeFile(t, in, randBytes(t, 3000))
	for _, k := range []string{k1, k2, k3} {
		writeFile(t, k, randBytes(t, 50))
	}
	vol, st := encrypt(t, []string{in}, "right", []string{k1, k2}, func() { keyfileOrdered = true })
	mustStatus(t, st, "Completed")
	os.Remove(in)

	_, st = decrypt(t, vol, "wrong", []string{k1, k2}, nil)
	mustStatus(t, st, "password is incorrect")
	_, st = decrypt(t, vol, "right", []string{k1, k3}, nil)
	mustStatus(t, st, "Incorrect keyfiles or ordering")
	_, st = decrypt(t, vol, "right", []string{k2, k1}, nil)
	mustStatus(t, st, "Incorrect keyfiles or ordering")
	_, st = decrypt(t, vol, "wrong", []string{k1, k3}, nil)
	mustStatus(t, st, "Incorrect keyfiles")
	mustOnly(t, dir, "f.bin.pcv", "1.key", "2.key", "3.key")
}

func TestDuplicateKeyfiles(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	k1, k2 := filepath.Join(dir, "1.key"), filepath.Join(dir, "2.key")
	writeFile(t, in, []byte("x"))
	writeFile(t, k1, []byte("same"))
	writeFile(t, k2, []byte("same"))
	_, st := encrypt(t, []string{in}, "pw", []string{k1, k2}, nil)
	mustStatus(t, st, "Duplicate keyfiles")
	mustOnly(t, dir, "f.bin", "1.key", "2.key")
}

func TestForceDecryptStillOutputs(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 5000))
	vol, _ := encrypt(t, []string{in}, "pw", nil, nil)
	os.Remove(in)
	flipByte(t, vol, 789+10)
	out, st := decrypt(t, vol, "pw", nil, func() { keep = true })
	mustStatus(t, st, "modified. Please be careful")
	if _, err := os.Stat(out); err != nil {
		t.Fatal("force decrypt produced no output")
	}
}

// ---------- Finding #1: failed decrypt leaves plaintext / deletes overwritten file ----------

func TestFailedDecryptCleansIncompleteAndKeepsExisting(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "doc.txt")
	writeFile(t, in, randBytes(t, 300000))
	vol, _ := encrypt(t, []string{in}, "pw", nil, nil)
	writeFile(t, in, []byte("EXISTING")) // the file the user chose to overwrite
	flipByte(t, vol, 789+1000)
	out, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "damaged or modified")
	mustContent(t, out, []byte("EXISTING"))
	mustOnly(t, dir, "doc.txt", "doc.txt.pcv")
}

// ---------- Finding #2/#3: Reed-Solomon repair on deniable and split volumes ----------

func TestRepairDeniable(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 50000)
	writeFile(t, in, data)
	vol, st := encrypt(t, []string{in}, "pw", nil, func() { deniability = true; reedsolo = true })
	mustStatus(t, st, "Completed")
	os.Remove(in)
	flipByte(t, vol, 40+789+500) // outer layer is a stream cipher: flips one inner byte
	out, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
	mustOnly(t, dir, "f.bin", "f.bin.pcv")
}

func TestRepairSplit(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 5000)
	writeFile(t, in, data)
	vol, st := encrypt(t, []string{in}, "pw", nil, func() { reedsolo = true; split = true; splitSize = "2"; splitSelected = 0 })
	mustStatus(t, st, "Completed")
	os.Remove(in)
	flipByte(t, vol+".1", 50) // (2048+50-789)%136 = 85: a data byte, not parity
	out, st := decrypt(t, vol+".1", "pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
	mustOnly(t, dir, "f.bin", "f.bin.pcv.0", "f.bin.pcv.1", "f.bin.pcv.2", "f.bin.pcv.3")
}

func TestRepairDeniableSplit(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 5000)
	writeFile(t, in, data)
	vol, st := encrypt(t, []string{in}, "pw", nil, func() { deniability = true; reedsolo = true; split = true; splitSize = "2"; splitSelected = 0 })
	mustStatus(t, st, "Completed")
	os.Remove(in)
	flipByte(t, vol+".0", 40+789+20)
	out, st := decrypt(t, vol+".0", "pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
	mustOnly(t, dir, "f.bin", "f.bin.pcv.0", "f.bin.pcv.1", "f.bin.pcv.2", "f.bin.pcv.3")
}

// ---------- Finding #4 (+ tail fragment): corrupted padding / appended bytes ----------

func TestCorruptPaddingByteRepaired(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 1000)
	writeFile(t, in, data)
	vol, _ := encrypt(t, []string{in}, "pw", nil, func() { reedsolo = true })
	os.Remove(in)
	b, _ := os.ReadFile(vol)
	b[len(b)-9] = 0xff // PKCS#7 length byte of the final RS block (valid: 24)
	writeFile(t, vol, b)
	out, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
}

func TestAppendedTailRejectedCleanly(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 1<<20))
	vol, _ := encrypt(t, []string{in}, "pw", nil, func() { reedsolo = true })
	os.Remove(in)
	f, _ := os.OpenFile(vol, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte("0123456789"))
	f.Close()
	_, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "irrecoverably damaged")
	mustOnly(t, dir, "f.bin.pcv")
}

// ---------- Finding #5: keyfile-only header forgery ----------

func TestKeyfileOnlyForgedHeaderRejected(t *testing.T) {
	dir := t.TempDir()
	in, kf := filepath.Join(dir, "s.bin"), filepath.Join(dir, "k.key")
	writeFile(t, in, randBytes(t, 5000))
	writeFile(t, kf, randBytes(t, 64))
	vol, st := encrypt(t, []string{in}, "", []string{kf}, nil)
	mustStatus(t, st, "Completed")
	os.Remove(in)
	forgeKeyfileOnlyHeader(t, vol)
	_, st = decrypt(t, vol, "", []string{kf}, nil)
	// Rejected at the header, with no output. (It's forged with the old derivation,
	// so it's reported as a v1.50/1.51 volume; either message means "not accepted".)
	if strings.Contains(st, "Completed") || !(strings.Contains(st, "tampered") || strings.Contains(st, "v1.51")) {
		t.Fatalf("forged header not rejected: %q", st)
	}
	mustOnly(t, dir, "s.bin.pcv", "k.key")
}

// ---------- Finding #6: deniable failures must not leave the unwrapped .tmp ----------

func TestDeniableFailuresLeaveNoTmp(t *testing.T) {
	dir := t.TempDir()
	in, kf := filepath.Join(dir, "f.bin"), filepath.Join(dir, "k.key")
	data := randBytes(t, 20000)
	writeFile(t, in, data)
	writeFile(t, kf, randBytes(t, 64))
	vol, _ := encrypt(t, []string{in}, "pw", []string{kf}, func() { deniability = true })
	os.Remove(in)

	// Wrong password
	_, st := decrypt(t, vol, "nope", []string{kf}, nil)
	mustStatus(t, st, "incorrect")
	mustOnly(t, dir, "f.bin.pcv", "k.key")

	// No keyfiles selected (only discoverable after unwrapping), then retry in the same UI state
	_, st = decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "requires keyfiles")
	mustOnly(t, dir, "f.bin.pcv", "k.key")
	keyfiles = []string{kf}
	fastDecode = true
	work(false)
	working = false
	mustStatus(t, mainStatus, "Completed")
	mustContent(t, filepath.Join(dir, "f.bin"), data)
}

func TestDeniableTamperedLeavesNoTmp(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 20000))
	vol, _ := encrypt(t, []string{in}, "pw", nil, func() { deniability = true })
	os.Remove(in)
	flipByte(t, vol, 40+789+100) // auth tag mismatch
	_, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "damaged or modified")
	mustOnly(t, dir, "f.bin.pcv")
}

func TestDeniableSplitWrongPasswordThenRetry(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	data := randBytes(t, 5000)
	writeFile(t, in, data)
	vol, _ := encrypt(t, []string{in}, "pw", nil, func() { deniability = true; split = true; splitSize = "2"; splitSelected = 0 })
	os.Remove(in)
	chunks := listDir(t, dir)
	_, st := decrypt(t, vol+".0", "bad", nil, nil)
	mustStatus(t, st, "incorrect")
	mustOnly(t, dir, chunks...)
	password = "pw"
	fastDecode = true
	work(false)
	working = false
	mustStatus(t, mainStatus, "Completed")
	mustContent(t, filepath.Join(dir, "f.bin"), data)
	mustOnly(t, dir, append(chunks, "f.bin")...)
}

func TestTinyFileTreatedAsDeniable(t *testing.T) {
	dir := t.TempDir()
	vol := filepath.Join(dir, "junk.pcv")
	writeFile(t, vol, randBytes(t, 20))
	_, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "too short")
	mustOnly(t, dir, "junk.pcv")
}

// ---------- Finding #7: cancelled split leaves no chunks ----------

func TestCancelledSplitLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 4<<20))
	go func() {
		deadline := time.Now().Add(60 * time.Second)
		for !strings.HasPrefix(popupStatus, "Splitting") && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		working = false
	}()
	_, st := encrypt(t, []string{in}, "pw", nil, func() { split = true; splitSize = "100"; splitSelected = 0 })
	mustStatus(t, st, "cancelled")
	mustOnly(t, dir, "f.bin")
}

// ---------- Finding #8: no self-update while working ----------

func TestApplyUpdateRefusedWhileWorking(t *testing.T) {
	setup()
	working, showProgress = true, true
	applyUpdate()
	if updateApplying {
		t.Fatal("applyUpdate started while an operation was running")
	}
	working, showProgress = false, false
}

// ---------- Compat: volumes produced by v1.51 ----------
// Password-only volumes still open; keyfile volumes are rejected with a pointer to v1.51.

func TestLegacyVolumes(t *testing.T) {
	// Volumes made by v1.51 (see testdata/legacy-v1.51/README.md)
	src := filepath.Join("testdata", "legacy-v1.51")
	dir := t.TempDir()
	for _, n := range []string{"pw.txt.pcv", "kf.txt.pcv", "pkf.txt.pcv", "kf.key", "plain.orig"} {
		b, err := os.ReadFile(filepath.Join(src, n))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, n), b)
	}
	want, _ := os.ReadFile(filepath.Join(dir, "plain.orig"))

	out, st := decrypt(t, filepath.Join(dir, "pw.txt.pcv"), "legacy-pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, want)

	kf := []string{filepath.Join(dir, "kf.key")}
	_, st = decrypt(t, filepath.Join(dir, "kf.txt.pcv"), "", kf, nil)
	mustStatus(t, st, "use ZeeCrypt v1.51")
	_, st = decrypt(t, filepath.Join(dir, "pkf.txt.pcv"), "legacy-pw", kf, nil)
	mustStatus(t, st, "use ZeeCrypt v1.51")
	_, st = decrypt(t, filepath.Join(dir, "pkf.txt.pcv"), "typo", kf, nil)
	mustStatus(t, st, "password is incorrect")
	mustOnly(t, dir, "pw.txt", "pw.txt.pcv", "kf.txt.pcv", "pkf.txt.pcv", "kf.key", "plain.orig")
}

// ---------- Review follow-ups ----------

func TestExistingTmpNotClobbered(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, randBytes(t, 3000))
	vol, _ := encrypt(t, []string{in}, "pw", nil, func() { deniability = true })
	os.Remove(in)
	writeFile(t, vol+".tmp", []byte("USERDATA"))
	_, st := decrypt(t, vol, "pw", nil, nil)
	mustStatus(t, st, "Please remove f.bin.pcv.tmp")
	mustContent(t, vol+".tmp", []byte("USERDATA"))
	mustOnly(t, dir, "f.bin.pcv", "f.bin.pcv.tmp")
}

func TestStartIgnoredWhileWorking(t *testing.T) {
	setup()
	dir := t.TempDir()
	in := filepath.Join(dir, "f.bin")
	writeFile(t, in, []byte("x"))
	onDrop([]string{in})
	waitScan()
	password, cpassword = "pw", "pw"
	working = true
	onClickStartButton() // what the Enter key does mid-operation
	working = false
	if showProgress || showOverwrite {
		t.Fatal("onClickStartButton started an operation while one was running")
	}
	mustOnly(t, dir, "f.bin")
}

func TestSplitNameWithGlobMetacharacters(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "report[1].bin")
	data := randBytes(t, 5000)
	writeFile(t, in, data)
	vol, st := encrypt(t, []string{in}, "pw", nil, func() { split = true; splitSize = "2"; splitSelected = 0 })
	mustStatus(t, st, "Completed")
	os.Remove(in)
	mustOnly(t, dir, "report[1].bin.pcv.0", "report[1].bin.pcv.1", "report[1].bin.pcv.2")
	out, st := decrypt(t, vol+".0", "pw", nil, nil)
	mustStatus(t, st, "Completed")
	mustContent(t, out, data)
}

func TestRemoveTempInputIdempotent(t *testing.T) {
	setup()
	dir := t.TempDir()
	user := filepath.Join(dir, "foo.pcv")
	writeFile(t, user, []byte("user volume"))
	rec := filepath.Join(dir, "bar.pcv")
	writeFile(t, rec, []byte("recombined"))
	mode, recombine = "decrypt", true
	inputFileOld, inputFile, recombinedFile = user, rec, rec
	removeTempInput()
	removeTempInput()
	mustOnly(t, dir, "foo.pcv")
	if inputFile != user {
		t.Fatalf("inputFile = %q", inputFile)
	}
}
