package main

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParseArgs(t *testing.T) {
	cases := []struct {
		args  []string
		mode  string
		paths []string
	}{
		{nil, "", nil},
		{[]string{`C:\a b\x.txt`}, "", []string{`C:\a b\x.txt`}},
		{[]string{"--encrypt", "--", `C:\x.pcv`}, "encrypt", []string{`C:\x.pcv`}},
		{[]string{"--decrypt", "--", `C:\x.pcv`}, "decrypt", []string{`C:\x.pcv`}},
		{[]string{"-x.txt"}, "", []string{"-x.txt"}},                        // dash names are paths
		{[]string{"--", "--encrypt"}, "", []string{"--encrypt"}},            // after "--" everything is a path
		{[]string{"--bogus", "a"}, "", []string{"--bogus", "a"}},            // unknown options are paths
		{[]string{"--encrypt", "--decrypt", "a"}, "decrypt", []string{"a"}}, // last one wins
		{[]string{"--encrypt", "--", "a", "--", "b"}, "encrypt", []string{"a", "--", "b"}},
	}
	for _, c := range cases {
		r := parseArgs(c.args)
		if r.mode != c.mode || !reflect.DeepEqual(r.paths, c.paths) {
			t.Errorf("parseArgs(%q) = %q %q, want %q %q", c.args, r.mode, r.paths, c.mode, c.paths)
		}
	}
}

func TestRequestEncoding(t *testing.T) {
	for _, r := range []launchRequest{
		{},
		{mode: "encrypt", paths: []string{`C:\a b\é.txt`, `D:\x`}},
		{mode: "decrypt", paths: []string{`C:\v.pcv`}},
	} {
		got, err := decodeRequest(encodeRequest(r))
		if err != nil || got.mode != r.mode || !reflect.DeepEqual(got.paths, r.paths) {
			t.Errorf("round trip of %+v gave %+v, %v", r, got, err)
		}
	}
	for _, bad := range []string{"format\x00C:\\x", "encrypt\x00\x00C:\\x", "encrypt\x00"} {
		if _, err := decodeRequest([]byte(bad)); err == nil {
			t.Errorf("decodeRequest(%q) accepted", bad)
		}
	}
}

func TestMergeRequests(t *testing.T) {
	got := mergeRequests([]launchRequest{
		{mode: "encrypt", paths: []string{`C:\a`}},
		{mode: "encrypt", paths: []string{`C:\b`, `c:\A`}}, // duplicate (case-insensitive)
	})
	if got.mode != "encrypt" || !reflect.DeepEqual(got.paths, []string{`C:\a`, `C:\b`}) {
		t.Errorf("merge = %+v", got)
	}
	// A different verb later in the burst replaces what came before it
	got = mergeRequests([]launchRequest{
		{mode: "encrypt", paths: []string{`C:\a`}},
		{mode: "decrypt", paths: []string{`C:\v.pcv`}},
	})
	if got.mode != "decrypt" || !reflect.DeepEqual(got.paths, []string{`C:\v.pcv`}) {
		t.Errorf("merge across modes = %+v", got)
	}
}

func TestBatchRequests(t *testing.T) {
	in := make(chan launchRequest, 8)
	out := make(chan launchRequest, 8)
	go batchRequests(in, 100*time.Millisecond, func(r launchRequest) { out <- r })
	in <- launchRequest{paths: []string{"a"}}
	in <- launchRequest{paths: []string{"b"}}
	first := <-out
	if !reflect.DeepEqual(first.paths, []string{"a", "b"}) {
		t.Fatalf("first batch = %q", first.paths)
	}
	in <- launchRequest{paths: []string{"c"}}
	if second := <-out; !reflect.DeepEqual(second.paths, []string{"c"}) {
		t.Fatalf("second batch = %q", second.paths)
	}
	close(in)
}

func TestPipeForwarding(t *testing.T) {
	base, err := instancePipeName()
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("%s-test-%d", base, time.Now().UnixNano())
	h, err := listenInstance(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := listenInstance(name); err != errInstanceRunning {
		t.Fatalf("second listen: %v, want errInstanceRunning", err)
	}
	got := make(chan launchRequest, 4)
	go serveInstance(h, got)

	want := []launchRequest{
		{mode: "encrypt", paths: []string{`C:\one two\a.txt`}},
		{mode: "", paths: []string{`C:\b.pcv`, `C:\c`}},
	}
	for _, r := range want {
		if err := forwardToInstance(name, r); err != nil {
			t.Fatal(err)
		}
	}
	for _, w := range want {
		select {
		case r := <-got:
			if r.mode != w.mode || !reflect.DeepEqual(r.paths, w.paths) {
				t.Errorf("received %+v, want %+v", r, w)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("request not received")
		}
	}
}

func TestForcedEncryptOnVolume(t *testing.T) {
	setup()
	dir := t.TempDir()
	v := filepath.Join(dir, "x.pcv")
	writeFile(t, v, []byte("pretend volume"))
	onDropMode([]string{v}, "encrypt")
	waitScan()
	if mode != "encrypt" || outputFile != v+".pcv" {
		t.Fatalf("mode=%q output=%q", mode, outputFile)
	}
	if forcedMode != "" {
		t.Fatal("forcedMode not cleared")
	}
}

func TestForcedDecryptRejectsNonVolumes(t *testing.T) {
	setup()
	dir := t.TempDir()
	f := filepath.Join(dir, "x.txt")
	writeFile(t, f, []byte("x"))
	for _, c := range []struct {
		names []string
		msg   string
	}{
		{[]string{f}, "Not a ZeeCrypt volume"},
		{[]string{dir}, "Not a ZeeCrypt volume"},
		{[]string{f, f + ".pcv"}, "Select one volume to decrypt"},
	} {
		onDropMode(c.names, "decrypt")
		waitScan()
		if mode != "" || mainStatus != c.msg {
			t.Errorf("%q: mode=%q status=%q", c.names, mode, mainStatus)
		}
	}
}

func TestForcedDecryptOpensVolume(t *testing.T) {
	setup()
	dir := t.TempDir()
	f := filepath.Join(dir, "x.txt")
	writeFile(t, f, []byte("hello"))
	onDrop([]string{f})
	waitScan()
	password = "pw"
	work(false)
	onDropMode([]string{f + ".pcv"}, "decrypt")
	waitScan()
	if mode != "decrypt" || outputFile != f {
		t.Fatalf("mode=%q output=%q", mode, outputFile)
	}
}
