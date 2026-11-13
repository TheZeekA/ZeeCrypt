// Package volume reads and writes v3 ZeeCrypt volumes.
//
// A v3 volume encrypts its data under a random 32-byte file key. The header
// holds one or more "stanzas", each wrapping the file key for one way of
// unlocking it (a password plus optional keyfiles, a public-key recipient,
// ...), in the style of age. Data is split into chunks that are each
// authenticated, so nothing is decrypted or written before it's verified
// (this closes PCC-004, decrypt-then-verify, from the Picocrypt audit).
//
// Layout (every header field is Reed-Solomon encoded at 3x, as in v1.5x/v2):
//
//	version "v3.00"            5 -> 15
//	comments length "%05d"     5 -> 15
//	comments                   C -> 3C (one byte at a time)
//	flags                      5 -> 15  [0] paranoid [1] keyfiles [2] keyfile order [3] Reed-Solomon [4] signed
//	header block length        5 -> 15  (big-endian)
//	header block               zero-padded to 32-byte units, each 32 -> 96
//	    hkdf salt (32) | stanza count (2) | stanzas (type 1 | length 4 | body) | header MAC (32)
//	[signature block, if flags[4]: see signature.go]
//	data chunks
//
// The first four fields match the v1.5x/v2 layout, so the app can show a
// volume's comments and flags the same way for every version.
//
// Data chunk i holds up to ChunkSize bytes of plaintext (ChunkSizeRS with
// Reed-Solomon, which pads every chunk to a multiple of 128 bytes):
//
//	ciphertext = XChaCha20(Serpent-CTR(plaintext))     (Serpent in paranoid mode only)
//	tag        = MAC(i | last | ciphertext)            (keyed BLAKE2b-256, or HMAC-SHA3-256 in paranoid mode)
//	stored     = ciphertext | tag                      (with Reed-Solomon: PKCS#7-padded, then 128 -> 136)
//
// A full chunk stores exactly 1 MiB (before Reed-Solomon). The last chunk is
// the one followed by end of file; its "last" bit in the MAC stops a volume
// from being cut short at a chunk boundary without detection.
package volume

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strconv"

	"github.com/Picocrypt/infectious"
	"github.com/Picocrypt/serpent"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

const (
	Version = "v3.00"

	MiB         = 1 << 20
	tagSize     = 32
	ChunkSize   = MiB - tagSize       // plaintext bytes per chunk
	ChunkSizeRS = MiB - tagSize - 128 // with Reed-Solomon (room for the padding)

	maxComments   = 99999
	maxBlockSize  = 16 << 20
	maxStanzas    = 4096
	headerKeySize = 32
)

var (
	ErrNotV3           = errors.New("not a v3 volume")
	ErrTooShort        = errors.New("the file is too short to be a volume")
	ErrHeaderDamaged   = errors.New("the volume header is damaged")
	ErrIncorrect       = errors.New("no key opened the volume")
	ErrHeaderModified  = errors.New("the volume header was modified")
	ErrDamaged         = errors.New("the data is damaged or was modified")
	ErrCancelled       = errors.New("cancelled")
	ErrCommentsTooLong = errors.New("comments exceed 99,999 characters")
)

// Flags are the options stored in the header
type Flags struct {
	Paranoid        bool
	Keyfiles        bool
	KeyfilesOrdered bool
	ReedSolomon     bool
	Signed          bool
}

func (f Flags) bytes() []byte {
	b := make([]byte, 5)
	for i, v := range []bool{f.Paranoid, f.Keyfiles, f.KeyfilesOrdered, f.ReedSolomon, f.Signed} {
		if v {
			b[i] = 1
		}
	}
	return b
}

func flagsFrom(b []byte) Flags {
	return Flags{b[0] == 1, b[1] == 1, b[2] == 1, b[3] == 1, b[4] == 1}
}

// Stanza types
const (
	StanzaPassword  byte = 1
	StanzaRecipient byte = 2
	StanzaFIDO2     byte = 3
)

// A Stanza wraps the file key for one way of opening the volume
type Stanza struct {
	Type byte
	Body []byte
}

// Header is a parsed v3 header
type Header struct {
	Comments string
	Flags    Flags
	HKDFSalt []byte
	Stanzas  []Stanza
	MAC      []byte

	// Repaired is set if Reed-Solomon had to correct the header
	Repaired bool
	// macInput is what the header MAC covers
	macInput []byte
	// Signature block (only if Flags.Signed), still encrypted
	sigBlock []byte
	// Size is the header's length on disk, i.e. where the data starts
	Size int64
}

// A Recipient wraps the file key into a stanza
type Recipient interface {
	Wrap(fileKey []byte, flags Flags) (Stanza, error)
}

// An Identity unwraps the file key from one of the stanzas, or returns
// ErrIncorrect if none of them is for it
type Identity interface {
	Unwrap(stanzas []Stanza, flags Flags) ([]byte, error)
}

// ---------- Reed-Solomon ----------

var (
	rs1, _   = infectious.NewFEC(1, 3)
	rs5, _   = infectious.NewFEC(5, 15)
	rs32, _  = infectious.NewFEC(32, 96)
	rs128, _ = infectious.NewFEC(128, 136)
)

func rsEncode(rs *infectious.FEC, data []byte) []byte {
	res := make([]byte, rs.Total())
	rs.Encode(data, func(s infectious.Share) {
		res[s.Number] = s.Data[0]
	})
	return res
}

// rsDecode corrects 'data'. On failure it returns the uncorrected data bytes
// (the encoding is systematic) and an error.
func rsDecode(rs *infectious.FEC, data []byte) ([]byte, error) {
	shares := make([]infectious.Share, rs.Total())
	for i := range shares {
		shares[i] = infectious.Share{Number: i, Data: []byte{data[i]}}
	}
	res, err := rs.Decode(nil, shares)
	if err != nil {
		return append([]byte{}, data[:rs.Required()]...), err
	}
	return res, nil
}

// ---------- Keys ----------

type keys struct {
	header, cipher, serpent, chunkMAC []byte
}

func deriveKeys(fileKey, hkdfSalt []byte) keys {
	derive := func(info string) []byte {
		k := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.New(sha3.New256, fileKey, hkdfSalt, []byte(info)), k); err != nil {
			panic(err) // can't happen: well under HKDF's output limit
		}
		return k
	}
	return keys{
		header:   derive("zeecrypt v3 header"),
		cipher:   derive("zeecrypt v3 cipher"),
		serpent:  derive("zeecrypt v3 serpent"),
		chunkMAC: derive("zeecrypt v3 chunk mac"),
	}
}

func headerMAC(k keys, macInput []byte) []byte {
	m := hmac.New(sha3.New256, k.header)
	m.Write(macInput)
	return m.Sum(nil)
}

// ---------- Header ----------

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the OS CSPRNG never fails on supported Windows versions
	}
	return b
}

// macInput is the header MAC's message: every header field except the MAC
// itself, each length-prefixed so field boundaries can't shift
func buildMACInput(comments string, flags Flags, blockWithoutMAC []byte) []byte {
	var b bytes.Buffer
	b.WriteString(Version)
	binary.Write(&b, binary.BigEndian, uint32(len(comments)))
	b.WriteString(comments)
	b.Write(flags.bytes())
	binary.Write(&b, binary.BigEndian, uint32(len(blockWithoutMAC)))
	b.Write(blockWithoutMAC)
	return b.Bytes()
}

func encodeBlock(hkdfSalt []byte, stanzas []Stanza) []byte {
	var b bytes.Buffer
	b.Write(hkdfSalt)
	binary.Write(&b, binary.BigEndian, uint16(len(stanzas)))
	for _, s := range stanzas {
		b.WriteByte(s.Type)
		binary.Write(&b, binary.BigEndian, uint32(len(s.Body)))
		b.Write(s.Body)
	}
	return b.Bytes()
}

func parseBlock(block []byte) (hkdfSalt []byte, stanzas []Stanza, mac []byte, err error) {
	if len(block) < 32+2+32 {
		return nil, nil, nil, ErrHeaderDamaged
	}
	mac = block[len(block)-32:]
	block = block[:len(block)-32]
	hkdfSalt = block[:32]
	count := int(binary.BigEndian.Uint16(block[32:34]))
	rest := block[34:]
	if count > maxStanzas {
		return nil, nil, nil, ErrHeaderDamaged
	}
	for i := 0; i < count; i++ {
		if len(rest) < 5 {
			return nil, nil, nil, ErrHeaderDamaged
		}
		t := rest[0]
		n := binary.BigEndian.Uint32(rest[1:5])
		rest = rest[5:]
		if uint64(n) > uint64(len(rest)) {
			return nil, nil, nil, ErrHeaderDamaged
		}
		stanzas = append(stanzas, Stanza{Type: t, Body: rest[:n]})
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return nil, nil, nil, ErrHeaderDamaged
	}
	return hkdfSalt, stanzas, mac, nil
}

// writeHeader writes everything up to the data (and the signature block's
// placeholder, if signing). It returns the header MAC.
func writeHeader(w io.Writer, comments string, flags Flags, hkdfSalt []byte, stanzas []Stanza, k keys) ([]byte, error) {
	if len(comments) > maxComments {
		return nil, ErrCommentsTooLong
	}
	var b bytes.Buffer
	b.Write(rsEncode(rs5, []byte(Version)))
	b.Write(rsEncode(rs5, []byte(fmt.Sprintf("%05d", len(comments)))))
	for i := 0; i < len(comments); i++ {
		b.Write(rsEncode(rs1, []byte{comments[i]}))
	}
	b.Write(rsEncode(rs5, flags.bytes()))

	body := encodeBlock(hkdfSalt, stanzas)
	mac := headerMAC(k, buildMACInput(comments, flags, body))
	block := append(body, mac...)
	if len(block) > maxBlockSize {
		return nil, errors.New("too many recipients")
	}
	length := make([]byte, 8)
	binary.BigEndian.PutUint64(length, uint64(len(block)))
	b.Write(rsEncode(rs5, length[3:]))
	for i := 0; i < len(block); i += 32 {
		unit := make([]byte, 32)
		copy(unit, block[i:])
		b.Write(rsEncode(rs32, unit))
	}
	if flags.Signed {
		b.Write(make([]byte, sigBlockEncodedSize))
	}
	_, err := w.Write(b.Bytes())
	return mac, err
}

var versionRegex = regexp.MustCompile(`^v3\.\d{2}$`)

// IsV3 reports whether the first 15 bytes of a file are a v3 version field
// (Reed-Solomon corrected if possible)
func IsV3(first15 []byte) bool {
	if len(first15) < 15 {
		return false
	}
	v, _ := rsDecode(rs5, first15[:15])
	return versionRegex.Match(v)
}

// ReadHeader reads and parses a v3 header without any keys (the stanzas and
// MAC are not checked). With 'force', uncorrectable Reed-Solomon errors are
// ignored and the raw bytes used.
func ReadHeader(r io.Reader, force bool) (*Header, error) {
	h := &Header{}
	var size int64
	field := func(rs *infectious.FEC, n int) ([]byte, error) {
		raw := make([]byte, n)
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, ErrTooShort
		}
		size += int64(n)
		var out []byte
		for i := 0; i < n; i += rs.Total() {
			d, err := rsDecode(rs, raw[i:i+rs.Total()])
			if err != nil {
				if !force {
					return nil, ErrHeaderDamaged
				}
				h.Repaired = true // best effort
			} else if !bytes.Equal(d, raw[i:i+rs.Required()]) {
				h.Repaired = true
			}
			out = append(out, d...)
		}
		return out, nil
	}

	v, err := field(rs5, 15)
	if err != nil {
		return nil, err
	}
	if !versionRegex.Match(v) {
		return nil, ErrNotV3
	}
	if string(v) != Version {
		return nil, fmt.Errorf("volume format %s needs a newer ZeeCrypt", v)
	}
	cl, err := field(rs5, 15)
	if err != nil {
		return nil, err
	}
	commentsLen, err := strconv.Atoi(string(cl))
	if err != nil || commentsLen < 0 || commentsLen > maxComments {
		return nil, ErrHeaderDamaged
	}
	c, err := field(rs1, commentsLen*3)
	if err != nil {
		return nil, err
	}
	h.Comments = string(c)
	f, err := field(rs5, 15)
	if err != nil {
		return nil, err
	}
	for _, x := range f {
		if x > 1 {
			return nil, ErrHeaderDamaged
		}
	}
	h.Flags = flagsFrom(f)
	l, err := field(rs5, 15)
	if err != nil {
		return nil, err
	}
	blockLen := int(binary.BigEndian.Uint64(append(make([]byte, 3), l...)))
	if blockLen > maxBlockSize || blockLen < 66 {
		return nil, ErrHeaderDamaged
	}
	units := (blockLen + 31) / 32
	block, err := field(rs32, units*96)
	if err != nil {
		return nil, err
	}
	block = block[:blockLen]
	h.HKDFSalt, h.Stanzas, h.MAC, err = parseBlock(block)
	if err != nil {
		return nil, err
	}
	h.macInput = buildMACInput(h.Comments, h.Flags, block[:blockLen-32])
	if h.Flags.Signed {
		raw := make([]byte, sigBlockEncodedSize)
		if _, err := io.ReadFull(r, raw); err != nil {
			return nil, ErrTooShort
		}
		size += sigBlockEncodedSize
		h.sigBlock = raw
	}
	h.Size = size
	return h, nil
}

// ---------- Data ----------

type chunkCipher struct {
	k        keys
	paranoid bool
	serpent  cipher.Block
}

func newChunkCipher(k keys, paranoid bool) *chunkCipher {
	c := &chunkCipher{k: k, paranoid: paranoid}
	if paranoid {
		s, err := serpent.NewCipher(k.serpent)
		if err != nil {
			panic(err)
		}
		c.serpent = s
	}
	return c
}

// xor applies the keystream for chunk i (the same operation both ways)
func (c *chunkCipher) xor(i uint64, dst, src []byte) {
	nonce := make([]byte, 24)
	binary.BigEndian.PutUint64(nonce[16:], i)
	if c.paranoid {
		iv := make([]byte, 16)
		binary.BigEndian.PutUint64(iv, i)
		cipher.NewCTR(c.serpent, iv).XORKeyStream(dst, src)
		src = dst
	}
	ch, err := chacha20.NewUnauthenticatedCipher(c.k.cipher, nonce)
	if err != nil {
		panic(err)
	}
	ch.XORKeyStream(dst, src)
}

func (c *chunkCipher) tag(i uint64, last bool, ciphertext []byte) []byte {
	var m hash.Hash
	if c.paranoid {
		m = hmac.New(sha3.New256, c.k.chunkMAC)
	} else {
		var err error
		if m, err = blake2b.New256(c.k.chunkMAC); err != nil {
			panic(err)
		}
	}
	var prefix [9]byte
	binary.BigEndian.PutUint64(prefix[:8], i)
	if last {
		prefix[8] = 1
	}
	m.Write(prefix[:])
	m.Write(ciphertext)
	return m.Sum(nil)
}

func pad(data []byte) []byte {
	n := 128 - len(data)%128
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...)
}

func unpad(data []byte) ([]byte, bool) {
	if len(data) == 0 || len(data)%128 != 0 {
		return nil, false
	}
	n := int(data[len(data)-1])
	if n < 1 || n > 128 {
		return nil, false
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, false
		}
	}
	return data[:len(data)-n], true
}

func rsEncodeChunk(data []byte) []byte {
	out := make([]byte, 0, len(data)/128*136)
	for i := 0; i < len(data); i += 128 {
		out = append(out, rsEncode(rs128, data[i:i+128])...)
	}
	return out
}

// rsChunkData returns a stored chunk's data bytes: just the systematic
// bytes when 'repair' is false (fast), or Reed-Solomon corrected
func rsChunkData(stored []byte, repair bool) []byte {
	out := make([]byte, 0, len(stored)/136*128)
	for i := 0; i < len(stored); i += 136 {
		if repair {
			d, _ := rsDecode(rs128, stored[i:i+136])
			out = append(out, d...)
		} else {
			out = append(out, stored[i:i+128]...)
		}
	}
	return out
}

// storedChunkSize is a full chunk's size on disk
func storedChunkSize(reedSolomon bool) int {
	if reedSolomon {
		return MiB / 128 * 136
	}
	return MiB
}

// ---------- Encrypt ----------

// EncryptOptions configures Encrypt
type EncryptOptions struct {
	Comments string
	Flags    Flags
	// Signer signs the volume (sets Flags.Signed); see signature.go
	Signer *Signer
	// Progress is called with the plaintext bytes processed so far
	Progress func(done int64)
	// Cancelled is polled between chunks
	Cancelled func() bool
}

// Encrypt writes a v3 volume of r's contents to w. With a Signer, w must be
// an io.WriteSeeker (the signature is filled in at the end).
func Encrypt(w io.Writer, r io.Reader, recipients []Recipient, opts EncryptOptions) error {
	if len(recipients) == 0 {
		return errors.New("no recipients")
	}
	flags := opts.Flags
	flags.Signed = opts.Signer != nil
	var ws io.WriteSeeker
	var start int64
	if flags.Signed {
		var ok bool
		if ws, ok = w.(io.WriteSeeker); !ok {
			return errors.New("signing needs a seekable output")
		}
		var err error
		if start, err = ws.Seek(0, io.SeekCurrent); err != nil {
			return err
		}
	}

	fileKey := randBytes(32)
	hkdfSalt := randBytes(32)
	var stanzas []Stanza
	for _, rc := range recipients {
		s, err := rc.Wrap(fileKey, flags)
		if err != nil {
			return err
		}
		stanzas = append(stanzas, s)
	}
	k := deriveKeys(fileKey, hkdfSalt)
	mac, err := writeHeader(w, opts.Comments, flags, hkdfSalt, stanzas, k)
	if err != nil {
		return err
	}

	cc := newChunkCipher(k, flags.Paranoid)
	tags := newTagHasher()
	in := bufio.NewReaderSize(r, 64*1024)
	plainSize := ChunkSize
	if flags.ReedSolomon {
		plainSize = ChunkSizeRS
	}
	buf := make([]byte, plainSize)
	var done int64
	for i := uint64(0); ; i++ {
		if opts.Cancelled != nil && opts.Cancelled() {
			return ErrCancelled
		}
		n, err := io.ReadFull(in, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		last := n < plainSize
		if !last {
			if _, err := in.Peek(1); err == io.EOF {
				last = true
			} else if err != nil {
				return err
			}
		}
		stored := make([]byte, n, n+tagSize+128)
		cc.xor(i, stored, buf[:n])
		t := cc.tag(i, last, stored)
		tags.add(t)
		stored = append(stored, t...)
		if flags.ReedSolomon {
			stored = pad(stored) // every chunk, so a full last chunk fits in a full chunk
			stored = rsEncodeChunk(stored)
		}
		if _, err := w.Write(stored); err != nil {
			return err
		}
		done += int64(n)
		if opts.Progress != nil {
			opts.Progress(done)
		}
		if last {
			break
		}
	}

	if flags.Signed {
		block, err := opts.Signer.sign(k, mac, tags.sum(), stanzas)
		if err != nil {
			return err
		}
		end, err := ws.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		if _, err := ws.Seek(start+sigBlockOffset(opts.Comments, flags, hkdfSalt, stanzas), io.SeekStart); err != nil {
			return err
		}
		if _, err := ws.Write(block); err != nil {
			return err
		}
		if _, err := ws.Seek(end, io.SeekStart); err != nil {
			return err
		}
	}
	return nil
}

// sigBlockOffset is where the signature block starts, relative to the
// start of the volume
func sigBlockOffset(comments string, flags Flags, hkdfSalt []byte, stanzas []Stanza) int64 {
	blockLen := len(encodeBlock(hkdfSalt, stanzas)) + 32
	return int64(15+15+3*len(comments)+15+15) + int64((blockLen+31)/32*96)
}

// ---------- Decrypt ----------

// DecryptOptions configures Decrypt
type DecryptOptions struct {
	// Force writes data that fails authentication instead of stopping
	Force bool
	// TrustedSigners names known signing keys for the result's signature
	// status; see signature.go
	TrustedSigners []TrustedSigner
	// Progress is called with the volume bytes read so far (header included)
	Progress  func(done int64)
	Cancelled func() bool
}

// Result describes a decrypted volume
type Result struct {
	Header *Header
	// Damaged is set when Force let unauthenticated data through
	Damaged bool
	// Repaired is set when Reed-Solomon corrected anything
	Repaired bool
	// Signature is the sender's signature status (signature.go)
	Signature SignatureStatus
}

// Unlock reads the header and finds the file key, without decrypting
// anything. It returns the header and the keys for decryptData.
func unlock(r io.Reader, ids []Identity, force bool) (*Header, keys, error) {
	h, err := ReadHeader(r, force)
	if err != nil {
		return nil, keys{}, err
	}
	var fileKey []byte
	for _, id := range ids {
		fk, err := id.Unwrap(h.Stanzas, h.Flags)
		if err == nil {
			fileKey = fk
			break
		}
		if !errors.Is(err, ErrIncorrect) {
			return h, keys{}, err
		}
	}
	if fileKey == nil {
		return h, keys{}, ErrIncorrect
	}
	k := deriveKeys(fileKey, h.HKDFSalt)
	if subtle.ConstantTimeCompare(headerMAC(k, h.macInput), h.MAC) != 1 {
		if !force {
			return h, keys{}, ErrHeaderModified
		}
	}
	return h, k, nil
}

// Decrypt decrypts the v3 volume in r to w. Every chunk is authenticated
// before it's decrypted and written, so w never receives unverified data
// (unless opts.Force is set).
func Decrypt(w io.Writer, r io.Reader, ids []Identity, opts DecryptOptions) (Result, error) {
	h, k, err := unlock(r, ids, opts.Force)
	res := Result{Header: h}
	if err != nil {
		return res, err
	}
	res.Repaired = h.Repaired
	if subtle.ConstantTimeCompare(headerMAC(k, h.macInput), h.MAC) != 1 {
		res.Damaged = true // only reachable with Force
	}

	cc := newChunkCipher(k, h.Flags.Paranoid)
	tags := newTagHasher()
	in := bufio.NewReaderSize(r, 64*1024)
	full := storedChunkSize(h.Flags.ReedSolomon)
	buf := make([]byte, full)
	done := h.Size
	for i := uint64(0); ; i++ {
		if opts.Cancelled != nil && opts.Cancelled() {
			return res, ErrCancelled
		}
		n, err := io.ReadFull(in, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return res, err
		}
		last := n < full
		if !last {
			if _, err := in.Peek(1); err == io.EOF {
				last = true
			} else if err != nil {
				return res, err
			}
		}
		if n == 0 && i > 0 {
			// A chunk ended exactly at end of file without being marked last
			if !opts.Force {
				return res, ErrDamaged
			}
			res.Damaged = true
			break
		}

		plain, tag, ok, repaired := openChunk(cc, i, last, buf[:n], h.Flags.ReedSolomon)
		if repaired {
			res.Repaired = true
		}
		tags.add(tag)
		if !ok {
			if !opts.Force {
				return res, ErrDamaged
			}
			res.Damaged = true
		}
		if _, err := w.Write(plain); err != nil {
			return res, err
		}
		done += int64(n)
		if opts.Progress != nil {
			opts.Progress(done)
		}
		if last {
			break
		}
	}

	res.Signature = checkSignature(h, k, tags.sum(), opts.TrustedSigners)
	return res, nil
}

// openChunk verifies and decrypts one stored chunk. With Reed-Solomon it
// first tries the bytes as stored, and repairs them only if that fails.
// If verification fails, 'plain' is still the best-effort decryption.
func openChunk(cc *chunkCipher, i uint64, last bool, stored []byte, reedSolomon bool) (plain, tag []byte, ok, repaired bool) {
	try := func(data []byte) ([]byte, []byte, bool) {
		if len(data) < tagSize {
			return nil, nil, false
		}
		ct, t := data[:len(data)-tagSize], data[len(data)-tagSize:]
		good := hmac.Equal(cc.tag(i, last, ct), t)
		p := make([]byte, len(ct))
		if good {
			cc.xor(i, p, ct)
		}
		return p, t, good
	}

	if !reedSolomon {
		plain, tag, ok = try(stored)
		if !ok && len(stored) >= tagSize {
			ct := stored[:len(stored)-tagSize]
			plain = make([]byte, len(ct))
			cc.xor(i, plain, ct)
		}
		return plain, tag, ok, false
	}
	if len(stored)%136 != 0 || len(stored) == 0 {
		return nil, nil, false, false
	}
	for _, repair := range []bool{false, true} {
		data, good := unpad(rsChunkData(stored, repair)) // every chunk is padded
		if !good {
			continue
		}
		if p, t, good := try(data); good {
			return p, t, true, repair
		}
	}
	// Best effort for Force: repaired bytes, decrypted unverified
	data := rsChunkData(stored, true)
	if d, good := unpad(data); good {
		data = d
	}
	if len(data) < tagSize {
		return nil, nil, false, true
	}
	ct := data[:len(data)-tagSize]
	plain = make([]byte, len(ct))
	cc.xor(i, plain, ct)
	return plain, data[len(data)-tagSize:], false, true
}
