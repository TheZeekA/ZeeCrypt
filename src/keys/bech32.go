package keys

// Bech32 (BIP 173) without the 90-character limit, as age uses for its keys:
// a checksum that catches typos, and a case-insensitive alphabet without
// look-alike characters.

import (
	"errors"
	"strings"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var generator = []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	h := strings.ToLower(hrp)
	var ret []byte
	for _, c := range h {
		ret = append(ret, byte(c>>5))
	}
	ret = append(ret, 0)
	for _, c := range h {
		ret = append(ret, byte(c&31))
	}
	return ret
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var ret []byte
	acc, bits := uint32(0), uint(0)
	maxv := byte(1<<to - 1)
	for _, b := range data {
		if b>>from != 0 {
			return nil, errors.New("invalid data range")
		}
		acc = acc<<from | uint32(b)
		bits += from
		for bits >= to {
			bits -= to
			ret = append(ret, byte(acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte(acc<<(to-bits))&maxv)
		}
	} else if bits >= from || byte(acc<<(to-bits))&maxv != 0 {
		return nil, errors.New("invalid padding")
	}
	return ret, nil
}

// encode returns hrp + "1" + data + checksum. The case of 'hrp' decides the
// case of the result.
func encode(hrp string, data []byte) string {
	values, _ := convertBits(data, 8, 5, true)
	upper := strings.ToUpper(hrp) == hrp && strings.ToLower(hrp) != hrp
	mod := polymod(append(append(hrpExpand(hrp), values...), 0, 0, 0, 0, 0, 0)) ^ 1
	var b strings.Builder
	b.WriteString(strings.ToLower(hrp))
	b.WriteByte('1')
	for _, v := range values {
		b.WriteByte(charset[v])
	}
	for i := 0; i < 6; i++ {
		b.WriteByte(charset[(mod>>uint(5*(5-i)))&31])
	}
	if upper {
		return strings.ToUpper(b.String())
	}
	return b.String()
}

// decode checks the checksum and returns the (lowercase) hrp and the data
func decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("mixed case")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndex(s, "1")
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("malformed key")
	}
	hrp := s[:pos]
	for _, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, errors.New("malformed key")
		}
	}
	var values []byte
	for _, c := range s[pos+1:] {
		i := strings.IndexRune(charset, c)
		if i < 0 {
			return "", nil, errors.New("invalid character in key")
		}
		values = append(values, byte(i))
	}
	if polymod(append(hrpExpand(hrp), values...)) != 1 {
		return "", nil, errors.New("key checksum doesn't match (typo?)")
	}
	data, err := convertBits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}
