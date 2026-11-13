package volume

// FIDO2 security-key stanzas: a password AND a hardware key.
//
// The security key computes a secret from a per-volume salt with the FIDO2
// hmac-secret extension (WebAuthn "PRF"); the secret never leaves the key
// without a touch (and PIN). The file key is wrapped under
//
//	HKDF-SHA3-256(Argon2id(password) | keyfile key | key secret, salt = Argon2 salt,
//	              info = "zeecrypt v3 fido2 stanza")
//
// so the password alone, or the security key alone, opens nothing.
//
// Stanza body:
//
//	Argon2 salt (16) | PRF salt (32) | credential ID length (2) | credential ID | wrapped file key (48)

import (
	"encoding/binary"
	"errors"
)

// FIDO2Device talks to a security key
type FIDO2Device interface {
	// Register creates a credential on the key (asks for a touch)
	Register() (credentialID []byte, err error)
	// Secret evaluates the credential's PRF on 'salt' (asks for a touch).
	// It returns ErrNoMatchingKey if the plugged-in key doesn't hold any of
	// the credentials.
	Secret(credentialIDs [][]byte, salt []byte) (credentialID, secret []byte, err error)
}

// ErrNoMatchingKey: the security key used isn't the one the volume needs
var ErrNoMatchingKey = errors.New("this security key can't open the volume")

// FIDO2Password is a password (and keyfiles) plus a security key
type FIDO2Password struct {
	Password   []byte
	KeyfileKey []byte
	Device     FIDO2Device
}

func (p FIDO2Password) Wrap(fileKey []byte, flags Flags) (Stanza, error) {
	credID, err := p.Device.Register()
	if err != nil {
		return Stanza{}, err
	}
	if len(credID) == 0 || len(credID) > 1023 {
		return Stanza{}, errors.New("the security key returned an unusable credential")
	}
	prfSalt := randBytes(32)
	_, secret, err := p.Device.Secret([][]byte{credID}, prfSalt)
	if err != nil {
		return Stanza{}, err
	}
	argonSalt := randBytes(16)
	k := Password{Password: p.Password, KeyfileKey: p.KeyfileKey, Extra: secret}.wrapKey(argonSalt, flags.Paranoid, "zeecrypt v3 fido2 stanza")
	body := append(append([]byte{}, argonSalt...), prfSalt...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(credID)))
	body = append(body, credID...)
	body = append(body, seal(k, fileKey, StanzaFIDO2)...)
	return Stanza{Type: StanzaFIDO2, Body: body}, nil
}

type fido2Stanza struct {
	argonSalt, prfSalt, credID, wrapped []byte
}

func parseFIDO2(body []byte) (fido2Stanza, bool) {
	if len(body) < 16+32+2 {
		return fido2Stanza{}, false
	}
	n := int(binary.BigEndian.Uint16(body[48:50]))
	if len(body) != 50+n+48 || n == 0 {
		return fido2Stanza{}, false
	}
	return fido2Stanza{body[:16], body[16:48], body[50 : 50+n], body[50+n:]}, true
}

// FIDO2Stanzas reports whether any stanza needs a security key
func FIDO2Stanzas(stanzas []Stanza) bool {
	for _, s := range stanzas {
		if s.Type == StanzaFIDO2 {
			return true
		}
	}
	return false
}

func (p FIDO2Password) Unwrap(stanzas []Stanza, flags Flags) ([]byte, error) {
	var parsed []fido2Stanza
	for _, s := range stanzas {
		if s.Type != StanzaFIDO2 {
			continue
		}
		if f, ok := parseFIDO2(s.Body); ok {
			parsed = append(parsed, f)
		}
	}
	if len(parsed) == 0 {
		return nil, ErrIncorrect
	}
	// One touch: the key reports which of the volume's credentials it holds.
	// Each stanza has its own PRF salt, so ask stanza by stanza (one
	// credential each) when there are several.
	for _, f := range parsed {
		credID, secret, err := p.Device.Secret([][]byte{f.credID}, f.prfSalt)
		if errors.Is(err, ErrNoMatchingKey) {
			continue
		}
		if err != nil {
			return nil, err
		}
		_ = credID
		k := Password{Password: p.Password, KeyfileKey: p.KeyfileKey, Extra: secret}.wrapKey(f.argonSalt, flags.Paranoid, "zeecrypt v3 fido2 stanza")
		if fk, ok := open(k, f.wrapped, StanzaFIDO2); ok {
			return fk, nil
		}
		return nil, ErrIncorrect // right key, wrong password
	}
	return nil, ErrNoMatchingKey
}
