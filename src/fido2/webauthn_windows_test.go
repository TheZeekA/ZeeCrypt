package fido2

import (
	"testing"
	"unsafe"
)

// The Go structs must match webauthn.h's x64 layout exactly, or Windows
// reads garbage. Expected sizes are worked out from the C definitions
// (DWORD/BOOL/LONG = 4 bytes, pointers = 8, natural alignment).
func TestStructLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("layouts checked for 64-bit Windows")
	}
	for name, c := range map[string]struct{ got, want uintptr }{
		"WEBAUTHN_RP_ENTITY_INFORMATION":                 {unsafe.Sizeof(rpEntityInformation{}), 32},
		"WEBAUTHN_USER_ENTITY_INFORMATION":               {unsafe.Sizeof(userEntityInformation{}), 40},
		"WEBAUTHN_CLIENT_DATA":                           {unsafe.Sizeof(clientData{}), 24},
		"WEBAUTHN_COSE_CREDENTIAL_PARAMETER":             {unsafe.Sizeof(coseCredentialParameter{}), 24},
		"WEBAUTHN_COSE_CREDENTIAL_PARAMETERS":            {unsafe.Sizeof(coseCredentialParameters{}), 16},
		"WEBAUTHN_CREDENTIAL":                            {unsafe.Sizeof(credential{}), 24},
		"WEBAUTHN_CREDENTIALS":                           {unsafe.Sizeof(credentials{}), 16},
		"WEBAUTHN_EXTENSION":                             {unsafe.Sizeof(extension{}), 24},
		"WEBAUTHN_EXTENSIONS":                            {unsafe.Sizeof(extensions{}), 16},
		"WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS": {unsafe.Sizeof(makeCredentialOptions{}), 96},
		"WEBAUTHN_HMAC_SECRET_SALT":                      {unsafe.Sizeof(hmacSecretSalt{}), 32},
		"WEBAUTHN_HMAC_SECRET_SALT_VALUES":               {unsafe.Sizeof(hmacSecretSaltValues{}), 24},
		"WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS":   {unsafe.Sizeof(getAssertionOptions{}), 120},
		"WEBAUTHN_CREDENTIAL_ATTESTATION (to cred ID)":   {unsafe.Sizeof(credentialAttestation{}), 96},
		"WEBAUTHN_ASSERTION (to pHmacSecret)":            {unsafe.Sizeof(assertion{}), 120},
	} {
		if c.got != c.want {
			t.Errorf("%s: %d bytes, want %d", name, c.got, c.want)
		}
	}
	// Offsets of the fields read back or set past the start
	for name, c := range map[string]struct{ got, want uintptr }{
		"get options pHmacSecretSaltValues":   {unsafe.Offsetof(getAssertionOptions{}.pHmacSecretSaltValues), 104},
		"get options pAllowCredentialList":    {unsafe.Offsetof(getAssertionOptions{}.pAllowCredentialList), 80},
		"make options pExcludeCredentialList": {unsafe.Offsetof(makeCredentialOptions{}.pExcludeCredentialList), 72},
		"attestation pbCredentialId":          {unsafe.Offsetof(credentialAttestation{}.pbCredentialId), 88},
		"assertion Credential":                {unsafe.Offsetof(assertion{}.Credential), 32},
		"assertion pHmacSecret":               {unsafe.Offsetof(assertion{}.pHmacSecret), 112},
	} {
		if c.got != c.want {
			t.Errorf("%s at %d, want %d", name, c.got, c.want)
		}
	}
}

func TestAvailableDoesNotCrash(t *testing.T) {
	// Only checks that loading webauthn.dll and asking its version works
	_ = Available()
}
