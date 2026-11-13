// Package fido2 uses FIDO2 security keys through the Windows WebAuthn API
// (webauthn.dll, built into Windows 10 1903+), which shows the system's own
// "touch your security key" and PIN prompts. No drivers, admin rights or
// vendor software are needed.
//
// It implements volume.FIDO2Device with the hmac-secret extension (WebAuthn
// PRF). Windows hashes each salt as a PRF input before it reaches the key,
// so the secret is HMAC(credential secret, SHA-256("WebAuthn PRF" | 0 | salt)).
//
// User verification (PIN or fingerprint) is always required: a key derives
// a different hmac-secret with and without it, so making it optional would
// lock volumes out if a PIN is added to the key later.
package fido2

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"ZeeCrypt/volume"

	"golang.org/x/sys/windows"
)

// The relying party ID: an identifier for ZeeCrypt credentials on the key
// (shown in some key-management tools), not a website
const rpID = "zeecrypt.app"

var (
	webauthn                        = syscall.NewLazyDLL("webauthn.dll")
	procGetApiVersionNumber         = webauthn.NewProc("WebAuthNGetApiVersionNumber")
	procAuthenticatorMakeCredential = webauthn.NewProc("WebAuthNAuthenticatorMakeCredential")
	procAuthenticatorGetAssertion   = webauthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procFreeCredentialAttestation   = webauthn.NewProc("WebAuthNFreeCredentialAttestation")
	procFreeAssertion               = webauthn.NewProc("WebAuthNFreeAssertion")
	procGetErrorName                = webauthn.NewProc("WebAuthNGetErrorName")
)

// The structs below mirror webauthn.h field for field (x64 layout; the
// sizes are checked in webauthn_windows_test.go)

type rpEntityInformation struct {
	dwVersion uint32
	pwszId    *uint16
	pwszName  *uint16
	pwszIcon  *uint16
}

type userEntityInformation struct {
	dwVersion       uint32
	cbId            uint32
	pbId            *byte
	pwszName        *uint16
	pwszIcon        *uint16
	pwszDisplayName *uint16
}

type clientData struct {
	dwVersion        uint32
	cbClientDataJSON uint32
	pbClientDataJSON *byte
	pwszHashAlgId    *uint16
}

type coseCredentialParameter struct {
	dwVersion          uint32
	pwszCredentialType *uint16
	lAlg               int32
}

type coseCredentialParameters struct {
	cCredentialParameters uint32
	pCredentialParameters *coseCredentialParameter
}

type credential struct {
	dwVersion          uint32
	cbId               uint32
	pbId               *byte
	pwszCredentialType *uint16
}

type credentials struct {
	cCredentials uint32
	pCredentials *credential
}

type extension struct {
	pwszExtensionIdentifier *uint16
	cbExtension             uint32
	pvExtension             unsafe.Pointer
}

type extensions struct {
	cExtensions uint32
	pExtensions *extension
}

// WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, up to version 4
type makeCredentialOptions struct {
	dwVersion                         uint32
	dwTimeoutMilliseconds             uint32
	CredentialList                    credentials
	Extensions                        extensions
	dwAuthenticatorAttachment         uint32
	bRequireResidentKey               int32
	dwUserVerificationRequirement     uint32
	dwAttestationConveyancePreference uint32
	dwFlags                           uint32
	pCancellationId                   unsafe.Pointer // v2
	pExcludeCredentialList            unsafe.Pointer // v3
	dwEnterpriseAttestation           uint32         // v4
	dwLargeBlobSupport                uint32
	bPreferResidentKey                int32
}

type hmacSecretSalt struct {
	cbFirst  uint32
	pbFirst  *byte
	cbSecond uint32
	pbSecond *byte
}

type hmacSecretSaltValues struct {
	pGlobalHmacSalt             *hmacSecretSalt
	cCredWithHmacSecretSaltList uint32
	pCredWithHmacSecretSaltList unsafe.Pointer
}

// WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, up to version 6
type getAssertionOptions struct {
	dwVersion                     uint32
	dwTimeoutMilliseconds         uint32
	CredentialList                credentials
	Extensions                    extensions
	dwAuthenticatorAttachment     uint32
	dwUserVerificationRequirement uint32
	dwFlags                       uint32
	pwszU2fAppId                  *uint16        // v2
	pbU2fAppId                    *int32         // v2
	pCancellationId               unsafe.Pointer // v3
	pAllowCredentialList          unsafe.Pointer // v4
	dwCredLargeBlobOperation      uint32         // v5
	cbCredLargeBlob               uint32
	pbCredLargeBlob               *byte
	pHmacSecretSaltValues         *hmacSecretSaltValues // v6
	bBrowserInPrivateMode         int32
}

// WEBAUTHN_CREDENTIAL_ATTESTATION, the fields up to the credential ID
type credentialAttestation struct {
	dwVersion               uint32
	pwszFormatType          *uint16
	cbAuthenticatorData     uint32
	pbAuthenticatorData     *byte
	cbAttestation           uint32
	pbAttestation           *byte
	dwAttestationDecodeType uint32
	pvAttestationDecode     unsafe.Pointer
	cbAttestationObject     uint32
	pbAttestationObject     *byte
	cbCredentialId          uint32
	pbCredentialId          *byte
}

// WEBAUTHN_ASSERTION, the fields up to pHmacSecret (version 3)
type assertion struct {
	dwVersion             uint32
	cbAuthenticatorData   uint32
	pbAuthenticatorData   *byte
	cbSignature           uint32
	pbSignature           *byte
	Credential            credential
	cbUserId              uint32
	pbUserId              *byte
	Extensions            extensions // v2
	cbCredLargeBlob       uint32
	pbCredLargeBlob       *byte
	dwCredLargeBlobStatus uint32
	pHmacSecret           *hmacSecretSalt // v3
}

const (
	attachmentCrossPlatform  = 2 // security keys, not Windows Hello
	userVerificationRequired = 1
	attestationNone          = 1
	coseES256                = -7
	coseEdDSA                = -8
	hresultCancelled         = 0x800704C7 // NTE_USER_CANCELLED / ERROR_CANCELLED
	timeoutMs                = 60000
)

// minAPIVersion: hmac-secret salts in GetAssertion (options version 6)
// arrived with WebAuthn API version 4 (Windows 11 22H2)
const minAPIVersion = 4

// Available reports whether this Windows supports security-key secrets
func Available() error {
	if err := webauthn.Load(); err != nil {
		return errors.New("this version of Windows has no WebAuthn support")
	}
	v, _, _ := procGetApiVersionNumber.Call()
	if v < minAPIVersion {
		return fmt.Errorf("security keys need Windows 11 22H2 or later (WebAuthn API %d)", v)
	}
	return nil
}

func utf16(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		panic(err) // only called with constants
	}
	return p
}

func hresultError(hr uintptr) error {
	if uint32(hr) == hresultCancelled {
		return errors.New("cancelled at the security key prompt")
	}
	name := ""
	if p, _, _ := procGetErrorName.Call(hr); p != 0 {
		name = windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&p))) // a static string in webauthn.dll
	}
	if name == "NotAllowedError" {
		return volume.ErrNoMatchingKey // also: timed out, or the prompt was closed
	}
	return fmt.Errorf("security key error 0x%08X %s", uint32(hr), name)
}

// clientDataFor builds the client data the key signs. ZeeCrypt doesn't
// check WebAuthn signatures (only the hmac-secret output matters), so the
// challenge is just random.
func clientDataFor(kind string) (*clientData, []byte) {
	challenge := make([]byte, 32)
	rand.Read(challenge)
	sum := sha256.Sum256(challenge)
	json := []byte(fmt.Sprintf(`{"type":"webauthn.%s","challenge":"%x","origin":"https://%s"}`, kind, sum[:16], rpID))
	return &clientData{dwVersion: 1, cbClientDataJSON: uint32(len(json)), pbClientDataJSON: &json[0], pwszHashAlgId: utf16("SHA-256")}, json
}

// Device is a security key used through Windows, with dialogs owned by HWND
type Device struct {
	HWND uintptr
}

// Register creates a (non-discoverable) ZeeCrypt credential with
// hmac-secret on the security key
func (d Device) Register() ([]byte, error) {
	if err := Available(); err != nil {
		return nil, err
	}
	rp := &rpEntityInformation{dwVersion: 1, pwszId: utf16(rpID), pwszName: utf16("ZeeCrypt")}
	userID := make([]byte, 16)
	rand.Read(userID)
	user := &userEntityInformation{dwVersion: 1, cbId: 16, pbId: &userID[0], pwszName: utf16("ZeeCrypt volume"), pwszDisplayName: utf16("ZeeCrypt volume")}
	algs := []coseCredentialParameter{
		{dwVersion: 1, pwszCredentialType: utf16("public-key"), lAlg: coseES256},
		{dwVersion: 1, pwszCredentialType: utf16("public-key"), lAlg: coseEdDSA},
	}
	params := &coseCredentialParameters{cCredentialParameters: uint32(len(algs)), pCredentialParameters: &algs[0]}
	cd, cdJSON := clientDataFor("create")

	enable := int32(1)
	ext := []extension{{pwszExtensionIdentifier: utf16("hmac-secret"), cbExtension: 4, pvExtension: unsafe.Pointer(&enable)}}
	opts := &makeCredentialOptions{
		dwVersion:                         4,
		dwTimeoutMilliseconds:             timeoutMs,
		Extensions:                        extensions{cExtensions: 1, pExtensions: &ext[0]},
		dwAuthenticatorAttachment:         attachmentCrossPlatform,
		dwUserVerificationRequirement:     userVerificationRequired,
		dwAttestationConveyancePreference: attestationNone,
	}

	var att *credentialAttestation
	hr, _, _ := procAuthenticatorMakeCredential.Call(d.HWND,
		uintptr(unsafe.Pointer(rp)), uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(cd)), uintptr(unsafe.Pointer(opts)), uintptr(unsafe.Pointer(&att)))
	runtime.KeepAlive(rp)
	runtime.KeepAlive(user)
	runtime.KeepAlive(userID)
	runtime.KeepAlive(algs)
	runtime.KeepAlive(params)
	runtime.KeepAlive(cdJSON)
	runtime.KeepAlive(ext)
	runtime.KeepAlive(&enable)
	runtime.KeepAlive(opts)
	if hr != 0 {
		return nil, hresultError(hr)
	}
	if att == nil {
		return nil, errors.New("the security key returned no credential")
	}
	defer procFreeCredentialAttestation.Call(uintptr(unsafe.Pointer(att)))
	if att.cbCredentialId == 0 || att.pbCredentialId == nil {
		return nil, errors.New("the security key returned no credential")
	}
	return append([]byte{}, unsafe.Slice(att.pbCredentialId, att.cbCredentialId)...), nil
}

// Secret asks the key holding one of 'credentialIDs' for its PRF output on
// 'salt'
func (d Device) Secret(credentialIDs [][]byte, salt []byte) ([]byte, []byte, error) {
	if err := Available(); err != nil {
		return nil, nil, err
	}
	if len(credentialIDs) == 0 || len(salt) != 32 {
		return nil, nil, errors.New("bad security key request")
	}
	creds := make([]credential, len(credentialIDs))
	for i, id := range credentialIDs {
		creds[i] = credential{dwVersion: 1, cbId: uint32(len(id)), pbId: &id[0], pwszCredentialType: utf16("public-key")}
	}
	saltCopy := append([]byte{}, salt...)
	hs := &hmacSecretSalt{cbFirst: 32, pbFirst: &saltCopy[0]}
	values := &hmacSecretSaltValues{pGlobalHmacSalt: hs}
	cd, cdJSON := clientDataFor("get")
	opts := &getAssertionOptions{
		dwVersion:                     6,
		dwTimeoutMilliseconds:         timeoutMs,
		CredentialList:                credentials{cCredentials: uint32(len(creds)), pCredentials: &creds[0]},
		dwAuthenticatorAttachment:     attachmentCrossPlatform,
		dwUserVerificationRequirement: userVerificationRequired,
		pHmacSecretSaltValues:         values,
	}

	var as *assertion
	hr, _, _ := procAuthenticatorGetAssertion.Call(d.HWND, uintptr(unsafe.Pointer(utf16(rpID))),
		uintptr(unsafe.Pointer(cd)), uintptr(unsafe.Pointer(opts)), uintptr(unsafe.Pointer(&as)))
	runtime.KeepAlive(creds)
	runtime.KeepAlive(credentialIDs)
	runtime.KeepAlive(saltCopy)
	runtime.KeepAlive(hs)
	runtime.KeepAlive(values)
	runtime.KeepAlive(cdJSON)
	runtime.KeepAlive(opts)
	if hr != 0 {
		return nil, nil, hresultError(hr)
	}
	if as == nil {
		return nil, nil, errors.New("the security key returned nothing")
	}
	defer procFreeAssertion.Call(uintptr(unsafe.Pointer(as)))
	if as.dwVersion < 3 || as.pHmacSecret == nil || as.pHmacSecret.cbFirst != 32 || as.pHmacSecret.pbFirst == nil {
		return nil, nil, errors.New("this security key doesn't support hmac-secret")
	}
	secret := append([]byte{}, unsafe.Slice(as.pHmacSecret.pbFirst, 32)...)
	var used []byte
	if as.Credential.pbId != nil {
		used = append([]byte{}, unsafe.Slice(as.Credential.pbId, as.Credential.cbId)...)
	}
	return used, secret, nil
}
