package main

// Public keys in the UI: your identity (create / open / copy your public
// key), contacts, which public keys to encrypt to, and signing.

import (
	"errors"
	"image/color"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ZeeCrypt/keys"
	"ZeeCrypt/volume"

	"github.com/Picocrypt/dialog"
	"github.com/Picocrypt/giu"
)

var (
	identity         *keys.Identity
	identityPath     string
	identityPassword string // kept while the identity is open, to save contact changes

	showKeys        bool
	keysPassword    string
	keysConfirm     string
	keysStatus      string
	keysStatusColor color.RGBA
	keysBusy        bool
	newContactName  string

	// Encryption choices
	encryptToSelf   bool
	contactSelected []bool           // parallel to identity.Contacts
	extraRecipients []keys.PublicKey // from .pub files, not saved as contacts
	signVolumes     bool
	useSecurityKey  bool // FIDO2 second factor with the password

	// What the dropped v3 volume can be opened with
	volumeHasRecipients bool
	volumeHasPassword   bool
	volumeHasFIDO2      bool

	// The last decryption's signature, for the final status
	lastSignature volume.SignatureStatus
)

// recipients are the public keys chosen for encryption
func recipients() []keys.PublicKey {
	var out []keys.PublicKey
	if identity != nil {
		if encryptToSelf {
			out = append(out, identity.Public())
		}
		for i, c := range identity.Contacts {
			if i < len(contactSelected) && contactSelected[i] {
				out = append(out, c.Key)
			}
		}
	}
	return append(out, extraRecipients...)
}

// hasCredentials: enough has been entered to start
func hasCredentials() bool {
	if password != "" || len(keyfiles) > 0 {
		return true
	}
	if mode == "encrypt" {
		return len(recipients()) > 0
	}
	return identity != nil && volumeHasRecipients
}

// publicKeysLabel summarizes the public-key choices for the main window
func publicKeysLabel() string {
	if mode == "decrypt" {
		switch {
		case volumeHasFIDO2:
			return "Password + security key"
		case !volumeHasRecipients:
			return "Not applicable"
		case identity != nil:
			return "Using your identity"
		default:
			return "Open your identity"
		}
	}
	var s string
	switch n := len(recipients()); {
	case n == 0:
		s = "None"
	case n == 1 && encryptToSelf:
		s = "To you"
	case n == 1:
		s = "To 1 person"
	default:
		s = "To " + strconv.Itoa(n) + " people"
	}
	if signVolumes && identity != nil {
		s += ", signed"
	}
	if useSecurityKey {
		if s == "None" {
			return "Security key"
		}
		s += ", security key"
	}
	return s
}

// noteVolumeStanzas records what a v3 volume can be opened with, for the UI
func noteVolumeStanzas(path string) {
	volumeHasRecipients, volumeHasPassword, volumeHasFIDO2 = false, false, false
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	h, err := volume.ReadHeader(f, true)
	if err != nil {
		return
	}
	for _, s := range h.Stanzas {
		switch s.Type {
		case volume.StanzaRecipient:
			volumeHasRecipients = true
		case volume.StanzaPassword:
			volumeHasPassword = true
		case volume.StanzaFIDO2:
			volumeHasFIDO2 = true
		}
	}
}

// signatureStatus is the final status line after a decryption
func signatureStatus(s volume.SignatureStatus) (string, color.RGBA) {
	switch {
	case !s.Signed:
		return "Completed", GREEN
	case !s.Valid:
		return "Completed, but its signature is invalid", YELLOW
	case s.Name != "":
		return "Completed (signed by " + s.Name + ")", GREEN
	default:
		return "Completed (signed by unknown " + volume.Fingerprint(s.Key) + ")", YELLOW
	}
}

func setKeysStatus(s string, c color.RGBA) {
	keysStatus, keysStatusColor = s, c
	giu.Update()
}

// saveIdentity writes contact changes back to the identity file
func saveIdentity() {
	if identity == nil || identityPath == "" {
		return
	}
	keysBusy = true
	setKeysStatus("Saving...", NEUTRAL)
	id, path, pw := identity, identityPath, identityPassword
	go func() {
		defer func() { keysBusy = false; giu.Update() }()
		if err := id.Save(path, pw); err != nil {
			setKeysStatus("Couldn't save the identity file", RED)
			return
		}
		setKeysStatus("Saved", GREEN)
	}()
}

func startDir() string {
	switch {
	case identityPath != "":
		return filepath.Dir(identityPath)
	case len(onlyFiles) > 0:
		return filepath.Dir(onlyFiles[0])
	case len(onlyFolders) > 0:
		return filepath.Dir(onlyFolders[0])
	}
	home, _ := os.UserHomeDir()
	return home
}

func createIdentity() {
	if keysPassword == "" || keysPassword != keysConfirm {
		setKeysStatus("Enter the same password twice", RED)
		return
	}
	f := dialog.File().Title("Save your identity")
	f.SetStartDir(startDir())
	f.SetInitFilename("my-identity.zeecrypt")
	path, err := f.Save()
	if path == "" || err != nil {
		return
	}
	if !strings.HasSuffix(strings.ToLower(path), ".zeecrypt") {
		path += ".zeecrypt"
	}
	if _, err := os.Stat(path); err == nil {
		setKeysStatus("That file already exists", RED)
		return
	}
	pw := keysPassword
	keysBusy = true
	setKeysStatus("Creating...", NEUTRAL)
	go func() {
		defer func() { keysBusy = false; giu.Update() }()
		id, err := keys.Generate()
		if err == nil {
			err = id.Save(path, pw)
		}
		if err != nil {
			setKeysStatus("Couldn't create the identity", RED)
			return
		}
		useIdentity(id, path, pw)
		setKeysStatus("Created. Back up this file and its password!", GREEN)
	}()
}

func openIdentity() {
	if keysPassword == "" {
		setKeysStatus("Enter the identity's password first", RED)
		return
	}
	f := dialog.File().Title("Open your identity")
	f.SetStartDir(startDir())
	path, err := f.Load()
	if path == "" || err != nil {
		return
	}
	pw := keysPassword
	keysBusy = true
	setKeysStatus("Opening...", NEUTRAL)
	go func() {
		defer func() { keysBusy = false; giu.Update() }()
		id, err := keys.Load(path, pw)
		if errors.Is(err, keys.ErrWrongPassword) {
			setKeysStatus("Wrong password for this identity", RED)
			return
		}
		if err != nil {
			setKeysStatus("Not a ZeeCrypt identity file", RED)
			return
		}
		useIdentity(id, path, pw)
		setKeysStatus("Opened", GREEN)
	}()
}

func useIdentity(id *keys.Identity, path, pw string) {
	identity, identityPath, identityPassword = id, path, pw
	keysPassword, keysConfirm = "", ""
	contactSelected = make([]bool, len(id.Contacts))
	encryptToSelf = true
	giu.Update()
}

func closeIdentity() {
	identity, identityPath, identityPassword = nil, "", ""
	contactSelected = nil
	encryptToSelf, signVolumes = false, false
	setKeysStatus("", NEUTRAL)
}

// readPublicKeyFile reads a .pub file (or any small text file holding a key)
func readPublicKeyFile(path string) (keys.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return keys.PublicKey{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16*1024))
	if err != nil {
		return keys.PublicKey{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			return keys.ParsePublicKey(line)
		}
	}
	return keys.PublicKey{}, errors.New("no public key in that file")
}

func addContactFromClipboard() {
	key, err := keys.ParsePublicKey(giu.Context.GetPlatform().GetClipboard())
	if err != nil {
		setKeysStatus("The clipboard doesn't hold a ZeeCrypt public key", RED)
		return
	}
	n := len(identity.Contacts)
	if err := identity.AddContact(newContactName, key); err != nil {
		setKeysStatus(err.Error(), RED)
		return
	}
	if len(identity.Contacts) > n {
		contactSelected = append(contactSelected, mode == "encrypt")
	}
	newContactName = ""
	saveIdentity()
}

func addPublicKeyFile() {
	f := dialog.File().Title("Choose a public key (.pub)")
	f.SetStartDir(startDir())
	path, err := f.Load()
	if path == "" || err != nil {
		return
	}
	key, err := readPublicKeyFile(path)
	if err != nil {
		setKeysStatus("Not a ZeeCrypt public key", RED)
		return
	}
	for _, k := range recipients() {
		if k.Equal(key) {
			setKeysStatus("Already a recipient", NEUTRAL)
			return
		}
	}
	extraRecipients = append(extraRecipients, key)
	setKeysStatus("Added "+filepath.Base(path), GREEN)
}

func savePublicKey() {
	f := dialog.File().Title("Save your public key")
	f.SetStartDir(startDir())
	f.SetInitFilename(strings.TrimSuffix(filepath.Base(identityPath), ".zeecrypt") + ".pub")
	path, err := f.Save()
	if path == "" || err != nil {
		return
	}
	content := "# ZeeCrypt public key, fingerprint " + identity.Public().Fingerprint() + "\n" + identity.Public().String() + "\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		setKeysStatus("Couldn't save the public key", RED)
		return
	}
	setKeysStatus("Saved "+filepath.Base(path), GREEN)
}

// keysModal is the "Public keys" dialog
func keysModal() giu.Widget {
	return giu.Custom(func() {
		if !showKeys {
			return
		}
		giu.PopupModal("Public keys:##"+strconv.Itoa(modalId)).Flags(6|64).Layout(
			giu.Style().SetDisabled(keysBusy).To(
				giu.Custom(identitySection),
				giu.Custom(securityKeySection),
				giu.Custom(recipientsSection),
			),
			giu.Custom(func() {
				if keysStatus != "" {
					giu.Style().SetColor(giu.StyleColorText, keysStatusColor).To(giu.Label(keysStatus)).Build()
				}
			}),
			giu.Style().SetDisabled(keysBusy).To(
				giu.Button("Done").Size(100, 0).OnClick(func() {
					giu.CloseCurrentPopup()
					showKeys = false
					keysPassword, keysConfirm, keysStatus = "", "", ""
				}),
			),
		).Build()
		giu.OpenPopup("Public keys:##" + strconv.Itoa(modalId))
		giu.Update()
	})
}

func identitySection() {
	if identity == nil {
		giu.Label("Your identity: none open").Build()
		giu.Row(
			giu.Label("Password:"),
			giu.InputText(&keysPassword).Flags(giu.InputTextFlagsPassword).Size(180),
		).Build()
		giu.Row(
			giu.Label("Confirm: "),
			giu.InputText(&keysConfirm).Flags(giu.InputTextFlagsPassword).Size(180).Hint("only to create"),
		).Build()
		giu.Row(
			giu.Button("Open...").Size(120, 0).OnClick(openIdentity),
			giu.Tooltip("Open your identity file"),
			giu.Button("Create new...").Size(120, 0).OnClick(createIdentity),
			giu.Tooltip("Create a key pair, saved in a file protected by this password"),
		).Build()
		return
	}
	giu.Label("You: " + identity.Public().Fingerprint()).Build()
	giu.Tooltip("Your fingerprint: others can compare it to make sure they have your real key").Build()
	giu.Row(
		giu.Button("Copy key").Size(64, 0).OnClick(func() {
			setClipboard(identity.Public().String())
			setKeysStatus("Public key copied", GREEN)
		}),
		giu.Tooltip("Copy your public key to share it (it isn't secret)"),
		giu.Button("Save .pub").Size(64, 0).OnClick(savePublicKey),
		giu.Tooltip("Save your public key to a file to share it"),
		giu.Button("Close").Size(64, 0).OnClick(closeIdentity),
		giu.Tooltip("Forget the open identity"),
	).Build()
	if mode == "encrypt" {
		giu.Checkbox("Sign as you", &signVolumes).Build()
		giu.Tooltip("Recipients will see that you made this volume").Build()
	}
}

// securityKeySection offers a FIDO2 key as a second factor when encrypting
func securityKeySection() {
	if mode != "encrypt" {
		return
	}
	giu.Separator().Build()
	giu.Checkbox("Also require a security key", &useSecurityKey).Build()
	giu.Tooltip("A FIDO2 key (YubiKey, SoloKey, Titan, ...) with a PIN, touched when encrypting and decrypting, on top of the password").Build()
	if useSecurityKey {
		giu.Style().SetColor(giu.StyleColorText, YELLOW).To(
			giu.Label("Without this key the password can't open it:"),
			giu.Label("also encrypt to your public key as a backup"),
		).Build()
	}
}

func recipientsSection() {
	giu.Separator().Build()
	if mode == "encrypt" {
		giu.Label("Encrypt to:").Build()
	} else {
		giu.Label("Contacts:").Build()
	}
	giu.Child().Border(true).Size(280, 110).Layout(giu.Custom(func() {
		if identity != nil && mode == "encrypt" {
			giu.Checkbox("You##self", &encryptToSelf).Build()
		}
		if identity != nil {
			for i := 0; i < len(identity.Contacts); i++ {
				c := identity.Contacts[i]
				idx := strconv.Itoa(i)
				giu.Row(
					giu.Custom(func() {
						if mode == "encrypt" && i < len(contactSelected) {
							giu.Checkbox(c.Name+"##c"+idx, &contactSelected[i]).Build()
						} else {
							giu.Label(c.Name).Build()
						}
					}),
					giu.Tooltip(c.Key.Fingerprint()),
					giu.SmallButton("x##rc"+idx).OnClick(func() {
						identity.RemoveContact(i)
						if i < len(contactSelected) {
							contactSelected = append(contactSelected[:i], contactSelected[i+1:]...)
						}
						saveIdentity()
					}),
					giu.Tooltip("Remove this contact"),
				).Build()
			}
		}
		for i := 0; i < len(extraRecipients); i++ {
			k := extraRecipients[i]
			idx := strconv.Itoa(i)
			giu.Row(
				giu.Label(k.Fingerprint()),
				giu.SmallButton("x##rx"+idx).OnClick(func() {
					extraRecipients = append(extraRecipients[:i], extraRecipients[i+1:]...)
				}),
			).Build()
		}
	})).Build()

	if identity != nil {
		giu.Row(
			giu.InputText(&newContactName).Size(130).Hint("Name"),
			giu.Button("Add from clipboard").Size(140, 0).OnClick(addContactFromClipboard),
			giu.Tooltip("Copy someone's public key, type their name, then click"),
		).Build()
	} else {
		giu.Label("Open your identity to keep contacts").Build()
	}
	if mode == "encrypt" {
		giu.Button("Add a .pub file...").Size(140, 0).OnClick(addPublicKeyFile).Build()
		giu.Tooltip("Encrypt to a public key file, without adding a contact").Build()
	}
}
