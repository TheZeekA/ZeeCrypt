package main

/*

ZeeCrypt v2.0.0 (fork of Picocrypt by Evan Su)
Copyright (c) Evan Su
Released under GPL-3.0-only
https://github.com/TheZeekA/ZeeCrypt

~ In cryptography we trust ~

*/

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"image"
	"image/color"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"ZeeCrypt/internal/releasesig"

	"github.com/Picocrypt/dialog"
	"github.com/Picocrypt/giu"
	"github.com/Picocrypt/imgui-go"
	"github.com/Picocrypt/infectious"
	"github.com/Picocrypt/serpent"
	"github.com/Picocrypt/zxcvbn-go"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Constants
const KiB = 1 << 10
const MiB = 1 << 20
const GiB = 1 << 30
const TiB = 1 << 40

var NEUTRAL = color.RGBA{0x18, 0x18, 0x1c, 0xff}
var RED = color.RGBA{0xd3, 0x2f, 0x2f, 0xff}
var GREEN = color.RGBA{0x2e, 0x7d, 0x32, 0xff}
var YELLOW = color.RGBA{0xb2, 0x8a, 0x00, 0xff}
var TRANSPARENT = color.RGBA{0x00, 0x00, 0x00, 0x00}

// Generic variables
var window *giu.MasterWindow
var version = "v2.0.0"

// Written to the 5-byte header version field. It identifies the volume format,
// not the app release, and must stay in "vX.YY" form: decryption checks it with
// `^v\d\.\d{2}` (and `^v[13]\.\d{2}` for unwrapped deniable volumes). It's
// only written by the v2 code path; new volumes are v3 (src/volume).
const headerVersion = "v1.52"

var dpi float32
var mode string
var working bool
var scanning bool

// Each drop starts a background folder scan. 'scanGen' identifies the latest
// one so an older scan, still running when something new is dropped, stops
// instead of adding its files to the new selection; 'scanMu' serializes the
// check-and-append against onDrop resetting the selection.
var scanGen int
var scanMu sync.Mutex

// Popup modals
var modalId int
var showPassgen bool
var showKeyfile bool
var showOverwrite bool
var showProgress bool
var showUpdate bool

// Update checking
const updateRepo = "TheZeekA/ZeeCrypt"

var updateChecking bool
var updateApplying bool
var updateAvailable bool
var updateVersion string
var updateNotes string
var updateDownloadURL string
var updateChecksum string
var updateSigURL string

// releasePublicKey is the Ed25519 key that signs releases (base64; create it
// with "go run ./cmd/zeecrypt-sign keygen"). While it's empty, updates are
// checked against the SHA-256 in the release notes only. Once it's set,
// every update must also come with a valid ZeeCrypt.exe.sig, which a
// tampered release (e.g. from a stolen GitHub token) can't produce.
var releasePublicKey = ""

// verifyUpdate checks a downloaded update's signature file against its
// SHA-256 and the version it was offered as. Always nil while no release
// key is configured.
func verifyUpdate(sigFile []byte, version string, sum []byte) error {
	if releasePublicKey == "" {
		return nil
	}
	pub, err := releasesig.ParsePublicKey(releasePublicKey)
	if err != nil {
		return err
	}
	return releasesig.Verify(pub, sigFile, "ZeeCrypt.exe", version, sum)
}

var updateError string

// Input and output files
var inputFile string
var inputFileOld string
var outputFile string
var onlyFiles []string
var onlyFolders []string
var allFiles []string
var allDirs []string // every folder found while scanning, so empty ones survive zipping
var inputLabel = "Drop files and folders into this window"

// Password and confirm password
var password string
var cpassword string
var passwordStrength int
var passwordState = giu.InputTextFlagsPassword
var passwordStateLabel = "Show"

// Password generator
var passgenLength int32 = 32
var passgenUpper bool
var passgenLower bool
var passgenNums bool
var passgenSymbols bool
var passgenCopy bool

// Keyfile variables
var keyfile bool
var keyfiles []string
var keyfileOrdered bool
var keyfileLabel = "None selected"

// Comments variables
var comments string
var commentsLabel = "Comments:"
var commentsDisabled bool

// Advanced options
var paranoid bool
var reedsolo bool
var deniability bool
var recursively bool
var split bool
var splitSize string
var splitUnits = []string{"KiB", "MiB", "GiB", "TiB", "Total"}
var splitSelected int32 = 1
var recombine bool
var compress bool
var delete bool
var autoUnzip bool
var sameLevel bool
var keep bool
var kept bool

// Status variables
var startLabel = "Start"
var mainStatus = "Ready"
var mainStatusColor = NEUTRAL
var popupStatus string
var requiredFreeSpace int64

// Progress variables
var progress float32
var progressInfo string
var speed float64
var eta string
var canCancel bool

// Reed-Solomon encoders
var rs1, rsErr1 = infectious.NewFEC(1, 3)
var rs5, rsErr2 = infectious.NewFEC(5, 15)
var rs16, rsErr3 = infectious.NewFEC(16, 48)
var rs24, rsErr4 = infectious.NewFEC(24, 72)
var rs32, rsErr5 = infectious.NewFEC(32, 96)
var rs64, rsErr6 = infectious.NewFEC(64, 192)
var rs128, rsErr7 = infectious.NewFEC(128, 136)
var fastDecode bool

// Temporary files created by work(), so failure paths only ever delete
// files that work() itself made (see removeTempInput)
var tempZipFile string    // zip of the selected items, when encrypting
var recombinedFile string // split volume recombined into one file
var unwrappedFile string  // deniable volume with the deniability layer removed

// Compression variables and passthrough
var compressDone int64
var compressTotal int64
var compressStart time.Time

type compressorProgress struct {
	io.Reader
}

func (p *compressorProgress) Read(data []byte) (int, error) {
	if !working {
		return 0, io.EOF
	}
	read, err := p.Reader.Read(data)
	compressDone += int64(read)
	progress, speed, eta = statify(compressDone, compressTotal, compressStart)
	if compress {
		popupStatus = fmt.Sprintf("Compressing at %.2f MiB/s (ETA: %s)", speed, eta)
	} else {
		popupStatus = fmt.Sprintf("Combining at %.2f MiB/s (ETA: %s)", speed, eta)
	}
	giu.Update()
	return read, err
}

type encryptedZipWriter struct {
	_w      io.Writer
	_cipher *chacha20.Cipher
}

func (ezw *encryptedZipWriter) Write(data []byte) (n int, err error) {
	dst := make([]byte, len(data))
	ezw._cipher.XORKeyStream(dst, data)
	return ezw._w.Write(dst)
}

type encryptedZipReader struct {
	_r      io.Reader
	_cipher *chacha20.Cipher
}

func (ezr *encryptedZipReader) Read(data []byte) (n int, err error) {
	src := make([]byte, len(data))
	n, err = ezr._r.Read(src)
	if n > 0 { // a reader may return data together with an error such as io.EOF
		dst := make([]byte, n)
		ezr._cipher.XORKeyStream(dst, src[:n])
		if copy(data, dst) != n {
			panic(errors.New("built-in copy() function failed"))
		}
	}
	return n, err
}

func onClickStartButton() {
	// Enter calls this even while a modal is open; never start a second
	// operation, or one that a pending self-update would kill
	if working || showProgress || showOverwrite || updateApplying || scanning {
		return
	}

	// Start button should be disabled if these conditions are true; don't do anything if so
	if (len(keyfiles) == 0 && password == "") || (mode == "encrypt" && password != cpassword) {
		return
	}

	if mode == "encrypt" && deniability && password == "" {
		mainStatus = deniabilityNeedsPassword
		mainStatusColor = RED
		giu.Update()
		return
	}

	if keyfile && keyfiles == nil {
		mainStatus = "Please select your keyfiles"
		mainStatusColor = RED
		giu.Update()
		return
	}
	tmp, err := strconv.Atoi(splitSize)
	if split && (splitSize == "" || err != nil || tmp <= 0) {
		mainStatus = "Invalid chunk size"
		mainStatusColor = RED
		giu.Update()
		return
	}

	// Check if output file already exists
	_, err = os.Stat(outputFile)

	// Check if any split chunks already exist
	if split {
		if len(existingChunks(outputFile)) > 0 {
			err = nil
		} else {
			err = os.ErrNotExist
		}
	}

	// If files already exist, show the overwrite modal
	if err == nil && !recursively {
		showOverwrite = true
		modalId++
		giu.Update()
	} else { // Nothing to worry about, start working
		showProgress = true
		fastDecode = true
		canCancel = true
		modalId++
		giu.Update()
		if !recursively {
			go func() {
				work(false)
				working = false
				showProgress = false
				giu.Update()
			}()
		} else {
			// Store variables as they will be cleared
			oldPassword := password
			oldKeyfile := keyfile
			oldKeyfiles := keyfiles
			oldKeyfileOrdered := keyfileOrdered
			oldKeyfileLabel := keyfileLabel
			oldComments := comments
			oldParanoid := paranoid
			oldReedsolo := reedsolo
			oldDeniability := deniability
			oldSplit := split
			oldSplitSize := splitSize
			oldSplitSelected := splitSelected
			oldDelete := delete
			files := allFiles
			go func() {
				skipped, failed := 0, 0
				for _, file := range files {
					// Simulate dropping the file
					onDrop([]string{file})

					// Restore variables and options
					password = oldPassword
					cpassword = oldPassword
					keyfile = oldKeyfile
					keyfiles = oldKeyfiles
					keyfileOrdered = oldKeyfileOrdered
					keyfileLabel = oldKeyfileLabel
					comments = oldComments
					paranoid = oldParanoid
					reedsolo = oldReedsolo
					if mode != "decrypt" {
						deniability = oldDeniability
					}
					split = oldSplit
					splitSize = oldSplitSize
					splitSelected = oldSplitSelected
					delete = oldDelete
					fastDecode = true // a repair pass on the previous file clears it

					// There's no overwrite prompt per file, so never replace
					// anything: a folder holding both "a.txt" and "a.txt.pcv"
					// would otherwise have each one overwrite the other
					if mode == "" { // onDrop couldn't read it
						failed++
						continue
					}
					if outputExists() {
						skipped++
						continue
					}

					work(false)
					if !working {
						resetUI()
						cancel(nil, nil)
						showProgress = false
						giu.Update()
						return
					}
					if mainStatusColor == RED {
						failed++
					}
				}
				working = false
				showProgress = false
				resetUI()
				mainStatus, mainStatusColor = recursiveSummary(len(files), skipped, failed)
				giu.Update()
			}()
		}
	}
}

// The main user interface
func draw() {
	if r, ok := takePendingLaunch(); ok {
		applyLaunch(r)
	}
	giu.SingleWindow().Flags(524351).Layout(
		giu.Custom(func() {
			if giu.IsKeyReleased(giu.KeyEnter) {
				onClickStartButton()
				return
			}
			if showPassgen {
				giu.PopupModal("Generate password:##"+strconv.Itoa(modalId)).Flags(6).Layout(
					giu.Row(
						giu.Label("Length:"),
						giu.SliderInt(&passgenLength, 12, 64).Size(giu.Auto),
					),
					giu.Checkbox("Uppercase", &passgenUpper),
					giu.Checkbox("Lowercase", &passgenLower),
					giu.Checkbox("Numbers", &passgenNums),
					giu.Checkbox("Symbols", &passgenSymbols),
					giu.Checkbox("Copy to clipboard", &passgenCopy),
					giu.Row(
						giu.Button("Cancel").Size(100, 0).OnClick(func() {
							giu.CloseCurrentPopup()
							showPassgen = false
						}),
						giu.Style().SetDisabled(!(passgenUpper || passgenLower || passgenNums || passgenSymbols)).To(
							giu.Button("Generate").Size(100, 0).OnClick(func() {
								password = genPassword()
								cpassword = password
								passwordStrength = zxcvbn.PasswordStrength(password, nil).Score

								giu.CloseCurrentPopup()
								showPassgen = false
							}),
						),
					),
				).Build()
				giu.OpenPopup("Generate password:##" + strconv.Itoa(modalId))
				giu.Update()
			}

			if showKeyfile {
				giu.PopupModal("Manage keyfiles:##"+strconv.Itoa(modalId)).Flags(70).Layout(
					giu.Label("Drag and drop your keyfiles here"),
					giu.Custom(func() {
						if mode != "decrypt" {
							giu.Checkbox("Require correct order", &keyfileOrdered).Build()
							giu.Tooltip("Ordering of keyfiles will matter").Build()
						} else if keyfileOrdered {
							giu.Label("Correct ordering is required").Build()
						}
					}),
					giu.Custom(func() {
						if len(keyfiles) > 0 {
							giu.Separator().Build()
						}
						for _, i := range keyfiles {
							giu.Label(filepath.Base(i)).Build()
						}
					}),
					giu.Row(
						giu.Button("Clear").Size(100, 0).OnClick(func() {
							keyfiles = nil
							if keyfile {
								keyfileLabel = "Keyfiles required"
							} else {
								keyfileLabel = "None selected"
							}
							modalId++
							giu.Update()
						}),
						giu.Tooltip("Remove all keyfiles"),

						giu.Button("Done").Size(100, 0).OnClick(func() {
							giu.CloseCurrentPopup()
							showKeyfile = false
						}),
					),
				).Build()
				giu.OpenPopup("Manage keyfiles:##" + strconv.Itoa(modalId))
				giu.Update()
			}

			if showOverwrite {
				giu.PopupModal("Warning:##"+strconv.Itoa(modalId)).Flags(6).Layout(
					giu.Label("Output already exists. Overwrite?"),
					giu.Row(
						giu.Button("No").Size(100, 0).OnClick(func() {
							giu.CloseCurrentPopup()
							showOverwrite = false
						}),
						giu.Button("Yes").Size(100, 0).OnClick(func() {
							giu.CloseCurrentPopup()
							showOverwrite = false

							showProgress = true
							fastDecode = true
							canCancel = true
							modalId++
							giu.Update()
							go func() {
								work(false)
								working = false
								showProgress = false
								giu.Update()
							}()
						}),
					),
				).Build()
				giu.OpenPopup("Warning:##" + strconv.Itoa(modalId))
				giu.Update()
			}

			if showProgress {
				giu.PopupModal("Progress:##"+strconv.Itoa(modalId)).Flags(6|1<<0).Layout(
					giu.Dummy(0, 0),
					giu.Row(
						giu.ProgressBar(progress).Size(210, 0).Overlay(progressInfo),
						giu.Style().SetDisabled(!canCancel).To(
							giu.Button(func() string {
								if working {
									return "Cancel"
								}
								return "..."
							}()).Size(58, 0).OnClick(func() {
								working = false
								canCancel = false
							}),
						),
					),
					giu.Label(popupStatus),
				).Build()
				giu.OpenPopup("Progress:##" + strconv.Itoa(modalId))
				giu.Update()
			}

			if showUpdate {
				giu.PopupModal("Update available:##"+strconv.Itoa(modalId)).Flags(6).Layout(
					giu.Label("ZeeCrypt "+updateVersion+" is available (you have "+version+")"),
					giu.Dummy(0, 4),
					giu.InputTextMultiline(&updateNotes).Flags(giu.InputTextFlagsReadOnly).Size(280, 150),
					giu.Dummy(0, 4),
					giu.Custom(func() {
						if updateError != "" {
							giu.Style().SetColor(giu.StyleColorText, RED).To(
								giu.Label(updateError),
							).Build()
						}
					}),
					giu.Style().SetDisabled(updateApplying).To(
						giu.Row(
							giu.Button("Later").Size(100, 0).OnClick(func() {
								giu.CloseCurrentPopup()
								showUpdate = false
							}),
							giu.Button(func() string {
								if updateApplying {
									return "Updating..."
								}
								return "Update Now"
							}()).Size(160, 0).OnClick(applyUpdate),
						),
					),
				).Build()
				giu.OpenPopup("Update available:##" + strconv.Itoa(modalId))
				giu.Update()
			}
		}),

		giu.Row(
			giu.Label(inputLabel),
			giu.Custom(func() {
				bw, _ := giu.CalcTextSize("Clear")
				p, _ := giu.GetWindowPadding()
				bw += p * 2
				giu.Dummy((bw+p)/-dpi, 0).Build()
				giu.SameLine()
				giu.Style().SetDisabled((len(allFiles) == 0 && len(onlyFiles) == 0) || scanning).To(
					giu.Button("Clear").Size(bw/dpi, 0).OnClick(resetUI),
					giu.Tooltip("Clear all input files and reset UI state"),
				).Build()
			}),
		),

		giu.Separator(),
		giu.Style().SetDisabled((len(allFiles) == 0 && len(onlyFiles) == 0) || scanning).To(
			giu.Label("Password:"),
			giu.Row(
				giu.Button(passwordStateLabel).Size(54, 0).OnClick(func() {
					if passwordState == giu.InputTextFlagsPassword {
						passwordState = giu.InputTextFlagsNone
						passwordStateLabel = "Hide"
					} else {
						passwordState = giu.InputTextFlagsPassword
						passwordStateLabel = "Show"
					}
					giu.Update()
				}),
				giu.Tooltip("Toggle the visibility of password entries"),

				giu.Button("Clear").Size(54, 0).OnClick(func() {
					password = ""
					cpassword = ""
					giu.Update()
				}),
				giu.Tooltip("Clear the password entries"),

				giu.Button("Copy").Size(54, 0).OnClick(func() {
					setSecretClipboard(password)
					giu.Update()
				}),
				giu.Tooltip("Copy the password into your clipboard (cleared after 30 seconds)"),

				giu.Button("Paste").Size(54, 0).OnClick(func() {
					tmp := giu.Context.GetPlatform().GetClipboard()
					password = tmp
					if mode != "decrypt" {
						cpassword = tmp
					}
					passwordStrength = zxcvbn.PasswordStrength(password, nil).Score
					giu.Update()
				}),
				giu.Tooltip("Paste a password from your clipboard"),

				giu.Style().SetDisabled(mode == "decrypt").To(
					giu.Button("Create").Size(54, 0).OnClick(func() {
						showPassgen = true
						modalId++
						giu.Update()
					}),
				),
				giu.Tooltip("Generate a cryptographically secure password"),
			),
			giu.Row(
				giu.InputText(&password).Flags(passwordState).Size(302/dpi).OnChange(func() {
					passwordStrength = zxcvbn.PasswordStrength(password, nil).Score
					giu.Update()
				}),
				giu.Custom(func() {
					c := giu.GetCanvas()
					p := giu.GetCursorScreenPos()
					col := color.RGBA{
						uint8(0xc8 - 31*passwordStrength),
						uint8(0x4c + 31*passwordStrength), 0x4b, 0xff,
					}
					if password == "" || mode == "decrypt" {
						col = TRANSPARENT
					}
					path := p.Add(image.Pt(
						int(math.Round(-20*float64(dpi))),
						int(math.Round(12*float64(dpi))),
					))
					c.PathArcTo(path, 6*dpi, -math.Pi/2, math.Pi*(.4*float32(passwordStrength)-.1), -1)
					c.PathStroke(col, false, 2)
				}),
			),

			giu.Dummy(0, 0),
			giu.Style().SetDisabled(password == "" || mode == "decrypt").To(
				giu.Label("Confirm password:"),
				giu.Row(
					giu.InputText(&cpassword).Flags(passwordState).Size(302/dpi),
					giu.Custom(func() {
						c := giu.GetCanvas()
						p := giu.GetCursorScreenPos()
						col := color.RGBA{0x4c, 0xc8, 0x4b, 0xff}
						if cpassword != password {
							col = color.RGBA{0xc8, 0x4c, 0x4b, 0xff}
						}
						if password == "" || cpassword == "" || mode == "decrypt" {
							col = TRANSPARENT
						}
						path := p.Add(image.Pt(
							int(math.Round(-20*float64(dpi))),
							int(math.Round(12*float64(dpi))),
						))
						c.PathArcTo(path, 6*dpi, 0, 2*math.Pi, -1)
						c.PathStroke(col, false, 2)
					}),
				),
			),

			giu.Dummy(0, 0),
			giu.Style().SetDisabled(mode == "decrypt" && !keyfile && !deniability).To(
				giu.Row(
					giu.Label("Keyfiles:"),
					giu.Button("Edit").Size(54, 0).OnClick(func() {
						showKeyfile = true
						modalId++
						giu.Update()
					}),
					giu.Tooltip("Manage keyfiles to use for "+(func() string {
						if mode != "decrypt" {
							return "encryption"
						}
						return "decryption"
					}())),

					giu.Style().SetDisabled(mode == "decrypt").To(
						giu.Button("Create").Size(54, 0).OnClick(func() {
							f := dialog.File().Title("Choose where to save the keyfile")
							f.SetStartDir(func() string {
								if len(onlyFiles) > 0 {
									return filepath.Dir(onlyFiles[0])
								}
								return filepath.Dir(onlyFolders[0])
							}())
							f.SetInitFilename("keyfile-" + strconv.Itoa(int(time.Now().Unix())) + ".bin")
							file, err := f.Save()
							if file == "" || err != nil {
								return
							}

							fout, err := os.Create(file)
							if err != nil {
								mainStatus = "Failed to create keyfile"
								mainStatusColor = RED
								giu.Update()
								return
							}
							data := make([]byte, 32)
							if n, err := rand.Read(data); err != nil || n != 32 {
								panic(errors.New("fatal crypto/rand error"))
							}
							n, errW := fout.Write(data)
							errC := fout.Close()
							if errW != nil || errC != nil || n != 32 {
								os.Remove(file) // a short keyfile would be weaker than intended
								mainStatus = "Failed to write keyfile"
								mainStatusColor = RED
								giu.Update()
								return
							}
							mainStatus = "Ready"
							mainStatusColor = NEUTRAL
							giu.Update()
							return
						}),
						giu.Tooltip("Generate a cryptographically secure keyfile"),
					),
					giu.Style().SetDisabled(true).To(
						giu.InputText(&keyfileLabel).Size(giu.Auto),
					),
				),
			),
		),

		giu.Separator(),
		giu.Style().SetDisabled(mode != "decrypt" && ((len(keyfiles) == 0 && password == "") || (password != cpassword)) || deniability).To(
			giu.Style().SetDisabled(mode == "decrypt" && (comments == "" || comments == "Comments are corrupted")).To(
				giu.Label(commentsLabel),
				giu.InputText(&comments).Size(giu.Auto).Flags(func() giu.InputTextFlags {
					if commentsDisabled {
						return giu.InputTextFlagsReadOnly
					} else if deniability {
						comments = ""
					}
					return giu.InputTextFlagsNone
				}()),
				giu.Custom(func() {
					if !commentsDisabled {
						giu.Tooltip("Note: comments are not encrypted or tamper-protected!").Build()
					}
				}),
			),
		),
		giu.Style().SetDisabled((len(keyfiles) == 0 && password == "") || (mode == "encrypt" && password != cpassword)).To(
			giu.Label("Advanced:"),
			giu.Custom(func() {
				if mode != "decrypt" {
					giu.Row(
						giu.Checkbox("Paranoid mode", &paranoid),
						giu.Tooltip("Provides the highest level of security attainable"),
						giu.Dummy(-170, 0),
						giu.Style().SetDisabled(recursively || !(len(allFiles) > 1 || len(onlyFolders) > 0)).To(
							giu.Combo("##compress", compressLevels[compressLevel], compressLevels, &compressLevel).Size(150).OnChange(func() {
								setCompression(compressLevel)
							}),
							giu.Tooltip("Compress into a .tar.zst archive (opens in Windows 11 Explorer and 7-Zip)"),
						),
					).Build()

					giu.Row(
						giu.Checkbox("Reed-Solomon", &reedsolo),
						giu.Tooltip("Prevent file corruption with erasure coding"),
						giu.Dummy(-170, 0),
						giu.Checkbox("Delete files", &delete),
						giu.Tooltip("Delete the input files after encryption"),
					).Build()

					giu.Row(
						giu.Checkbox("Deniability", &deniability),
						giu.Tooltip("Warning: only use this if you know what it does! Requires a password"),
						giu.Dummy(-170, 0),
						giu.Style().SetDisabled(!(len(allFiles) > 1 || len(onlyFolders) > 0)).To(
							giu.Checkbox("Recursively", &recursively).OnChange(func() {
								setCompression(0)
							}),
							giu.Tooltip("Warning: only use this if you know what it does!"),
						),
					).Build()

					giu.Row(
						giu.Checkbox("Split into chunks:", &split),
						giu.Tooltip("Split the output file into smaller chunks"),
						giu.Dummy(-170, 0),
						giu.InputText(&splitSize).Size(86/dpi).Flags(2).OnChange(func() {
							split = splitSize != ""
						}),
						giu.Tooltip("Choose the chunk size"),
						giu.Combo("##splitter", splitUnits[splitSelected], splitUnits, &splitSelected).Size(68),
						giu.Tooltip("Choose the chunk units"),
					).Build()
				} else {
					giu.Row(
						giu.Style().SetDisabled(deniability).To(
							giu.Checkbox("Force decrypt", &keep),
							giu.Tooltip("Override security measures when decrypting"),
						),
						giu.Dummy(-170, 0),
						giu.Checkbox("Delete volume", &delete),
						giu.Tooltip("Delete the volume after a successful decryption"),
					).Build()

					giu.Row(
						giu.Style().SetDisabled(!isArchiveVolume(inputFile)).To(
							giu.Checkbox("Auto unzip", &autoUnzip).OnChange(func() {
								if !autoUnzip {
									sameLevel = false
								}
							}),
							giu.Tooltip("Extract the .zip or .tar.zst after decryption (may overwrite files)"),
						),
						giu.Dummy(-170, 0),
						giu.Style().SetDisabled(!autoUnzip).To(
							giu.Checkbox("Same level", &sameLevel),
							giu.Tooltip("Extract the contents to the same folder as the volume"),
						),
					).Build()
				}
			}),

			giu.Style().SetDisabled(recursively).To(
				giu.Label("Save output as:"),
				giu.Custom(func() {
					w, _ := giu.GetAvailableRegion()
					bw, _ := giu.CalcTextSize("Change")
					p, _ := giu.GetWindowPadding()
					bw += p * 2
					dw := w - bw - p
					giu.Style().SetDisabled(true).To(
						giu.InputText(func() *string {
							tmp := ""
							if outputFile == "" {
								return &tmp
							}
							tmp = filepath.Base(outputFile)
							if split {
								tmp += ".*"
							}
							if recursively {
								tmp = "(multiple values)"
							}
							return &tmp
						}()).Size(dw / dpi / dpi).Flags(16384),
					).Build()

					giu.SameLine()
					giu.Button("Change").Size(bw/dpi, 0).OnClick(func() {
						f := dialog.File().Title("Choose where to save the output. Don't include extensions")
						f.SetStartDir(func() string {
							if len(onlyFiles) > 0 {
								return filepath.Dir(onlyFiles[0])
							}
							return filepath.Dir(onlyFolders[0])
						}())

						// Prefill the filename
						tmp := strings.TrimSuffix(filepath.Base(outputFile), ".pcv")
						f.SetInitFilename(strings.TrimSuffix(tmp, filepath.Ext(tmp)))
						if mode == "encrypt" && (len(allFiles) > 1 || len(onlyFolders) > 0) {
							f.SetInitFilename("encrypted-" + strconv.Itoa(int(time.Now().Unix())))
						}

						// Get the chosen file path
						file, err := f.Save()
						if file == "" || err != nil {
							return
						}
						outputFile = outputNameFromDialog(file)
						mainStatus = "Ready"
						mainStatusColor = NEUTRAL
						giu.Update()
					}).Build()
					giu.Tooltip("Save the output with a custom name and path").Build()
				}),
			),

			giu.Dummy(0, 0),
			giu.Separator(),
			giu.Dummy(0, 0),
			giu.Button(func() string {
				if !recursively {
					return startLabel
				}
				return "Process"
			}()).Size(giu.Auto, 34).OnClick(onClickStartButton),
			giu.Custom(func() {
				if mainStatus != "Ready" {
					giu.Style().SetColor(giu.StyleColorText, mainStatusColor).To(
						giu.Label(mainStatus),
					).Build()
					return
				}
				if requiredFreeSpace > 0 {
					multiplier := 1
					if len(allFiles) > 1 || len(onlyFolders) > 0 { // need a temporary zip file
						multiplier++
					}
					if deniability {
						multiplier++
					}
					if split {
						multiplier++
					}
					if recombine {
						multiplier++
					}
					if autoUnzip {
						multiplier++
					}
					giu.Style().SetColor(giu.StyleColorText, NEUTRAL).To(
						giu.Label("Ready (ensure >" + sizeify(requiredFreeSpace*int64(multiplier)) + " of disk space is free)"),
					).Build()
				} else {
					giu.Style().SetColor(giu.StyleColorText, NEUTRAL).To(
						giu.Label("Ready"),
					).Build()
				}
			}),
		),

		giu.Dummy(0, 2),
		giu.Custom(func() {
			label := version
			labelColor := NEUTRAL
			switch {
			case updateApplying:
				label = "Updating..."
			case updateChecking:
				label = "Checking for updates..."
			case updateAvailable:
				label = "Update available: " + updateVersion
				labelColor = GREEN
			case updateError != "":
				label = updateError
				labelColor = RED
			}

			// Right-align on its own line: measure the label, then move the
			// cursor so it ends flush with the window's right edge. This
			// mirrors giu's own Align(AlignRight) math, applied by hand
			// because Align has a documented bug that skips Selectable.
			w, _ := giu.CalcTextSize(label)
			availW, _ := giu.GetAvailableRegion()
			padW, _ := giu.GetWindowPadding()
			pos := giu.GetCursorPos()
			giu.SetCursorPos(image.Pt(int(availW+2*padW-w), pos.Y))

			giu.Style().SetColor(giu.StyleColorText, labelColor).To(
				giu.Selectable(label).OnClick(func() {
					if updateChecking || updateApplying {
						return
					}
					if updateAvailable {
						showUpdate = true
						modalId++
						giu.Update()
					} else {
						checkForUpdates()
					}
				}),
			).Build()
		}),

		giu.Custom(func() {
			window.SetSize(int(318*dpi), giu.GetCursorPos().Y+1)
		}),
	)
}

func onDrop(names []string) {
	if showKeyfile {
		keyfiles = append(keyfiles, names...)

		// Make sure keyfiles are accessible, remove duplicates
		var tmp []string
		for _, i := range keyfiles {
			duplicate := false
			for _, j := range tmp {
				if i == j {
					duplicate = true
				}
			}
			stat, statErr := os.Stat(i)
			fin, err := os.Open(i)
			if err == nil {
				fin.Close()
			} else {
				showKeyfile = false
				resetUI()
				accessDenied("Keyfile read")
				giu.Update()
				return
			}
			if !duplicate && statErr == nil && !stat.IsDir() {
				tmp = append(tmp, i)
			}
		}
		keyfiles = tmp

		// Update the keyfile status
		if len(keyfiles) == 0 {
			keyfileLabel = "None selected"
		} else if len(keyfiles) == 1 {
			keyfileLabel = "Using 1 keyfile"
		} else {
			keyfileLabel = fmt.Sprintf("Using %d keyfiles", len(keyfiles))
		}

		modalId++
		giu.Update()
		return
	}

	scanMu.Lock()
	scanGen++
	gen := scanGen
	scanning = true
	scanStarted := false
	defer func() {
		if !scanStarted { // an early return: no scan will clear 'scanning'
			scanning = false
		}
		scanMu.Unlock()
	}()
	files, folders := 0, 0
	compressDone, compressTotal = 0, 0
	resetUI()

	// Explorer's "Decrypt with ZeeCrypt" verb: only a single volume (or one
	// of its split chunks) makes sense
	if forcedMode == "decrypt" {
		isVolume := false
		if len(names) == 1 && (strings.HasSuffix(names[0], ".pcv") || splitChunkRegex.MatchString(names[0])) {
			if stat, err := os.Stat(names[0]); err == nil && !stat.IsDir() {
				isVolume = true
			}
		}
		if !isVolume {
			if len(names) == 1 {
				mainStatus = "Not a ZeeCrypt volume"
			} else {
				mainStatus = "Select one volume to decrypt"
			}
			mainStatusColor = RED
			giu.Update()
			return
		}
	}

	// One item dropped
	if len(names) == 1 {
		stat, err := os.Stat(names[0])
		if err != nil {
			mainStatus = "Failed to stat dropped item"
			mainStatusColor = RED
			giu.Update()
			return
		}

		// A folder was dropped
		if stat.IsDir() {
			folders++
			mode = "encrypt"
			inputLabel = "1 folder"
			startLabel = "Zip and Encrypt"
			onlyFolders = append(onlyFolders, names[0])
			inputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
			outputFile = inputFile + ".pcv"
		} else { // A file was dropped
			files++
			requiredFreeSpace = stat.Size()

			// Is the file a part of a split volume? ("name.pcv.<number>")
			isSplit := splitChunkRegex.MatchString(names[0])
			isVolume := strings.HasSuffix(names[0], ".pcv") || isSplit
			if forcedMode == "encrypt" { // e.g. encrypt a volume again with another key
				isSplit, isVolume = false, false
			}

			// Decide if encrypting or decrypting
			if isVolume {
				mode = "decrypt"
				inputLabel = "Volume for decryption"
				startLabel = "Decrypt"
				commentsLabel = "Comments (read-only):"
				commentsDisabled = true

				// Get the correct input and output filenames
				if isSplit {
					ind := strings.LastIndex(names[0], ".pcv.")
					names[0] = names[0][:ind+4]
					inputFile = names[0]
					outputFile = names[0][:ind]
					recombine = true

					// Find out the number of splitted chunks
					totalFiles := 0
					for {
						stat, err := os.Stat(fmt.Sprintf("%s.%d", inputFile, totalFiles))
						if err != nil {
							break
						}
						totalFiles++
						compressTotal += stat.Size()
					}
					requiredFreeSpace = compressTotal
				} else {
					outputFile = names[0][:len(names[0])-4]
				}

				// Open the input file in read-only mode
				var fin *os.File
				var err error
				if isSplit {
					fin, err = os.Open(names[0] + ".0")
				} else {
					fin, err = os.Open(names[0])
				}
				if err != nil {
					resetUI()
					accessDenied("Read")
					giu.Update()
					return
				}

				// Check if version can be read from header
				tmp := make([]byte, 15)
				if n, err := fin.Read(tmp); err != nil || n != 15 {
					fin.Close()
					mainStatus = "Failed to read 15 bytes from file"
					mainStatusColor = RED
					giu.Update()
					return
				}
				tmp, err = rsDecode(rs5, tmp)
				if valid, _ := regexp.Match(`^v\d\.\d{2}`, tmp); err != nil || !valid {
					// Volume has plausible deniability
					deniability = true
					mainStatus = "Can't read header, assuming volume is deniable"
					fin.Close()
					giu.Update()
				} else {
					// Read comments from file and check for corruption
					tmp = make([]byte, 15)
					if n, err := fin.Read(tmp); err != nil || n != 15 {
						fin.Close()
						mainStatus = "Failed to read 15 bytes from file"
						mainStatusColor = RED
						giu.Update()
						return
					}
					tmp, err = rsDecode(rs5, tmp)
					if valid, _ := regexp.Match(`^\d{5}$`, tmp); err == nil && valid {
						commentsLength, _ := strconv.Atoi(string(tmp))
						tmp = make([]byte, commentsLength*3)
						if n, err := fin.Read(tmp); err != nil || n != commentsLength*3 {
							fin.Close()
							mainStatus = "Failed to read comments from file"
							mainStatusColor = RED
							giu.Update()
							return
						}
						comments = ""
						for i := 0; i < commentsLength*3; i += 3 {
							t, err := rsDecode(rs1, tmp[i:i+3])
							if err != nil {
								comments = "Comments are corrupted"
								break
							}
							comments += string(t)
						}
						giu.Update()
					} else {
						comments = "Comments are corrupted"
						giu.Update()
					}

					// Read flags from file and check for corruption
					flags := make([]byte, 15)
					if n, err := fin.Read(flags); err != nil || n != 15 {
						fin.Close()
						mainStatus = "Failed to read 15 bytes from file"
						mainStatusColor = RED
						giu.Update()
						return
					}
					fin.Close()
					flags, err = rsDecode(rs5, flags)
					if err != nil {
						mainStatus = "The volume header is damaged"
						mainStatusColor = RED
						giu.Update()
						return
					}

					// Update UI and variables according to flags
					if flags[1] == 1 {
						keyfile = true
						keyfileLabel = "Keyfiles required"
					} else {
						keyfileLabel = "Not applicable"
					}
					if flags[2] == 1 {
						keyfileOrdered = true
					}
					giu.Update()
				}
			} else { // One file was dropped for encryption
				mode = "encrypt"
				inputLabel = "1 file"
				startLabel = "Encrypt"
				inputFile = names[0]
				outputFile = names[0] + ".pcv"
				giu.Update()
			}

			// Add the file
			onlyFiles = append(onlyFiles, names[0])
			inputFile = names[0]
			if !isSplit {
				compressTotal += stat.Size()
			}
			giu.Update()
		}
	} else { // There are multiple dropped items
		mode = "encrypt"
		startLabel = "Zip and Encrypt"

		// Go through each dropped item and add to corresponding slices
		for _, name := range names {
			stat, err := os.Stat(name)
			if err != nil {
				resetUI()
				mainStatus = "Failed to stat dropped items"
				mainStatusColor = RED
				giu.Update()
				return
			}
			if stat.IsDir() {
				folders++
				onlyFolders = append(onlyFolders, name)
			} else {
				files++
				onlyFiles = append(onlyFiles, name)
				allFiles = append(allFiles, name)

				compressTotal += stat.Size()
				requiredFreeSpace += stat.Size()
				inputLabel = fmt.Sprintf("Scanning files... (%s)", sizeify(compressTotal))
				giu.Update()
			}
		}

		// Update UI with the number of files and folders selected
		if folders == 0 {
			inputLabel = fmt.Sprintf("%d files", files)
		} else if files == 0 {
			inputLabel = fmt.Sprintf("%d folders", folders)
		} else {
			if files == 1 && folders > 1 {
				inputLabel = fmt.Sprintf("1 file and %d folders", folders)
			} else if folders == 1 && files > 1 {
				inputLabel = fmt.Sprintf("%d files and 1 folder", files)
			} else if folders == 1 && files == 1 {
				inputLabel = "1 file and 1 folder"
			} else {
				inputLabel = fmt.Sprintf("%d files and %d folders", files, folders)
			}
		}

		// Set the input and output paths
		inputFile = filepath.Join(filepath.Dir(names[0]), "encrypted-"+strconv.Itoa(int(time.Now().Unix()))) + ".zip"
		outputFile = inputFile + ".pcv"
		giu.Update()
	}

	// Recursively add all files in 'onlyFolders' to 'allFiles'
	scanStarted = true
	folderList := onlyFolders
	go func() {
		errStale := errors.New("superseded by a newer drop")
		walkFailed := func() {
			resetUI()
			mainStatus = "Failed to walk through dropped items"
			mainStatusColor = RED
			scanning = false
			giu.Update()
		}

		scanMu.Lock()
		oldInputLabel := inputLabel
		scanMu.Unlock()
		for _, name := range folderList {
			err := filepath.Walk(name, func(path string, _ os.FileInfo, err error) error {
				scanMu.Lock()
				defer scanMu.Unlock()
				if gen != scanGen { // something newer was dropped; stop quietly
					return errStale
				}
				if err != nil {
					walkFailed()
					return err
				}
				stat, err := os.Stat(path)
				if err != nil {
					walkFailed()
					return err
				}
				// If 'path' is a valid file path, add to 'allFiles'
				if stat.IsDir() {
					allDirs = append(allDirs, path)
				} else {
					allFiles = append(allFiles, path)
					compressTotal += stat.Size()
					requiredFreeSpace += stat.Size()
					inputLabel = fmt.Sprintf("Scanning files... (%s)", sizeify(compressTotal))
					giu.Update()
				}
				return nil
			})
			if err != nil {
				return // walkFailed() already ran, or a newer scan owns the state
			}
		}
		scanMu.Lock()
		defer scanMu.Unlock()
		if gen != scanGen {
			return
		}
		inputLabel = fmt.Sprintf("%s (%s)", oldInputLabel, sizeify(compressTotal))
		scanning = false
		giu.Update()
	}()
}

// 'prepared' is true on the Reed-Solomon repair pass, where 'inputFile' is
// already the recombined and/or unwrapped volume from the first pass
func work(prepared bool) {
	popupStatus = "Starting..."
	mainStatus = "Working..."
	mainStatusColor = NEUTRAL
	working = true
	padded := false
	giu.Update()

	if !prepared {
		tempZipFile, recombinedFile, unwrappedFile = "", "", ""
	}

	// The deniability layer is keyed by the password alone; with an empty
	// one, anyone could remove it and reveal the volume header
	if mode == "encrypt" && deniability && password == "" {
		mainStatus = deniabilityNeedsPassword
		mainStatusColor = RED
		return
	}

	// Cryptography values
	var salt []byte                    // Argon2 salt, 16 bytes
	var hkdfSalt []byte                // HKDF-SHA3 salt, 32 bytes
	var serpentIV []byte               // Serpent IV, 16 bytes
	var nonce []byte                   // 24-byte XChaCha20 nonce
	var flags []byte                   // 5-byte flags field (paranoid, keyfile, ordered, reedsolo, padded)
	var headerMAC []byte               // HMAC-SHA3-512 of the header, authenticates it and verifies the password
	var headerMACRef []byte            // Same as 'headerMAC', but used for comparison
	var keyfileKey []byte              // The SHA3-256 hashes of keyfiles
	var keyfileHash = make([]byte, 32) // The SHA3-256 of 'keyfileKey'
	var keyfileHashRef []byte          // Same as 'keyfileHash', but used for comparison
	var authTag []byte                 // 64-byte authentication tag (BLAKE2b or HMAC-SHA3)

	var tempZipCipherW *chacha20.Cipher
	var tempZipCipherR *chacha20.Cipher
	var tempZipInUse bool = false
	func() { // enclose to keep out of parent scope
		key, nonce := make([]byte, 32), make([]byte, 12)
		if n, err := rand.Read(key); err != nil || n != 32 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if n, err := rand.Read(nonce); err != nil || n != 12 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(key, make([]byte, 32)) || bytes.Equal(nonce, make([]byte, 12)) {
			panic(errors.New("fatal crypto/rand error")) // this should never happen but be safe
		}
		var errW error
		var errR error
		tempZipCipherW, errW = chacha20.NewUnauthenticatedCipher(key, nonce)
		tempZipCipherR, errR = chacha20.NewUnauthenticatedCipher(key, nonce)
		if errW != nil || errR != nil {
			panic(errors.New("fatal chacha20 init error"))
		}
	}()

	// Combine/compress all files into a .zip file if needed
	if len(allFiles) > 1 || len(onlyFolders) > 0 {
		// Consider case where compressing only one file
		files := allFiles
		if len(allFiles) == 0 {
			files = onlyFiles
		}

		// Names inside the zip are relative to the folder each dropped item
		// came from, which also works when items come from different folders
		// (e.g. Explorer search results)
		namer := newZipNamer(onlyFiles, onlyFolders)

		// Open a temporary archive for writing
		outputFile = withArchiveExt(outputFile)
		inputFile = strings.TrimSuffix(outputFile, ".pcv") + ".tmp"
		if _, err := os.Stat(inputFile); err == nil {
			mainStatus = "Please remove " + filepath.Base(inputFile)
			mainStatusColor = RED
			return
		}
		file, err := os.Create(inputFile)
		if err != nil { // Make sure file is writable
			accessDenied("Write")
			return
		}
		tempZipFile = inputFile

		// Add each file to the archive (.zip, or .tar.zst when compressing)
		tempZip := encryptedZipWriter{
			_w:      file,
			_cipher: tempZipCipherW,
		}
		tempZipInUse = true
		writer, err := newArchiveWriter(&tempZip)
		if err != nil {
			file.Close()
			os.Remove(inputFile)
			resetUI()
			mainStatus = "Failed to start compressing"
			mainStatusColor = RED
			return
		}
		compressStart = time.Now()
		archiveFail := func(status string) {
			writer.Close()
			file.Close()
			os.Remove(inputFile)
			resetUI()
			mainStatus = status
			mainStatusColor = RED
		}

		// Folder entries first, so empty folders survive the round trip
		for _, dir := range allDirs {
			var modified time.Time
			if stat, err := os.Stat(dir); err == nil {
				modified = stat.ModTime()
			}
			if err := writer.addDir(namer.dirName(dir), modified); err != nil {
				archiveFail("Failed to add a folder to the archive")
				return
			}
		}

		for i, path := range files {
			progressInfo = fmt.Sprintf("%d/%d", i+1, len(files))
			giu.Update()

			// Size, last modified, etc.
			stat, err := os.Stat(path)
			if err != nil {
				archiveFail("Failed to stat input files")
				return
			}
			entry, err := writer.addFile(namer.fileName(path), stat)
			if err != nil {
				archiveFail("Failed to add a file to the archive")
				return
			}
			fin, err := os.Open(path)
			if err != nil {
				writer.Close()
				file.Close()
				os.Remove(inputFile)
				resetUI()
				accessDenied("Read")
				return
			}

			// Use a passthrough to catch compression progress. Copy exactly
			// the size recorded in the entry's header (a tar entry can't hold
			// more or less).
			passthrough := &compressorProgress{Reader: fin}
			buf := make([]byte, MiB)
			n, err := io.CopyBuffer(entry, io.LimitReader(passthrough, stat.Size()), buf)
			fin.Close()

			if err != nil {
				writer.Close()
				insufficientSpace(nil, file)
				os.Remove(inputFile)
				return
			}

			if !working {
				writer.Close()
				cancel(nil, file)
				os.Remove(inputFile)
				return
			}

			if n != stat.Size() {
				archiveFail(filepath.Base(path) + " changed while it was being read")
				return
			}
		}
		errW := writer.Close()
		errF := file.Close()
		if errW != nil || errF != nil {
			insufficientSpace(nil, nil)
			removeTempInput()
			return
		}
	}

	// Recombine a split file if necessary
	if recombine && !prepared {
		totalFiles := 0
		totalBytes := int64(0)
		done := 0

		// Find out the number of splitted chunks
		for {
			stat, err := os.Stat(fmt.Sprintf("%s.%d", inputFile, totalFiles))
			if err != nil {
				break
			}
			totalFiles++
			totalBytes += stat.Size()
		}

		// Make sure not to overwrite anything
		_, err := os.Stat(outputFile + ".pcv")
		if err == nil { // File already exists
			mainStatus = "Please remove " + filepath.Base(outputFile+".pcv")
			mainStatusColor = RED
			return
		}

		// Create a .pcv to combine chunks into
		fout, err := os.Create(outputFile + ".pcv")
		if err != nil { // Make sure file is writable
			accessDenied("Write")
			return
		}

		// Merge all chunks into one file
		startTime := time.Now()
		for i := range totalFiles {
			fin, err := os.Open(fmt.Sprintf("%s.%d", inputFile, i))
			if err != nil {
				fout.Close()
				os.Remove(outputFile + ".pcv")
				resetUI()
				accessDenied("Read")
				return
			}

			for {
				if !working {
					cancel(fin, fout)
					os.Remove(outputFile + ".pcv")
					return
				}

				// Copy from the chunk into the .pcv
				data := make([]byte, MiB)
				read, err := fin.Read(data)
				if err != nil {
					break
				}
				data = data[:read]
				var n int
				n, err = fout.Write(data)
				done += read

				if err != nil || n != len(data) {
					insufficientSpace(fin, fout)
					os.Remove(outputFile + ".pcv")
					return
				}

				// Update the stats
				progress, speed, eta = statify(int64(done), totalBytes, startTime)
				progressInfo = fmt.Sprintf("%d/%d", i+1, totalFiles)
				popupStatus = fmt.Sprintf("Recombining at %.2f MiB/s (ETA: %s)", speed, eta)
				giu.Update()
			}
			fin.Close() // read-only; a close error can't lose data
		}
		if err := fout.Close(); err != nil {
			insufficientSpace(nil, nil)
			os.Remove(outputFile + ".pcv")
			return
		}
		recombinedFile = outputFile + ".pcv"
		inputFileOld = inputFile
		inputFile = outputFile + ".pcv"
	}

	// Input volume has plausible deniability
	if mode == "decrypt" && deniability && !prepared {
		popupStatus = "Removing deniability protection..."
		progressInfo = ""
		progress = 0
		canCancel = false
		giu.Update()

		// Get size of volume for showing progress
		stat, err := os.Stat(inputFile)
		if err != nil {
			removeTempInput()
			accessDenied("Read")
			return
		}
		total := stat.Size()

		// Rename input volume to free up the filename
		fin, err := os.Open(inputFile)
		if err != nil {
			removeTempInput()
			accessDenied("Read")
			return
		}
		for strings.HasSuffix(inputFile, ".tmp") {
			inputFile = strings.TrimSuffix(inputFile, ".tmp")
		}
		inputFile += ".tmp"
		if _, err := os.Stat(inputFile); err == nil {
			fin.Close()
			mainStatus = "Please remove " + filepath.Base(inputFile)
			mainStatusColor = RED
			inputFile = strings.TrimSuffix(inputFile, ".tmp")
			removeTempInput()
			return
		}
		fout, err := os.Create(inputFile)
		if err != nil {
			fin.Close()
			inputFile = strings.TrimSuffix(inputFile, ".tmp")
			removeTempInput()
			accessDenied("Write")
			return
		}
		unwrappedFile = inputFile

		// Get the Argon2 salt and XChaCha20 nonce from input volume
		salt := make([]byte, 16)
		nonce := make([]byte, 24)
		if n, err := fin.Read(salt); err != nil || n != 16 {
			broken(fin, fout, "The file is too short to be a volume", true)
			return
		}
		if n, err := fin.Read(nonce); err != nil || n != 24 {
			broken(fin, fout, "The file is too short to be a volume", true)
			return
		}

		// Generate key and XChaCha20
		key := argon2.IDKey([]byte(password), salt, 4, 1<<20, 4, 32)
		chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			panic(err)
		}

		// Decrypt the entire volume
		done, counter := 0, 0
		for {
			src := make([]byte, MiB)
			size, err := fin.Read(src)
			if err != nil {
				break
			}
			src = src[:size]
			dst := make([]byte, len(src))
			chacha.XORKeyStream(dst, src)
			if n, err := fout.Write(dst); err != nil || n != len(dst) {
				insufficientSpace(fin, fout)
				removeTempInput()
				return
			}

			// Update stats
			done += size
			counter += MiB
			progress = float32(float64(done) / float64(total))
			giu.Update()

			// Change nonce after 60 GiB to prevent overflow
			if counter >= 60*GiB {
				tmp := sha3.New256()
				if n, err := tmp.Write(nonce); err != nil || n != len(nonce) {
					panic(errors.New("failed to write nonce to tmp during rekeying"))
				}
				nonce = tmp.Sum(nil)[:24]
				chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
				if err != nil {
					panic(err)
				}
				counter = 0
			}
		}

		fin.Close()
		if err := fout.Close(); err != nil {
			insufficientSpace(nil, nil)
			removeTempInput()
			return
		}

		// Check if the version can be read from the volume
		fin, err = os.Open(inputFile)
		if err != nil {
			removeTempInput()
			accessDenied("Read")
			return
		}
		tmp := make([]byte, 15)
		if _, err := io.ReadFull(fin, tmp); err != nil {
			broken(fin, nil, "Password is incorrect or the file is not a volume", true)
			return
		}
		fin.Close()
		tmp, err = rsDecode(rs5, tmp)
		if valid, _ := regexp.Match(`^v[13]\.\d{2}`, tmp); err != nil || !valid {
			broken(nil, nil, "Password is incorrect or the file is not a volume", true)
			return
		}
	}

	canCancel = false
	progress = 0
	progressInfo = ""
	giu.Update()

	// The core: new volumes use the v3 format (src/volume); older volumes
	// are read by the v2 code below, which encryption also uses when tests
	// set 'legacyFormat'
	coreOK := false
	if (mode == "encrypt" && !legacyFormat) || (mode == "decrypt" && isV3Volume(inputFile)) {
		coreOK = workV3(func(r io.Reader) io.Reader {
			if tempZipInUse { // the temporary zip is encrypted on disk
				return &encryptedZipReader{_r: r, _cipher: tempZipCipherR}
			}
			return r
		})
	} else {
		func() {
			// Subtract the header size from the total size if decrypting
			stat, err := os.Stat(inputFile)
			if err != nil {
				removeTempInput()
				resetUI()
				accessDenied("Read")
				return
			}
			total := stat.Size()
			if mode == "decrypt" {
				total -= 789
			}

			// Open input file in read-only mode
			fin, err := os.Open(inputFile)
			if err != nil {
				removeTempInput()
				resetUI()
				accessDenied("Read")
				return
			}

			// Setup output file
			var fout *os.File

			// If encrypting, generate values and write to file
			if mode == "encrypt" {
				popupStatus = "Generating values..."
				giu.Update()

				// Stores any errors when writing to file
				errs := make([]error, 11)

				// Make sure not to overwrite anything
				_, err = os.Stat(outputFile)
				if split && err == nil { // File already exists
					fin.Close()
					removeTempInput()
					mainStatus = "Please remove " + filepath.Base(outputFile)
					mainStatusColor = RED
					return
				}

				// Create the output file
				fout, err = os.Create(outputFile + ".incomplete")
				if err != nil {
					fin.Close()
					removeTempInput()
					accessDenied("Write")
					return
				}

				// Set up cryptographic values
				salt = make([]byte, 16)
				hkdfSalt = make([]byte, 32)
				serpentIV = make([]byte, 16)
				nonce = make([]byte, 24)

				// Write the volume format version to file
				_, errs[0] = fout.Write(rsEncode(rs5, []byte(headerVersion)))

				if len(comments) > 99999 {
					fin.Close()
					fout.Close()
					removeTempInput()
					os.Remove(fout.Name())
					mainStatus = "Comment exceeds the maximum length of 99,999 characters"
					mainStatusColor = RED
					return
				}

				// Encode and write the comment length to file
				commentsLength := []byte(fmt.Sprintf("%05d", len(comments)))
				_, errs[1] = fout.Write(rsEncode(rs5, commentsLength))

				// Encode the comment and write to file
				for _, i := range []byte(comments) {
					_, err := fout.Write(rsEncode(rs1, []byte{i}))
					if err != nil {
						errs[2] = err
					}
				}

				// Configure flags and write to file
				flags = make([]byte, 5)
				if paranoid { // Paranoid mode selected
					flags[0] = 1
				}
				if len(keyfiles) > 0 { // Keyfiles are being used
					flags[1] = 1
				}
				if keyfileOrdered { // Order of keyfiles matter
					flags[2] = 1
				}
				if reedsolo { // Full Reed-Solomon encoding is selected
					flags[3] = 1
				}
				if total%int64(MiB) >= int64(MiB)-128 { // Reed-Solomon internals
					flags[4] = 1
				}
				_, errs[3] = fout.Write(rsEncode(rs5, flags))

				// Fill values with Go's CSPRNG
				if _, err := rand.Read(salt); err != nil {
					panic(err)
				}
				if _, err := rand.Read(hkdfSalt); err != nil {
					panic(err)
				}
				if _, err := rand.Read(serpentIV); err != nil {
					panic(err)
				}
				if _, err := rand.Read(nonce); err != nil {
					panic(err)
				}
				if bytes.Equal(salt, make([]byte, 16)) {
					panic(errors.New("fatal crypto/rand error"))
				}
				if bytes.Equal(hkdfSalt, make([]byte, 32)) {
					panic(errors.New("fatal crypto/rand error"))
				}
				if bytes.Equal(serpentIV, make([]byte, 16)) {
					panic(errors.New("fatal crypto/rand error"))
				}
				if bytes.Equal(nonce, make([]byte, 24)) {
					panic(errors.New("fatal crypto/rand error"))
				}

				// Encode values with Reed-Solomon and write to file
				_, errs[4] = fout.Write(rsEncode(rs16, salt))
				_, errs[5] = fout.Write(rsEncode(rs32, hkdfSalt))
				_, errs[6] = fout.Write(rsEncode(rs16, serpentIV))
				_, errs[7] = fout.Write(rsEncode(rs24, nonce))

				// Write placeholders for future use
				_, errs[8] = fout.Write(make([]byte, 192))  // HMAC-SHA3-512 of the header
				_, errs[9] = fout.Write(make([]byte, 96))   // Hash of keyfile key
				_, errs[10] = fout.Write(make([]byte, 192)) // BLAKE2b/HMAC-SHA3 tag

				for _, err := range errs {
					if err != nil {
						insufficientSpace(fin, fout)
						removeTempInput()
						os.Remove(fout.Name())
						return
					}
				}
			} else { // Decrypting, read values from file and decode
				popupStatus = "Reading values..."
				giu.Update()

				// Stores any Reed-Solomon decoding errors
				errs := make([]error, 10)

				// Read a fixed-size header field, remembering if the file ended early
				short := false
				readField := func(n int) []byte {
					b := make([]byte, n)
					if _, err := io.ReadFull(fin, b); err != nil {
						short = true
					}
					return b
				}

				_, errs[0] = rsDecode(rs5, readField(15))

				tmp, err := rsDecode(rs5, readField(15))
				errs[1] = err

				if valid, err := regexp.Match(`^\d{5}$`, tmp); !valid || err != nil {
					broken(fin, nil, "Unable to read comments length", true)
					return
				}

				commentsLength, _ := strconv.Atoi(string(tmp))
				readField(commentsLength * 3)
				total -= int64(commentsLength) * 3

				flags, errs[2] = rsDecode(rs5, readField(15))
				paranoid = flags[0] == 1
				reedsolo = flags[3] == 1
				padded = flags[4] == 1
				if deniability {
					keyfile = flags[1] == 1
					keyfileOrdered = flags[2] == 1
				}

				salt, errs[3] = rsDecode(rs16, readField(48))
				hkdfSalt, errs[4] = rsDecode(rs32, readField(96))
				serpentIV, errs[5] = rsDecode(rs16, readField(48))
				nonce, errs[6] = rsDecode(rs24, readField(72))
				headerMACRef, errs[7] = rsDecode(rs64, readField(192))
				keyfileHashRef, errs[8] = rsDecode(rs32, readField(96))
				authTag, errs[9] = rsDecode(rs64, readField(192))

				if short { // nothing to decrypt, even when forcing
					broken(fin, nil, "The file is too short to be a volume", true)
					return
				}

				// If there was an issue during decoding, the header is corrupted
				for _, err := range errs {
					if err != nil {
						if keep { // If the user chooses to force decrypt
							kept = true
						} else {
							broken(fin, nil, "The volume header is damaged", true)
							return
						}
					}
				}
			}

			// A deniable volume only reveals that it needs keyfiles once unwrapped
			if mode == "decrypt" && keyfile && len(keyfiles) == 0 {
				broken(fin, nil, "This volume requires keyfiles, please select them", true)
				return
			}

			popupStatus = "Deriving key..."
			giu.Update()

			// Derive encryption keys and subkeys
			var key []byte
			if paranoid {
				key = argon2.IDKey(
					[]byte(password),
					salt,
					8,     // 8 passes
					1<<20, // 1 GiB memory
					8,     // 8 threads
					32,    // 32-byte output key
				)
			} else {
				key = argon2.IDKey(
					[]byte(password),
					salt,
					4,
					1<<20,
					4,
					32,
				)
			}
			if bytes.Equal(key, make([]byte, 32)) {
				panic(errors.New("fatal crypto/argon2 error"))
			}

			// If keyfiles are being used
			if len(keyfiles) > 0 || keyfile {
				popupStatus = "Reading keyfiles..."
				giu.Update()

				var duplicate bool
				var err error
				keyfileKey, duplicate, err = hashKeyfiles(keyfiles, keyfileOrdered)
				if err != nil {
					fin.Close()
					removeTempInput()
					if fout != nil {
						fout.Close()
						os.Remove(fout.Name())
					}
					accessDenied("Keyfile read")
					return
				}

				// Unordered keyfiles are XORed together, so two with identical
				// contents cancel out and silently stop protecting the volume.
				// Only refuse when encrypting: older volumes may already use them.
				if mode == "encrypt" && duplicate {
					fin.Close()
					removeTempInput()
					fout.Close()
					os.Remove(fout.Name())
					mainStatus = "Duplicate keyfiles detected"
					mainStatusColor = RED
					return
				}

				// Only compared against volumes made before v2.1.0, which stored it
				tmp := sha3.New256()
				if _, err := tmp.Write(keyfileKey); err != nil {
					panic(err)
				}
				keyfileHash = tmp.Sum(nil)
			}

			popupStatus = "Calculating values..."
			giu.Update()

			var passwordKey []byte // pre-keyfile key, only to recognize v1.50/1.51 volumes
			if len(keyfiles) > 0 || keyfile {
				// Prevent an even number of duplicate keyfiles
				if bytes.Equal(keyfileKey, make([]byte, 32)) {
					mainStatus = "Duplicate keyfiles detected"
					mainStatusColor = RED
					fin.Close()
					removeTempInput()
					if fout != nil {
						fout.Close()
						os.Remove(fout.Name())
					}
					return
				}

				// XOR the encryption key with the keyfile key
				tmp := key
				passwordKey = tmp
				key = make([]byte, 32)
				for i := range key {
					key[i] = tmp[i] ^ keyfileKey[i]
				}
			}

			// Authenticate the header's decryption parameters (flags, salts, IVs) with
			// an HMAC keyed by a subkey independent from the data-encryption and
			// data-MAC keys. A successful comparison proves both a correct password
			// and keyfiles, and an untampered header, replacing the old bare hash of
			// the key. The subkey is derived after the keyfile key is mixed in (v2.0.0):
			// otherwise a keyfile-only volume's header MAC would depend only on an
			// empty password, letting anyone forge it.
			// The comment field is intentionally excluded (see the UI tooltip warning
			// that comments aren't tamper-protected): it isn't re-derived from disk
			// during decryption, so including it here could cause spurious failures.
			headerMAC = computeHeaderMAC(key, hkdfSalt, flags, salt, hkdfSalt, serpentIV, nonce)

			// Validate the password and/or keyfiles
			if mode == "decrypt" {
				keyCorrect := subtle.ConstantTimeCompare(headerMAC, headerMACRef) == 1

				// Since v2.1.0 the keyfile hash isn't stored (it's all zeros): it let
				// anyone test keyfile guesses at hash speed, separately from the
				// password. The header MAC alone already verifies the keyfiles.
				keyfileHashStored := !bytes.Equal(keyfileHashRef, make([]byte, 32))
				keyfileCorrect := !keyfileHashStored ||
					subtle.ConstantTimeCompare(keyfileHash, keyfileHashRef) == 1
				incorrect := !keyCorrect
				if keyfile || len(keyfiles) > 0 {
					incorrect = !keyCorrect || !keyfileCorrect
				}

				// If something is incorrect
				if incorrect {
					if keep {
						kept = true
					} else {
						// Wrong keyfiles also fail the header MAC, so check them first
						if (keyfile || len(keyfiles) > 0) && !keyfileCorrect {
							if keyfileOrdered {
								mainStatus = "Incorrect keyfiles or ordering"
							} else {
								mainStatus = "Incorrect keyfiles"
							}
						} else if passwordKey != nil && subtle.ConstantTimeCompare(headerMACRef,
							computeHeaderMAC(passwordKey, hkdfSalt, flags, salt, hkdfSalt, serpentIV, nonce)) == 1 {
							// v2.0.0 changed the header MAC for keyfile volumes. The old
							// MAC is only recognized for this message, never accepted:
							// without a password anyone can forge it.
							mainStatus = "This keyfile volume was made with ZeeCrypt v1.50/1.51 and can't be opened by this version"
						} else if (keyfile || len(keyfiles) > 0) && !keyfileHashStored {
							// Nothing separates a wrong password from wrong keyfiles anymore
							mainStatus = "The password or keyfiles are incorrect, or the file has been tampered with"
						} else {
							mainStatus = "The provided password is incorrect, or the file has been tampered with"
						}
						broken(fin, nil, mainStatus, true)
						return
					}
				}

				// Create the output file for decryption
				fout, err = os.Create(outputFile + ".incomplete")
				if err != nil {
					fin.Close()
					removeTempInput()
					accessDenied("Write")
					return
				}
			}

			done, counter := 0, 0
			chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
			if err != nil {
				panic(err)
			}

			// Use HKDF-SHA3 to generate a subkey for the MAC
			var mac hash.Hash
			subkey := make([]byte, 32)
			hkdf := hkdf.New(sha3.New256, key, hkdfSalt, nil)
			if n, err := hkdf.Read(subkey); err != nil || n != 32 {
				panic(errors.New("fatal hkdf.Read error"))
			}
			if paranoid {
				mac = hmac.New(sha3.New512, subkey) // HMAC-SHA3
			} else {
				mac, err = blake2b.New512(subkey) // Keyed BLAKE2b
				if err != nil {
					panic(err)
				}
			}

			// Generate another subkey for use as Serpent's key
			serpentKey := make([]byte, 32)
			if n, err := hkdf.Read(serpentKey); err != nil || n != 32 {
				panic(errors.New("fatal hkdf.Read error"))
			}
			s, err := serpent.NewCipher(serpentKey)
			if err != nil {
				panic(err)
			}
			serpent := cipher.NewCTR(s, serpentIV)

			// Start the main encryption process
			canCancel = true
			startTime := time.Now()
			tempZip := encryptedZipReader{
				_r:      fin,
				_cipher: tempZipCipherR,
			}
			for {
				if !working {
					cancel(fin, fout)
					removeTempInput()
					os.Remove(fout.Name())
					return
				}

				// Read in data from the file
				var src []byte
				if mode == "decrypt" && reedsolo {
					src = make([]byte, MiB/128*136)
				} else {
					src = make([]byte, MiB)
				}

				var size int
				if tempZipInUse {
					size, err = tempZip.Read(src)
				} else {
					size, err = fin.Read(src)
				}
				if err != nil {
					break
				}
				src = src[:size]
				dst := make([]byte, len(src))

				// Do the actual encryption
				if mode == "encrypt" {
					if paranoid {
						serpent.XORKeyStream(dst, src)
						copy(src, dst)
					}

					chacha.XORKeyStream(dst, src)
					if _, err := mac.Write(dst); err != nil {
						panic(err)
					}

					if reedsolo {
						copy(src, dst)
						dst = nil
						// If a full MiB is available
						if len(src) == MiB {
							// Encode every chunk
							for i := 0; i < MiB; i += 128 {
								dst = append(dst, rsEncode(rs128, src[i:i+128])...)
							}
						} else {
							// Encode the full chunks
							chunks := math.Floor(float64(len(src)) / 128)
							for i := 0; float64(i) < chunks; i++ {
								dst = append(dst, rsEncode(rs128, src[i*128:(i+1)*128])...)
							}

							// Pad and encode the final partial chunk
							dst = append(dst, rsEncode(rs128, pad(src[int(chunks*128):]))...)
						}
					}
				} else { // Decryption
					if reedsolo {
						copy(dst, src)
						src = nil
						// If a complete 1 MiB block is available
						if len(dst) == MiB/128*136 {
							// Decode every chunk
							for i := 0; i < MiB/128*136; i += 136 {
								tmp, err := rsDecode(rs128, dst[i:i+136])
								if err != nil {
									if keep {
										kept = true
									} else {
										broken(fin, fout, "The input file is irrecoverably damaged", false)
										return
									}
								}
								if i == MiB/128*136-136 && done+MiB/128*136 >= int(total) && padded {
									tmp = unpad(tmp)
								}
								src = append(src, tmp...)

								if !fastDecode && i%17408 == 0 {
									progress, speed, eta = statify(int64(done+i), total, startTime)
									progressInfo = fmt.Sprintf("%.2f%%", progress*100)
									popupStatus = fmt.Sprintf("Repairing at %.2f MiB/s (ETA: %s)", speed, eta)
									giu.Update()
								}
							}
						} else if len(dst) < 136 {
							// A trailing fragment smaller than one encoded chunk can only
							// come from a truncated or appended-to file
							if keep {
								kept = true
							} else {
								broken(fin, fout, "The input file is irrecoverably damaged", false)
								return
							}
						} else {
							// Decode the full chunks
							chunks := len(dst)/136 - 1
							for i := range chunks {
								tmp, err := rsDecode(rs128, dst[i*136:(i+1)*136])
								if err != nil {
									if keep {
										kept = true
									} else {
										broken(fin, fout, "The input file is irrecoverably damaged", false)
										return
									}
								}
								src = append(src, tmp...)

								if !fastDecode && i%128 == 0 {
									progress, speed, eta = statify(int64(done+i*136), total, startTime)
									progressInfo = fmt.Sprintf("%.2f%%", progress*100)
									popupStatus = fmt.Sprintf("Repairing at %.2f MiB/s (ETA: %s)", speed, eta)
									giu.Update()
								}
							}

							// Unpad and decode the final partial chunk
							tmp, err := rsDecode(rs128, dst[int(chunks)*136:])
							if err != nil {
								if keep {
									kept = true
								} else {
									broken(fin, fout, "The input file is irrecoverably damaged", false)
									return
								}
							}
							src = append(src, unpad(tmp)...)
						}
						dst = make([]byte, len(src))
					}

					if _, err := mac.Write(src); err != nil {
						panic(err)
					}
					chacha.XORKeyStream(dst, src)

					if paranoid {
						copy(src, dst)
						serpent.XORKeyStream(dst, src)
					}
				}

				// Write the data to output file
				_, err = fout.Write(dst)
				if err != nil {
					insufficientSpace(fin, fout)
					removeTempInput()
					os.Remove(fout.Name())
					return
				}

				// Update stats
				if mode == "decrypt" && reedsolo {
					done += MiB / 128 * 136
				} else {
					done += MiB
				}
				counter += MiB
				progress, speed, eta = statify(int64(done), total, startTime)
				progressInfo = fmt.Sprintf("%.2f%%", progress*100)
				if mode == "encrypt" {
					popupStatus = fmt.Sprintf("Encrypting at %.2f MiB/s (ETA: %s)", speed, eta)
				} else {
					if fastDecode {
						popupStatus = fmt.Sprintf("Decrypting at %.2f MiB/s (ETA: %s)", speed, eta)
					}
				}
				giu.Update()

				// Change nonce/IV after 60 GiB to prevent overflow
				if counter >= 60*GiB {
					// ChaCha20
					nonce = make([]byte, 24)
					if n, err := hkdf.Read(nonce); err != nil || n != 24 {
						panic(errors.New("fatal hkdf.Read error"))
					}
					chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
					if err != nil {
						panic(err)
					}

					// Serpent
					serpentIV = make([]byte, 16)
					if n, err := hkdf.Read(serpentIV); err != nil || n != 16 {
						panic(errors.New("fatal hkdf.Read error"))
					}
					serpent = cipher.NewCTR(s, serpentIV)

					// Reset counter to 0
					counter = 0
				}
			}

			progress = 0
			progressInfo = ""
			giu.Update()

			if mode == "encrypt" {
				popupStatus = "Writing values..."
				giu.Update()

				// Seek back to header and write important values
				// The keyfile-hash field is left as zeros: see 'keyfileHashStored'
				var errs [4]error
				_, errs[0] = fout.Seek(int64(309+len(comments)*3), 0)
				_, errs[1] = fout.Write(rsEncode(rs64, headerMAC))
				_, errs[2] = fout.Write(rsEncode(rs32, make([]byte, 32)))
				_, errs[3] = fout.Write(rsEncode(rs64, mac.Sum(nil)))
				for _, err := range errs {
					if err != nil {
						insufficientSpace(fin, fout)
						removeTempInput()
						os.Remove(fout.Name())
						return
					}
				}
			} else {
				popupStatus = "Comparing values..."
				giu.Update()

				// Validate the authenticity of decrypted data
				if subtle.ConstantTimeCompare(mac.Sum(nil), authTag) == 0 {
					// Decrypt again but this time rebuilding the input data
					if reedsolo && fastDecode {
						fastDecode = false
						fin.Close()
						fout.Close()
						os.Remove(fout.Name()) // unverified fast-pass output
						work(true)
						return
					}

					if keep {
						kept = true
					} else {
						broken(fin, fout, "The input file is damaged or modified", false)
						return
					}
				}
			}

			fin.Close()
			if err := fout.Close(); err != nil {
				insufficientSpace(nil, nil)
				removeTempInput()
				os.Remove(fout.Name())
				return
			}

			if err := os.Rename(outputFile+".incomplete", outputFile); err != nil {
				// Usually the file being replaced is open in another program
				os.Remove(outputFile + ".incomplete")
				removeTempInput()
				mainStatus = "Couldn't save " + filepath.Base(outputFile) + " (is it open in another program?)"
				mainStatusColor = RED
				return
			}
			coreOK = true
		}()
	}
	if !coreOK {
		return
	}

	// Add plausible deniability
	if mode == "encrypt" && deniability {
		popupStatus = "Adding plausible deniability..."
		canCancel = false
		giu.Update()

		// On failure, never leave the volume behind without its deniability
		// layer: its header would show that it's a ZeeCrypt volume
		var fin, fout *os.File
		denyFail := func(message string) {
			fin.Close()
			fout.Close()
			os.Remove(outputFile + ".incomplete")
			os.Remove(outputFile + ".tmp")
			os.Remove(outputFile)
			removeTempInput()
			mainStatus = message
			mainStatusColor = RED
		}

		// Get size of volume for showing progress
		stat, err := os.Stat(outputFile)
		if err != nil {
			denyFail("Read access denied by operating system")
			return
		}
		total := stat.Size()

		// Rename the output volume to free up the filename
		if _, err := os.Stat(outputFile + ".tmp"); err == nil {
			os.Remove(outputFile)
			removeTempInput()
			mainStatus = "Please remove " + filepath.Base(outputFile+".tmp")
			mainStatusColor = RED
			return
		}
		if err := os.Rename(outputFile, outputFile+".tmp"); err != nil {
			denyFail("Write access denied by operating system")
			return
		}
		fin, err = os.Open(outputFile + ".tmp")
		if err != nil {
			denyFail("Read access denied by operating system")
			return
		}
		fout, err = os.Create(outputFile + ".incomplete")
		if err != nil {
			denyFail("Write access denied by operating system")
			return
		}

		// Use a random Argon2 salt and XChaCha20 nonce
		salt := make([]byte, 16)
		nonce := make([]byte, 24)
		if n, err := rand.Read(salt); err != nil || n != 16 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if n, err := rand.Read(nonce); err != nil || n != 24 {
			panic(errors.New("fatal crypto/rand error"))
		}
		if bytes.Equal(salt, make([]byte, 16)) || bytes.Equal(nonce, make([]byte, 24)) {
			panic(errors.New("fatal crypto/rand error"))
		}
		_, err1 := fout.Write(salt)
		_, err2 := fout.Write(nonce)
		if err1 != nil || err2 != nil {
			denyFail("Insufficient disk space")
			return
		}

		// Generate key and XChaCha20
		key := argon2.IDKey([]byte(password), salt, 4, 1<<20, 4, 32)
		if bytes.Equal(key, make([]byte, 32)) {
			panic(errors.New("fatal crypto/argon2 error"))
		}
		chacha, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			panic(err)
		}

		// Encrypt the entire volume
		done, counter := 0, 0
		for {
			src := make([]byte, MiB)
			size, err := fin.Read(src)
			if err != nil {
				break
			}
			src = src[:size]
			dst := make([]byte, len(src))
			chacha.XORKeyStream(dst, src)
			if _, err := fout.Write(dst); err != nil {
				denyFail("Insufficient disk space")
				return
			}

			// Update stats
			done += size
			counter += MiB
			progress = float32(float64(done) / float64(total))
			giu.Update()

			// Change nonce after 60 GiB to prevent overflow
			if counter >= 60*GiB {
				tmp := sha3.New256()
				if _, err := tmp.Write(nonce); err != nil {
					panic(err)
				}
				nonce = tmp.Sum(nil)[:24]
				chacha, err = chacha20.NewUnauthenticatedCipher(key, nonce)
				if err != nil {
					panic(err)
				}
				counter = 0
			}
		}

		fin.Close()
		if err := fout.Close(); err != nil {
			fout = nil
			denyFail("Insufficient disk space")
			return
		}
		if err := os.Rename(outputFile+".incomplete", outputFile); err != nil {
			denyFail("Write access denied by operating system")
			return
		}
		if err := os.Remove(fin.Name()); err != nil {
			// The finished deniable volume is in place; the leftover
			// is the same volume without its deniability layer
			mainStatus = "Couldn't delete " + filepath.Base(fin.Name()) + ", delete it manually"
			mainStatusColor = RED
			removeTempInput()
			return
		}
		canCancel = true
		giu.Update()
	}

	// Files that couldn't be deleted at the end are reported, not fatal
	var leftovers []string
	removeOrNote := func(path string) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			leftovers = append(leftovers, filepath.Base(path))
		}
	}

	// Split the file into chunks
	if split {
		var splitted []string // chunks written so far (still ".incomplete")
		var fin *os.File

		// Remove everything splitting made, and the unsplit volume
		splitFail := func(fout *os.File, message string) {
			fin.Close()
			fout.Close()
			removeTempInput()
			os.Remove(outputFile)
			for _, j := range splitted {
				os.Remove(j)
			}
			if message != "" {
				mainStatus = message
				mainStatusColor = RED
			}
		}

		stat, err := os.Stat(outputFile)
		if err != nil {
			splitFail(nil, "Read access denied by operating system")
			return
		}
		size := stat.Size()
		finishedFiles := 0
		finishedBytes := 0
		chunkSize, err := strconv.Atoi(splitSize)
		if err != nil || chunkSize <= 0 {
			splitFail(nil, "Invalid chunk size")
			return
		}

		// Calculate chunk size
		if splitSelected == 0 {
			chunkSize *= KiB
		} else if splitSelected == 1 {
			chunkSize *= MiB
		} else if splitSelected == 2 {
			chunkSize *= GiB
		} else if splitSelected == 3 {
			chunkSize *= TiB
		} else {
			chunkSize = int(math.Ceil(float64(size) / float64(chunkSize)))
		}

		// Get the number of required chunks
		chunks := int(math.Ceil(float64(size) / float64(chunkSize)))
		progressInfo = fmt.Sprintf("%d/%d", finishedFiles+1, chunks)
		giu.Update()

		// Open the volume for reading
		fin, err = os.Open(outputFile)
		if err != nil {
			splitFail(nil, "Read access denied by operating system")
			return
		}

		// Delete existing chunks to prevent mixed chunks. Only "<name>.<number>"
		// files are chunks; other files that share the name prefix are kept.
		for _, old := range existingChunks(outputFile) {
			if err := os.Remove(old); err != nil {
				splitFail(nil, "Couldn't remove the old chunk "+filepath.Base(old))
				return
			}
		}

		// Start the splitting process
		startTime := time.Now()
		for i := range chunks {
			// Make the chunk
			name := fmt.Sprintf("%s.%d.incomplete", outputFile, i)
			fout, err := os.Create(name)
			if err != nil {
				splitFail(nil, "Write access denied by operating system")
				return
			}
			splitted = append(splitted, name)
			done := 0

			// Copy data into the chunk
			for {
				data := make([]byte, MiB)
				for done+len(data) > chunkSize {
					data = make([]byte, int(math.Ceil(float64(len(data))/2)))
				}

				read, err := fin.Read(data)
				if err != nil {
					break
				}
				if !working {
					splitFail(fout, "")
					cancel(nil, nil)
					return
				}

				data = data[:read]
				if _, err := fout.Write(data); err != nil {
					splitFail(fout, "Insufficient disk space")
					return
				}
				done += read
				finishedBytes += read
				if done >= chunkSize {
					break
				}

				// Update stats
				progress, speed, eta = statify(int64(finishedBytes), int64(size), startTime)
				popupStatus = fmt.Sprintf("Splitting at %.2f MiB/s (ETA: %s)", speed, eta)
				giu.Update()
			}
			if err := fout.Close(); err != nil {
				splitFail(nil, "Insufficient disk space")
				return
			}

			// Update stats
			finishedFiles++
			if finishedFiles == chunks {
				finishedFiles--
			}
			progressInfo = fmt.Sprintf("%d/%d", finishedFiles+1, chunks)
			giu.Update()
		}

		fin.Close()
		for k, j := range splitted {
			if err := os.Rename(j, strings.TrimSuffix(j, ".incomplete")); err != nil {
				for _, f := range splitted[:k] {
					os.Remove(strings.TrimSuffix(f, ".incomplete"))
				}
				splitFail(nil, "Write access denied by operating system")
				return
			}
		}
		removeOrNote(outputFile)
	}

	canCancel = false
	progress = 0
	progressInfo = ""
	giu.Update()

	// Delete temporary files used during encryption and decryption (the
	// temporary zip, recombined volume and unwrapped deniable volume). This
	// also points 'inputFile' back at what the user selected.
	removeTempInput()

	// Delete the input files if the user chooses. A volume that failed
	// verification and was force-decrypted is kept, so it can be retried.
	if delete && !kept {
		popupStatus = "Deleting files..."
		giu.Update()

		if mode == "decrypt" {
			if recombine { // Remove each chunk of volume
				for i := 0; ; i++ {
					chunk := fmt.Sprintf("%s.%d", inputFileOld, i)
					if _, err := os.Stat(chunk); err != nil {
						break
					}
					removeOrNote(chunk)
				}
			} else {
				removeOrNote(inputFile)
			}
		} else {
			for _, i := range onlyFiles {
				removeOrNote(i)
			}
			for _, i := range onlyFolders {
				if err := os.RemoveAll(i); err != nil {
					leftovers = append(leftovers, filepath.Base(i))
				}
			}
		}
	}

	if mode == "decrypt" && !kept && autoUnzip {
		showProgress = true
		popupStatus = "Unzipping..."
		giu.Update()

		if err := unpackArchive(outputFile); err != nil {
			mainStatus = "Auto unzipping failed!"
			mainStatusColor = RED
			giu.Update()
			return
		}

		removeOrNote(outputFile)
	}

	// All done, reset the UI
	oldKept := kept
	resetUI()
	kept = oldKept

	// If the user chose to keep a corrupted/modified file, let them know
	if kept {
		mainStatus = "The input file was modified. Please be careful"
		mainStatusColor = YELLOW
	} else if len(leftovers) > 0 {
		mainStatus = "Completed, but couldn't delete: " + strings.Join(leftovers, ", ")
		mainStatusColor = YELLOW
	} else {
		mainStatus = "Completed"
		mainStatusColor = GREEN
	}
}

// If the OS denies reading or writing to a file
func accessDenied(s string) {
	mainStatus = s + " access denied by operating system"
	mainStatusColor = RED
}

// If there isn't enough disk space
func insufficientSpace(fin *os.File, fout *os.File) {
	fin.Close()
	fout.Close()
	mainStatus = "Insufficient disk space"
	mainStatusColor = RED
}

// If corruption is detected during decryption
func broken(fin *os.File, fout *os.File, message string, keepOutput bool) {
	fin.Close()
	fout.Close()
	mainStatus = message
	mainStatusColor = RED

	// Clean up files since decryption failed. The output is only ever
	// written to the ".incomplete" file; 'outputFile' itself may be an
	// existing file the user chose to overwrite, so it's left alone.
	removeTempInput()
	if !keepOutput {
		os.Remove(outputFile + ".incomplete")
	}
}

// Remove the temporary input that work() prepared: the zip of the selected
// items when encrypting, or the recombined and/or unwrapped deniable volume
// when decrypting. 'inputFile' is restored to what the user selected so the
// operation can be retried (e.g. with the correct password).
func removeTempInput() {
	if tempZipFile != "" {
		os.Remove(tempZipFile)
		tempZipFile = ""
	}
	if unwrappedFile != "" {
		os.Remove(unwrappedFile)
		unwrappedFile = ""
		inputFile = strings.TrimSuffix(inputFile, ".tmp")
	}
	if recombinedFile != "" {
		os.Remove(recombinedFile)
		recombinedFile = ""
		inputFile = inputFileOld
	}
}

// Stop working if user hits "Cancel"
func cancel(fin *os.File, fout *os.File) {
	fin.Close()
	fout.Close()
	mainStatus = "Operation cancelled by user"
	mainStatusColor = NEUTRAL
}

// Reset the UI to a clean state with nothing selected or checked
func resetUI() {
	imgui.ClearActiveID()
	mode = ""

	inputFile = ""
	inputFileOld = ""
	outputFile = ""
	onlyFiles = nil
	onlyFolders = nil
	allFiles = nil
	allDirs = nil
	inputLabel = "Drop files and folders into this window"

	password = ""
	cpassword = ""
	passwordState = giu.InputTextFlagsPassword
	passwordStateLabel = "Show"

	passgenLength = 32
	passgenUpper = true
	passgenLower = true
	passgenNums = true
	passgenSymbols = true
	passgenCopy = true

	keyfile = false
	keyfiles = nil
	keyfileOrdered = false
	keyfileLabel = "None selected"

	comments = ""
	commentsLabel = "Comments:"
	commentsDisabled = false

	paranoid = false
	reedsolo = false
	deniability = false
	recursively = false
	split = false
	splitSize = ""
	splitSelected = 1
	recombine = false
	compress = false
	compressLevel = 0
	delete = false
	autoUnzip = false
	sameLevel = false
	keep = false
	kept = false

	startLabel = "Start"
	mainStatus = "Ready"
	mainStatusColor = NEUTRAL
	popupStatus = ""
	requiredFreeSpace = 0

	progress = 0
	progressInfo = ""
	giu.Update()
}

const deniabilityNeedsPassword = "Deniability requires a password (keyfiles alone can't protect it)"

// A chunk of a split volume: "<name>.pcv.<number>"
var splitChunkRegex = regexp.MustCompile(`\.pcv\.\d+$`)

// The window's drop callback. Dropping while an operation runs (or while the
// overwrite prompt waits) would reset the very state work() is using: mode,
// output path, password, options and the file lists.
func onWindowDrop(names []string) {
	if working || showProgress || showOverwrite || updateApplying {
		return
	}
	onDrop(names)
}

// forcedMode is "encrypt" or "decrypt" while onDropMode runs a drop that came
// from an Explorer verb, overriding the usual detection by file name
var forcedMode string

// onDropMode is onDrop with an explicit mode ("" = detect from the names)
func onDropMode(names []string, mode string) {
	forcedMode = mode
	defer func() { forcedMode = "" }()
	onDrop(names)
}

// existingChunks returns the split chunks ("<base>.<number>") that exist for
// 'base'. Listing the folder instead of globbing avoids treating characters
// like '[' in file names as patterns, and never matches unrelated files that
// merely start with the same name (e.g. "<base>.notes.txt").
func existingChunks(base string) []string {
	ents, err := os.ReadDir(filepath.Dir(base))
	if err != nil {
		return nil
	}
	prefix := filepath.Base(base) + "."
	var found []string
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix) {
			continue
		}
		if _, err := strconv.ParseUint(name[len(prefix):], 10, 64); err == nil {
			found = append(found, filepath.Join(filepath.Dir(base), name))
		}
	}
	return found
}

// outputExists reports whether the current operation would replace a file
func outputExists() bool {
	if split && mode == "encrypt" {
		if len(existingChunks(outputFile)) > 0 {
			return true
		}
	}
	_, err := os.Stat(outputFile)
	return err == nil
}

// recursiveSummary is the final status line of a recursive run
func recursiveSummary(total, skipped, failed int) (string, color.RGBA) {
	if skipped == 0 && failed == 0 {
		return "Completed", GREEN
	}
	var parts []string
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped (output already exists)", skipped))
	}
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", failed))
	}
	done := total - skipped - failed
	return fmt.Sprintf("Processed %d of %d files; %s", done, total, strings.Join(parts, ", ")), YELLOW
}

// hashKeyfiles derives the keyfile key. Ordered: SHA3-256 over all keyfiles
// in sequence. Unordered: the XOR of each keyfile's SHA3-256. 'duplicate'
// reports that two keyfiles have identical contents, which in unordered mode
// cancel each other out.
func hashKeyfiles(paths []string, ordered bool) (key []byte, duplicate bool, err error) {
	var total, done int64
	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			return nil, false, err
		}
		total += stat.Size()
	}

	hashFile := func(h hash.Hash, path string) error {
		fin, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fin.Close()
		data := make([]byte, MiB)
		for {
			size, err := fin.Read(data)
			if size > 0 {
				h.Write(data[:size])
				done += int64(size)
				progress = float32(done) / float32(total)
				giu.Update()
			}
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}

	if ordered {
		h := sha3.New256()
		for _, path := range paths {
			if err := hashFile(h, path); err != nil {
				return nil, false, err
			}
		}
		return h.Sum(nil), false, nil
	}

	seen := map[string]bool{}
	for _, path := range paths {
		h := sha3.New256()
		if err := hashFile(h, path); err != nil {
			return nil, false, err
		}
		sum := h.Sum(nil)
		if seen[string(sum)] {
			duplicate = true
		}
		seen[string(sum)] = true
		if key == nil {
			key = sum
		} else {
			for i, j := range sum {
				key[i] ^= j
			}
		}
	}
	return key, duplicate, nil
}

// zipNamer names zip entries relative to the folder that each dropped item
// came from, so items dropped from different folders (or drives) never
// produce absolute paths, and makes clashing file names unique
type zipNamer struct {
	files   []string
	folders []string
	used    map[string]bool
}

func newZipNamer(files, folders []string) *zipNamer {
	return &zipNamer{files: files, folders: folders, used: map[string]bool{}}
}

func (z *zipNamer) relative(path string) string {
	for _, f := range z.folders {
		if path == f || strings.HasPrefix(path, strings.TrimSuffix(f, string(filepath.Separator))+string(filepath.Separator)) {
			if rel, err := filepath.Rel(filepath.Dir(f), path); err == nil {
				return filepath.ToSlash(rel)
			}
		}
	}
	return filepath.Base(path)
}

func (z *zipNamer) dirName(path string) string {
	name := z.relative(path) + "/"
	z.used[strings.ToLower(name)] = true
	return name
}

func (z *zipNamer) fileName(path string) string {
	name := z.relative(path)
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 2; z.used[strings.ToLower(name)]; i++ {
		name = fmt.Sprintf("%s (%d)%s", stem, i, ext)
	}
	z.used[strings.ToLower(name)] = true
	return name
}

// outputNameFromDialog turns the name picked in the "Save output as" dialog
// into the output path. The dialog asks for a name without extensions: if
// the user typed the ones this operation adds anyway, they're not doubled,
// and other dots are kept (so "backup.2026.11" stays intact).
func outputNameFromDialog(file string) string {
	var ext string
	if mode == "encrypt" {
		if len(allFiles) > 1 || len(onlyFolders) > 0 {
			ext = archiveExt() + ".pcv"
		} else {
			ext = filepath.Ext(inputFile) + ".pcv"
		}
	} else if strings.HasSuffix(inputFile, ".tar.zst.pcv") {
		ext = ".tar.zst"
	} else if strings.HasSuffix(inputFile, ".zip.pcv") {
		ext = ".zip"
	} else {
		ext = filepath.Ext(strings.TrimSuffix(filepath.Base(inputFile), ".pcv"))
	}

	name := filepath.Base(file)
	for _, s := range []string{ext, ".pcv", strings.TrimSuffix(ext, ".pcv")} {
		if s != "" && len(name) > len(s) && strings.EqualFold(name[len(name)-len(s):], s) {
			name = name[:len(name)-len(s)]
			break
		}
	}
	return filepath.Join(filepath.Dir(file), name+ext)
}

// Windows clipboard access, used for passwords instead of GLFW's so they can
// be kept out of clipboard history and cloud sync, and cleared afterwards
var (
	user32                         = syscall.NewLazyDLL("user32.dll")
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procEmptyClipboard             = user32.NewProc("EmptyClipboard")
	procSetClipboardData           = user32.NewProc("SetClipboardData")
	procRegisterClipboardFormatW   = user32.NewProc("RegisterClipboardFormatW")
	procGetClipboardSequenceNumber = user32.NewProc("GetClipboardSequenceNumber")
	procGlobalAlloc                = kernel32.NewProc("GlobalAlloc")
	procGlobalLock                 = kernel32.NewProc("GlobalLock")
	procGlobalUnlock               = kernel32.NewProc("GlobalUnlock")
	procGlobalFree                 = kernel32.NewProc("GlobalFree")
	procRtlMoveMemory              = kernel32.NewProc("RtlMoveMemory")
)

const clipboardClearDelay = 30 * time.Second

func openClipboard() bool {
	for range 10 { // another program may hold it briefly
		if r, _, _ := procOpenClipboard.Call(0); r != 0 {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// clipboardPut copies 'data' into a new global memory block and hands it to
// the clipboard (which then owns it). The clipboard must be open.
func clipboardPut(format uintptr, data []byte) bool {
	const gmemMoveable = 0x0002
	h, _, _ := procGlobalAlloc.Call(gmemMoveable, uintptr(len(data)))
	if h == 0 {
		return false
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return false
	}
	procRtlMoveMemory.Call(p, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
	procGlobalUnlock.Call(h)
	if r, _, _ := procSetClipboardData.Call(format, h); r == 0 {
		procGlobalFree.Call(h)
		return false
	}
	return true
}

// setSecretClipboard copies a password to the clipboard, marked so Windows
// leaves it out of clipboard history (Win+V) and cloud clipboard sync, and
// clears it after 'clipboardClearDelay' unless something else was copied
func setSecretClipboard(text string) {
	if text == "" {
		return
	}
	utf16Text, err := syscall.UTF16FromString(text)
	if err != nil { // contains NUL; can't be typed or pasted anyway
		return
	}
	if !openClipboard() {
		return
	}
	procEmptyClipboard.Call()
	const cfUnicodeText = 13
	buf := make([]byte, len(utf16Text)*2)
	for i, c := range utf16Text {
		buf[2*i], buf[2*i+1] = byte(c), byte(c>>8)
	}
	clipboardPut(cfUnicodeText, buf)
	for _, name := range []string{
		"ExcludeClipboardContentFromMonitorProcessing",
		"CanIncludeInClipboardHistory",
		"CanUploadToCloudClipboard",
	} {
		namePtr, _ := syscall.UTF16PtrFromString(name)
		if format, _, _ := procRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(namePtr))); format != 0 {
			clipboardPut(format, make([]byte, 4)) // DWORD 0: "no"
		}
	}
	procCloseClipboard.Call()

	seq, _, _ := procGetClipboardSequenceNumber.Call()
	go func() {
		time.Sleep(clipboardClearDelay)
		if now, _, _ := procGetClipboardSequenceNumber.Call(); now == seq && openClipboard() {
			procEmptyClipboard.Call()
			procCloseClipboard.Call()
		}
	}()
}

// HMAC-SHA3-512 over the header's decryption parameters, keyed by an HKDF-SHA3
// subkey of 'key' that's independent from the data-encryption and MAC keys
func computeHeaderMAC(key []byte, hkdfSalt []byte, parts ...[]byte) []byte {
	subkey := make([]byte, 32)
	r := hkdf.New(sha3.New256, key, hkdfSalt, []byte("zeecrypt-header-mac"))
	if n, err := r.Read(subkey); err != nil || n != 32 {
		panic(errors.New("fatal hkdf.Read error"))
	}
	mac := hmac.New(sha3.New512, subkey)
	for _, part := range parts {
		if _, err := mac.Write(part); err != nil {
			panic(err)
		}
	}
	return mac.Sum(nil)
}

// Reed-Solomon encoder
func rsEncode(rs *infectious.FEC, data []byte) []byte {
	res := make([]byte, rs.Total())
	rs.Encode(data, func(s infectious.Share) {
		res[s.Number] = s.Data[0]
	})
	return res
}

// Reed-Solomon decoder
func rsDecode(rs *infectious.FEC, data []byte) ([]byte, error) {
	// If fast decode, just return the first 128 bytes
	if rs.Total() == 136 && fastDecode {
		return data[:128], nil
	}

	tmp := make([]infectious.Share, rs.Total())
	for i := range rs.Total() {
		tmp[i].Number = i
		tmp[i].Data = append(tmp[i].Data, data[i])
	}
	res, err := rs.Decode(nil, tmp)

	// Force decode the data but return the error as well
	if err != nil {
		if rs.Total() == 136 {
			return data[:128], err
		}
		return data[:rs.Total()/3], err
	}

	// No issues, return the decoded data
	return res, nil
}

// PKCS#7 pad (for use with Reed-Solomon)
func pad(data []byte) []byte {
	padLen := 128 - len(data)%128
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

// PKCS#7 unpad; invalid padding (a corrupted final byte) is left in place
// so the MAC check fails and triggers repair instead of crashing here
func unpad(data []byte) []byte {
	padLen := int(data[127])
	if padLen < 1 || padLen > 128 {
		return data
	}
	return data[:128-padLen]
}

// Generate a cryptographically secure password
func genPassword() string {
	chars := ""
	if passgenUpper {
		chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if passgenLower {
		chars += "abcdefghijklmnopqrstuvwxyz"
	}
	if passgenNums {
		chars += "1234567890"
	}
	if passgenSymbols {
		chars += "-=_+!@#$^&()?<>"
	}
	tmp := make([]byte, passgenLength)
	for i := range int(passgenLength) {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			panic(errors.New("fatal crypto/rand error"))
		}
		tmp[i] = chars[j.Int64()]
	}
	if passgenCopy {
		setSecretClipboard(string(tmp))
	}
	return string(tmp)
}

// Convert done, total, and starting time to progress, speed, and ETA
func statify(done int64, total int64, start time.Time) (float32, float64, string) {
	if total <= 0 {
		return 0, 0, timeify(0)
	}
	progress := float32(done) / float32(total)
	elapsed := time.Since(start).Seconds()
	speed := 0.0
	if elapsed > 0 {
		speed = float64(done) / elapsed / float64(MiB)
	}
	eta := 0
	if speed > 0 && done < total {
		eta = int(math.Floor(float64(total-done) / (speed * float64(MiB))))
	}
	return float32(math.Min(float64(progress), 1)), speed, timeify(eta)
}

// Convert seconds to HH:MM:SS
func timeify(seconds int) string {
	hours := int(math.Floor(float64(seconds) / 3600))
	seconds %= 3600
	minutes := int(math.Floor(float64(seconds) / 60))
	seconds %= 60
	hours = int(math.Max(float64(hours), 0))
	minutes = int(math.Max(float64(minutes), 0))
	seconds = int(math.Max(float64(seconds), 0))
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

// Convert bytes to KiB, MiB, etc.
func sizeify(size int64) string {
	if size >= int64(TiB) {
		return fmt.Sprintf("%.2f TiB", float64(size)/float64(TiB))
	} else if size >= int64(GiB) {
		return fmt.Sprintf("%.2f GiB", float64(size)/float64(GiB))
	} else if size >= int64(MiB) {
		return fmt.Sprintf("%.2f MiB", float64(size)/float64(MiB))
	} else {
		return fmt.Sprintf("%.2f KiB", float64(size)/float64(KiB))
	}
}

// zipEntryPathOK reports whether a zip entry name is a plain relative path
// that stays inside the extraction folder: no "..", absolute paths, drive
// letters, alternate data streams (':') or reserved names like "NUL"
func zipEntryPathOK(name string) bool {
	name = strings.TrimSuffix(name, "/") // folder entries end in '/'
	if name == "" || strings.Contains(name, ":") {
		return false
	}
	return filepath.IsLocal(filepath.FromSlash(name))
}

// diskFree returns the bytes available to this user on the volume holding
// 'dir', or -1 if it can't be determined
func diskFree(dir string) int64 {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return -1
	}
	var free uint64
	r, _, _ := kernel32.NewProc("GetDiskFreeSpaceExW").Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&free)), 0, 0)
	if r == 0 {
		return -1
	}
	return int64(free)
}

// setLightTheme overrides giu's built-in dark theme with a light one.
// giu's NewMasterWindow() hardcodes a dark color scheme directly onto the
// current imgui style, so we reapply every color it sets with light-appropriate
// values immediately afterward.
func setLightTheme() {
	style := imgui.CurrentStyle()

	style.SetColor(imgui.StyleColorText, imgui.Vec4{X: 0.09, Y: 0.09, Z: 0.11, W: 1.00})
	style.SetColor(imgui.StyleColorTextDisabled, imgui.Vec4{X: 0.55, Y: 0.55, Z: 0.58, W: 1.00})
	style.SetColor(imgui.StyleColorWindowBg, imgui.Vec4{X: 0.98, Y: 0.98, Z: 0.99, W: 1.00})
	style.SetColor(imgui.StyleColorChildBg, imgui.Vec4{X: 0.95, Y: 0.95, Z: 0.97, W: 1.00})
	style.SetColor(imgui.StyleColorPopupBg, imgui.Vec4{X: 1.00, Y: 1.00, Z: 1.00, W: 0.98})
	style.SetColor(imgui.StyleColorBorder, imgui.Vec4{X: 0.80, Y: 0.80, Z: 0.83, W: 1.00})
	style.SetColor(imgui.StyleColorBorderShadow, imgui.Vec4{X: 0.00, Y: 0.00, Z: 0.00, W: 0.00})
	style.SetColor(imgui.StyleColorFrameBg, imgui.Vec4{X: 0.93, Y: 0.93, Z: 0.95, W: 1.00})
	style.SetColor(imgui.StyleColorFrameBgHovered, imgui.Vec4{X: 0.87, Y: 0.91, Z: 0.98, W: 1.00})
	style.SetColor(imgui.StyleColorFrameBgActive, imgui.Vec4{X: 0.80, Y: 0.87, Z: 0.98, W: 1.00})
	style.SetColor(imgui.StyleColorTitleBg, imgui.Vec4{X: 0.90, Y: 0.90, Z: 0.93, W: 0.65})
	style.SetColor(imgui.StyleColorTitleBgActive, imgui.Vec4{X: 0.86, Y: 0.86, Z: 0.90, W: 1.00})
	style.SetColor(imgui.StyleColorTitleBgCollapsed, imgui.Vec4{X: 0.95, Y: 0.95, Z: 0.95, W: 0.51})
	style.SetColor(imgui.StyleColorMenuBarBg, imgui.Vec4{X: 0.94, Y: 0.94, Z: 0.96, W: 1.00})
	style.SetColor(imgui.StyleColorScrollbarBg, imgui.Vec4{X: 0.96, Y: 0.96, Z: 0.96, W: 0.53})
	style.SetColor(imgui.StyleColorScrollbarGrab, imgui.Vec4{X: 0.80, Y: 0.80, Z: 0.83, W: 1.00})
	style.SetColor(imgui.StyleColorScrollbarGrabHovered, imgui.Vec4{X: 0.70, Y: 0.70, Z: 0.75, W: 1.00})
	style.SetColor(imgui.StyleColorScrollbarGrabActive, imgui.Vec4{X: 0.55, Y: 0.63, Z: 0.85, W: 1.00})
	style.SetColor(imgui.StyleColorCheckMark, imgui.Vec4{X: 0.16, Y: 0.47, Z: 0.93, W: 1.00})
	style.SetColor(imgui.StyleColorSliderGrab, imgui.Vec4{X: 0.16, Y: 0.47, Z: 0.93, W: 1.00})
	style.SetColor(imgui.StyleColorSliderGrabActive, imgui.Vec4{X: 0.10, Y: 0.38, Z: 0.85, W: 1.00})
	style.SetColor(imgui.StyleColorButton, imgui.Vec4{X: 0.90, Y: 0.92, Z: 0.96, W: 1.00})
	style.SetColor(imgui.StyleColorButtonHovered, imgui.Vec4{X: 0.82, Y: 0.88, Z: 0.98, W: 1.00})
	style.SetColor(imgui.StyleColorButtonActive, imgui.Vec4{X: 0.72, Y: 0.82, Z: 0.97, W: 1.00})
	style.SetColor(imgui.StyleColorHeader, imgui.Vec4{X: 0.90, Y: 0.92, Z: 0.96, W: 0.55})
	style.SetColor(imgui.StyleColorHeaderHovered, imgui.Vec4{X: 0.82, Y: 0.88, Z: 0.98, W: 0.80})
	style.SetColor(imgui.StyleColorHeaderActive, imgui.Vec4{X: 0.72, Y: 0.82, Z: 0.97, W: 1.00})
	style.SetColor(imgui.StyleColorSeparator, imgui.Vec4{X: 0.80, Y: 0.80, Z: 0.83, W: 1.00})
	style.SetColor(imgui.StyleColorSeparatorHovered, imgui.Vec4{X: 0.16, Y: 0.47, Z: 0.93, W: 0.78})
	style.SetColor(imgui.StyleColorSeparatorActive, imgui.Vec4{X: 0.16, Y: 0.47, Z: 0.93, W: 1.00})
	style.SetColor(imgui.StyleColorResizeGrip, imgui.Vec4{X: 0.16, Y: 0.47, Z: 0.93, W: 0.25})
	style.SetColor(imgui.StyleColorResizeGripHovered, imgui.Vec4{X: 0.16, Y: 0.47, Z: 0.93, W: 0.67})
	style.SetColor(imgui.StyleColorResizeGripActive, imgui.Vec4{X: 0.16, Y: 0.47, Z: 0.93, W: 0.95})
	style.SetColor(imgui.StyleColorTab, imgui.Vec4{X: 0.93, Y: 0.93, Z: 0.95, W: 1.00})
	style.SetColor(imgui.StyleColorTabHovered, imgui.Vec4{X: 0.82, Y: 0.88, Z: 0.98, W: 0.80})
	style.SetColor(imgui.StyleColorTabActive, imgui.Vec4{X: 0.90, Y: 0.92, Z: 0.96, W: 1.00})
	style.SetColor(imgui.StyleColorTabUnfocused, imgui.Vec4{X: 0.95, Y: 0.95, Z: 0.96, W: 1.00})
	style.SetColor(imgui.StyleColorTabUnfocusedActive, imgui.Vec4{X: 0.93, Y: 0.93, Z: 0.95, W: 1.00})
	style.SetColor(imgui.StyleColorPlotLines, imgui.Vec4{X: 0.45, Y: 0.45, Z: 0.45, W: 1.00})
	style.SetColor(imgui.StyleColorPlotLinesHovered, imgui.Vec4{X: 1.00, Y: 0.43, Z: 0.35, W: 1.00})
	style.SetColor(imgui.StyleColorPlotHistogram, imgui.Vec4{X: 0.80, Y: 0.60, Z: 0.00, W: 1.00})
	style.SetColor(imgui.StyleColorPlotHistogramHovered, imgui.Vec4{X: 0.90, Y: 0.50, Z: 0.00, W: 1.00})
	style.SetColor(imgui.StyleColorTextSelectedBg, imgui.Vec4{X: 0.16, Y: 0.47, Z: 0.93, W: 0.35})
	style.SetColor(imgui.StyleColorDragDropTarget, imgui.Vec4{X: 1.00, Y: 0.70, Z: 0.00, W: 0.90})
	style.SetColor(imgui.StyleColorNavHighlight, imgui.Vec4{X: 0.16, Y: 0.47, Z: 0.93, W: 1.00})
	style.SetColor(imgui.StyleColorNavWindowingHighlight, imgui.Vec4{X: 0.00, Y: 0.00, Z: 0.00, W: 0.70})
	style.SetColor(imgui.StyleColorTableHeaderBg, imgui.Vec4{X: 0.90, Y: 0.92, Z: 0.96, W: 1.00})
	style.SetColor(imgui.StyleColorTableBorderStrong, imgui.Vec4{X: 0.75, Y: 0.75, Z: 0.78, W: 1.00})
	style.SetColor(imgui.StyleColorTableBorderLight, imgui.Vec4{X: 0.85, Y: 0.85, Z: 0.88, W: 0.70})
}

// isNewerVersion reports whether remote is a newer version than local.
// Versions are dot-separated integers (an optional leading 'v' is ignored),
// e.g. "v1.50" or "1.50". Missing trailing segments are treated as 0, so
// "1.6" is considered newer than "1.5.9".
func isNewerVersion(remote, local string) (bool, error) {
	parse := func(v string) ([]int, error) {
		v = strings.TrimPrefix(strings.TrimSpace(v), "v")
		parts := strings.Split(v, ".")
		nums := make([]int, len(parts))
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			nums[i] = n
		}
		return nums, nil
	}

	r, err := parse(remote)
	if err != nil {
		return false, err
	}
	l, err := parse(local)
	if err != nil {
		return false, err
	}

	length := len(r)
	if len(l) > length {
		length = len(l)
	}
	for i := 0; i < length; i++ {
		var rv, lv int
		if i < len(r) {
			rv = r[i]
		}
		if i < len(l) {
			lv = l[i]
		}
		if rv != lv {
			return rv > lv, nil
		}
	}
	return false, nil
}

// checksumRegex extracts the published SHA-256 for ZeeCrypt.exe from a
// release's body text, matching the exact format build-windows.yml writes:
// `sha256(ZeeCrypt.exe)  <hex>`
var checksumRegex = regexp.MustCompile(`sha256\(ZeeCrypt\.exe\)\s+([A-Fa-f0-9]{64})`)

// checkForUpdates queries the latest GitHub release and, if it's newer than
// the running version, populates the update* variables and opens the update
// modal. Runs in the background; never downloads or applies anything itself.
func checkForUpdates() {
	if updateChecking || updateApplying {
		return
	}
	updateChecking = true
	updateError = ""
	giu.Update()

	go func() {
		defer func() {
			updateChecking = false
			giu.Update()
		}()

		client := &http.Client{Timeout: 15 * time.Second}
		req, err := http.NewRequest("GET", "https://api.github.com/repos/"+updateRepo+"/releases/latest", nil)
		if err != nil {
			updateError = "Failed to check for updates"
			return
		}
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := client.Do(req)
		if err != nil {
			updateError = "Failed to reach GitHub"
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			updateError = "Failed to check for updates"
			return
		}

		var release struct {
			TagName string `json:"tag_name"`
			Body    string `json:"body"`
			Assets  []struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
			} `json:"assets"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
			updateError = "Failed to parse update information"
			return
		}

		newer, err := isNewerVersion(release.TagName, version)
		if err != nil {
			updateError = "Failed to compare version numbers"
			return
		}
		if !newer {
			return // already up to date - stay silent
		}

		var downloadURL, sigURL string
		for _, a := range release.Assets {
			if a.Name == "ZeeCrypt.exe" {
				downloadURL = a.BrowserDownloadURL
			}
			if a.Name == "ZeeCrypt.exe.sig" {
				sigURL = a.BrowserDownloadURL
			}
		}
		if downloadURL == "" {
			updateError = "Update found, but no download was published for it"
			return
		}
		if releasePublicKey != "" && sigURL == "" {
			updateError = "Update found, but it isn't signed - download it from GitHub instead"
			return
		}

		m := checksumRegex.FindStringSubmatch(release.Body)
		if len(m) != 2 {
			updateError = "Update found, but its checksum couldn't be verified"
			return
		}

		updateVersion = release.TagName
		updateNotes = release.Body
		updateDownloadURL = downloadURL
		updateSigURL = sigURL
		updateChecksum = m[1]
		updateAvailable = true

		// Don't open over the progress (or any other) modal: that would
		// allow "Update Now" to exit mid-operation. The version label now
		// reads "Update available" and can be clicked once things are idle.
		if !working && !showProgress && !showOverwrite && !showKeyfile && !showPassgen {
			showUpdate = true
			modalId++
		}
	}()
}

// applyUpdate downloads the update, verifies its checksum, then replaces the
// running executable and relaunches it. Windows won't let a running exe be
// overwritten, but it does allow renaming one out from under itself: the
// current exe is renamed aside, the verified new one takes its place, and a
// new process is spawned before this one exits.
func applyUpdate() {
	// Never swap the exe and exit while an operation is running
	if updateApplying || working || showProgress {
		return
	}
	updateApplying = true
	updateError = ""
	giu.Update()

	go func() {
		success := false
		defer func() {
			updateApplying = false
			if !success {
				giu.Update()
			}
		}()

		// An MSI install lives in Program Files: replacing the exe needs
		// admin rights, and would leave Windows' record of the install stale
		if exe, err := os.Executable(); err == nil && !selfUpdatable(exe) {
			updateError = "Installed with the MSI: update using the new installer from GitHub"
			return
		}

		client := &http.Client{Timeout: 5 * time.Minute}
		resp, err := client.Get(updateDownloadURL)
		if err != nil {
			updateError = "Failed to download the update"
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			updateError = "Failed to download the update"
			return
		}

		tmpFile, err := os.CreateTemp("", "ZeeCrypt-update-*.exe")
		if err != nil {
			updateError = "Failed to prepare the update"
			return
		}
		tmpPath := tmpFile.Name()

		hasher := sha256.New()
		if _, err := io.Copy(io.MultiWriter(tmpFile, hasher), resp.Body); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			updateError = "Failed to download the update"
			return
		}
		if err := tmpFile.Close(); err != nil {
			os.Remove(tmpPath)
			updateError = "Failed to download the update"
			return
		}

		sum := hasher.Sum(nil)
		if !strings.EqualFold(hex.EncodeToString(sum), updateChecksum) {
			os.Remove(tmpPath)
			updateError = "Update failed checksum verification - aborted for your safety"
			return
		}

		// The checksum comes from the same release, so it only catches a
		// broken download. The signature also catches a tampered release.
		if releasePublicKey != "" {
			var sigFile []byte
			sigResp, err := client.Get(updateSigURL)
			if err == nil {
				if sigResp.StatusCode == http.StatusOK {
					sigFile, err = io.ReadAll(io.LimitReader(sigResp.Body, 4096))
				} else {
					err = errors.New(sigResp.Status)
				}
				sigResp.Body.Close()
			}
			if err != nil {
				os.Remove(tmpPath)
				updateError = "Failed to download the update's signature"
				return
			}
			if verifyUpdate(sigFile, updateVersion, sum) != nil {
				os.Remove(tmpPath)
				updateError = "Update failed signature verification - aborted for your safety"
				return
			}
		}

		// An operation may have started during the download
		if working || showProgress {
			os.Remove(tmpPath)
			updateError = "Finish the current operation, then update again"
			return
		}

		currentExe, err := os.Executable()
		if err != nil {
			os.Remove(tmpPath)
			updateError = "Failed to locate the running executable"
			return
		}
		if resolved, err := filepath.EvalSymlinks(currentExe); err == nil {
			currentExe = resolved
		}

		oldPath := currentExe + ".old"
		os.Remove(oldPath) // clean up a leftover from a previous update, if any

		if err := os.Rename(currentExe, oldPath); err != nil {
			os.Remove(tmpPath)
			updateError = "Failed to replace the running executable (check antivirus/permissions)"
			return
		}
		if err := os.Rename(tmpPath, currentExe); err != nil {
			os.Rename(oldPath, currentExe) // best-effort restore
			updateError = "Failed to install the update"
			return
		}

		if err := exec.Command(currentExe).Start(); err != nil {
			updateError = "Update installed, but failed to relaunch - please start ZeeCrypt manually"
			return
		}

		success = true
		os.Exit(0)
	}()
}

// selfUpdatable reports whether the exe at 'exe' is a portable copy that the
// updater may replace: not under Program Files, and in a writable folder
func selfUpdatable(exe string) bool {
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		root := os.Getenv(env)
		if root == "" {
			continue
		}
		if rel, err := filepath.Rel(root, dir); err == nil && filepath.IsLocal(rel) || strings.EqualFold(filepath.Clean(root), filepath.Clean(dir)) {
			return false
		}
	}
	probe, err := os.CreateTemp(dir, ".zeecrypt-update-check-*")
	if err != nil {
		return false
	}
	probe.Close()
	os.Remove(probe.Name())
	return true
}

func main() {
	if rsErr1 != nil || rsErr2 != nil || rsErr3 != nil || rsErr4 != nil || rsErr5 != nil || rsErr6 != nil || rsErr7 != nil {
		panic(errors.New("rs failed to init"))
	}
	// Clean up a leftover .old exe from a previous self-update, if any
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe + ".old")
	}

	// Command-line arguments come from Explorer's verbs ("--encrypt"/
	// "--decrypt", then paths). If ZeeCrypt is already open, hand them to
	// that window and exit.
	launch := parseArgs(os.Args[1:])
	launches := make(chan launchRequest, 64)
	if !startInstance(launch, launches) {
		return
	}

	// Create the main window
	window = giu.NewMasterWindow("ZeeCrypt "+version[1:], 318, 507, giu.MasterWindowFlagsNotResizable)

	// Switch from giu's default dark theme to a light theme
	setLightTheme()
	window.SetBgColor(color.RGBA{0xfa, 0xfa, 0xfb, 0xff})

	// Start the dialog module
	dialog.Init()

	// Set callbacks
	window.SetDropCallback(onWindowDrop)
	window.SetCloseCallback(func() bool {
		return !working && !showProgress
	})

	// Set universal DPI
	dpi = giu.Context.GetPlatform().GetContentScale()

	// Open this launch's paths, and anything forwarded by later launches.
	// Explorer starts one process per selected item, so requests arriving
	// within 300 ms of each other are merged into one drop.
	go batchRequests(launches, 300*time.Millisecond, queueLaunch)
	if len(launch.paths) > 0 {
		launches <- launch
	}

	// Start the UI
	window.Run(draw)
}
