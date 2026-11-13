package main

// Command-line handling and single-instance forwarding for the Explorer
// "Encrypt with ZeeCrypt" / "Decrypt with ZeeCrypt" verbs.
//
// Explorer starts one process per selected item for a command-line verb, so
// the first process becomes the "primary": it owns a named pipe, and every
// later launch sends its arguments there and exits. The primary batches
// requests that arrive close together into one drop, so selecting ten files
// and choosing "Encrypt with ZeeCrypt" behaves like dropping all ten.

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Picocrypt/giu"
	"golang.org/x/sys/windows"
)

// launchRequest is what a launch asks for: a mode ("", "encrypt" or
// "decrypt") and the paths to open
type launchRequest struct {
	mode  string
	paths []string
}

// parseArgs understands "--encrypt", "--decrypt" and "--" (end of options).
// Everything else is a path, so a file whose name starts with '-' still
// opens. Options after "--" are paths too.
func parseArgs(args []string) launchRequest {
	var r launchRequest
	options := true
	for _, a := range args {
		if options {
			switch a {
			case "--":
				options = false
				continue
			case "--encrypt":
				r.mode = "encrypt"
				continue
			case "--decrypt":
				r.mode = "decrypt"
				continue
			}
		}
		r.paths = append(r.paths, a)
	}
	return r
}

const maxLaunchMessage = 4 << 20

// encodeRequest is the pipe message: the mode, then each path, NUL-separated.
// NUL can't occur in a Windows path.
func encodeRequest(r launchRequest) []byte {
	return []byte(strings.Join(append([]string{r.mode}, r.paths...), "\x00"))
}

func decodeRequest(b []byte) (launchRequest, error) {
	parts := strings.Split(string(b), "\x00")
	r := launchRequest{mode: parts[0]}
	if r.mode != "" && r.mode != "encrypt" && r.mode != "decrypt" {
		return launchRequest{}, errors.New("bad mode")
	}
	for _, p := range parts[1:] {
		if p == "" {
			return launchRequest{}, errors.New("empty path")
		}
		r.paths = append(r.paths, p)
	}
	return r, nil
}

// mergeRequests joins requests that arrived in one burst. If the mode
// changed within the burst (two different verbs used back to back), only the
// requests after the last change count: they're the user's latest action.
func mergeRequests(reqs []launchRequest) launchRequest {
	if len(reqs) == 0 {
		return launchRequest{}
	}
	start := len(reqs) - 1
	for start > 0 && reqs[start-1].mode == reqs[len(reqs)-1].mode {
		start--
	}
	out := launchRequest{mode: reqs[len(reqs)-1].mode}
	seen := map[string]bool{}
	for _, r := range reqs[start:] {
		for _, p := range r.paths {
			key := strings.ToLower(p)
			if !seen[key] {
				seen[key] = true
				out.paths = append(out.paths, p)
			}
		}
	}
	return out
}

// batchRequests delivers each burst of requests (no new request for 'quiet')
// as one merged request
func batchRequests(in <-chan launchRequest, quiet time.Duration, deliver func(launchRequest)) {
	for first := range in {
		batch := []launchRequest{first}
		timer := time.NewTimer(quiet)
	collect:
		for {
			select {
			case r, ok := <-in:
				if !ok {
					break collect
				}
				batch = append(batch, r)
				timer.Reset(quiet)
			case <-timer.C:
				break collect
			}
		}
		timer.Stop()
		deliver(mergeRequests(batch))
	}
}

// ---------- The pipe ----------

// instancePipeName is per user and per logon session, so two users (or one
// user in two Remote Desktop sessions) each get their own primary window
func instancePipeName() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return "", err
	}
	return `\\.\pipe\ZeeCrypt-` + user.User.Sid.String() + "-" + strconv.FormatUint(uint64(session), 10), nil
}

// errInstanceRunning means another ZeeCrypt already owns the pipe
var errInstanceRunning = errors.New("another instance is running")

// listenInstance creates the pipe. Only the current user may connect, and
// FILE_FLAG_FIRST_PIPE_INSTANCE makes creation fail if the name is taken.
func listenInstance(name string) (windows.Handle, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return 0, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return 0, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateNamedPipe(name16,
		windows.PIPE_ACCESS_INBOUND|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1, 0, 64*1024, 0, sa)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return 0, errInstanceRunning
		}
		return 0, err
	}
	return h, nil
}

// serveInstance accepts one client at a time on 'h' and sends each valid
// request to 'out'. It never returns.
func serveInstance(h windows.Handle, out chan<- launchRequest) {
	buf := make([]byte, 64*1024)
	for {
		err := windows.ConnectNamedPipe(h, nil)
		if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		var msg []byte
		tooLong := false
		for {
			var n uint32
			err := windows.ReadFile(h, buf, &n, nil)
			msg = append(msg, buf[:n]...)
			if len(msg) > maxLaunchMessage {
				tooLong = true
				break
			}
			if err != nil { // ERROR_BROKEN_PIPE: the client sent everything and closed
				break
			}
		}
		windows.DisconnectNamedPipe(h)
		if tooLong {
			continue
		}
		if r, err := decodeRequest(msg); err == nil {
			out <- r
		}
	}
}

// forwardToInstance sends 'r' to the primary instance. It refuses a pipe
// served from another logon session, so a pipe squatted by someone else
// doesn't receive the user's file names.
func forwardToInstance(name string, r launchRequest) error {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var h windows.Handle
	deadline := time.Now().Add(5 * time.Second)
	for {
		h, err = windows.CreateFile(name16, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			break
		}
		// Busy with another launch, or the primary is between clients
		if (errors.Is(err, windows.ERROR_PIPE_BUSY) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND)) && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		return err
	}
	defer windows.CloseHandle(h)

	var serverPid, serverSession, ourSession uint32
	if err := windows.GetNamedPipeServerProcessId(h, &serverPid); err != nil {
		return err
	}
	if err := windows.ProcessIdToSessionId(serverPid, &serverSession); err != nil {
		return err
	}
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &ourSession); err != nil {
		return err
	}
	if serverSession != ourSession {
		return errors.New("pipe served from another session")
	}

	// Let the primary bring its window to the front (Windows only allows
	// that for a process the user just interacted with, which is us)
	procAllowSetForegroundWindow.Call(uintptr(serverPid))

	msg := encodeRequest(r)
	for len(msg) > 0 {
		var n uint32
		if err := windows.WriteFile(h, msg, &n, nil); err != nil {
			return err
		}
		msg = msg[n:]
	}
	return nil
}

// ---------- Handing requests to the UI thread ----------

var (
	pendingLaunchMu sync.Mutex
	pendingLaunch   *launchRequest
)

// queueLaunch is called from the batcher goroutine; draw() picks it up on
// the UI thread, where onDrop is safe to call
func queueLaunch(r launchRequest) {
	pendingLaunchMu.Lock()
	pendingLaunch = &r
	pendingLaunchMu.Unlock()
	giu.Update()
}

func takePendingLaunch() (launchRequest, bool) {
	pendingLaunchMu.Lock()
	defer pendingLaunchMu.Unlock()
	if pendingLaunch == nil {
		return launchRequest{}, false
	}
	r := *pendingLaunch
	pendingLaunch = nil
	return r, true
}

// applyLaunch brings the window forward and opens the request's paths,
// unless an operation or a modal (including the keyfile picker, which a
// stray Explorer launch shouldn't fill) is in progress
func applyLaunch(r launchRequest) {
	bringWindowToFront()
	if len(r.paths) == 0 || working || showProgress || showOverwrite || updateApplying || showKeyfile || showPassgen {
		return
	}
	onDropMode(r.paths, r.mode)
}

var (
	procAllowSetForegroundWindow = user32.NewProc("AllowSetForegroundWindow")
	procFindWindowW              = user32.NewProc("FindWindowW")
	procSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	procShowWindow               = user32.NewProc("ShowWindow")
	procIsIconic                 = user32.NewProc("IsIconic")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
)

func bringWindowToFront() {
	title, err := syscall.UTF16PtrFromString("ZeeCrypt " + version[1:])
	if err != nil {
		return
	}
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(title)))
	if hwnd == 0 {
		return
	}
	var pid uint32
	procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid != windows.GetCurrentProcessId() {
		return
	}
	if iconic, _, _ := procIsIconic.Call(hwnd); iconic != 0 {
		procShowWindow.Call(hwnd, 9) // SW_RESTORE
	}
	procSetForegroundWindow.Call(hwnd)
}

// startInstance runs before the window exists. It returns false if the
// request was handed to an already-running ZeeCrypt and this process should
// exit. Otherwise this process is the primary (or runs standalone if the
// pipe couldn't be set up) and 'launches' receives forwarded requests.
func startInstance(r launchRequest, launches chan launchRequest) bool {
	name, err := instancePipeName()
	if err != nil {
		return true
	}
	h, err := listenInstance(name)
	if err == errInstanceRunning {
		if forwardToInstance(name, r) == nil {
			return false
		}
		return true // couldn't reach it: open our own window
	}
	if err != nil {
		return true
	}
	go serveInstance(h, launches)
	return true
}
