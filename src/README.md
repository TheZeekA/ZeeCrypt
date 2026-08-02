# Running From Source
If you would like to run ZeeCrypt from source, you've come to the right place. Running from source is very simple. ZeeCrypt can easily be compiled from source with only a Go and C compiler. All you need is ten minutes and an Internet connection.

# 1. Prerequisites
**Windows:** A C compiler, ideally TDM-GCC or MinGW-w64

# 2. Install Go
If you don't have Go installed, download it from <a href="https://go.dev/dl/">here</a> or install it from your package manager. The latest version of Go is recommended, although you may fall back to Go 1.19 should any issues arise in the future.

# 3. Get the Source Files
Download the source files as a zip from the homepage or `git clone` this repository. Next, navigate to the `src/` directory, where you will find the source file (`ZeeCrypt.go`). You will need this file, along with `go.mod` and `go.sum`, to compile ZeeCrypt.

# 4. Build From Source
Finally, build ZeeCrypt from source (run this from inside the `src/` directory):
- Windows: <code>go build -ldflags="-s -w -H=windowsgui -extldflags=-static" .</code>

Note: Make sure to set `CGO_ENABLED=1` if it isn't already. Also make sure **not** to name `ZeeCrypt.go` explicitly on the command line (e.g. `go build ZeeCrypt.go`) — Go only auto-links the `.syso` icon resource files when building the package as a whole (`.` or no argument), not when you list specific `.go` files.

# 5. Done!
You should now see a compiled executable (`ZeeCrypt.exe`) in your directory, with the app icon already embedded. You can run it by double-clicking or executing it in your terminal. That wasn't too hard, right? Enjoy!

# Updating the app icon
The icon is embedded automatically via `rsrc_windows_386.syso`/`rsrc_windows_amd64.syso` in this directory, which `go build` links in without any extra flags. If you change `images/lock.ico`, regenerate these files:
```
cd src
go tool go-winres make
```
This reads `src/winres/winres.json` (icon only — see below) and rewrites the `.syso` files to match the new icon.

# Manifest and version info
`src/winres/winres.json` also defines the app manifest (`RT_MANIFEST`, sourced from `dist/windows/manifest.xml`) and version info (`RT_VERSION`, shown in Explorer's file Properties dialog). These are **not** compiled into the `.syso` files above — this project links with cgo (for GLFW) via mingw, whose C runtime auto-links its own `default-manifest.o` into GUI executables, which conflicts with an embedded `RT_MANIFEST` at link time (`ld: .rsrc merge failure: multiple non-default manifests`). Version info alone doesn't hit this conflict, but it's kept alongside the manifest in the same file for a single source of truth.

Instead, CI (and release builds) patch the manifest and version info into the already-built exe as a separate step:
```
go tool go-winres patch --in winres/winres.json --no-backup ZeeCrypt.exe
```
When bumping `VERSION`, also update `file_version`/`product_version`/`FileVersion` in `src/winres/winres.json` to match.
