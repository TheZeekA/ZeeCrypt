<p align="center"><img align="center" src="/images/zeecrypt-logo-scaled.png" width="512" alt="ZeeCrypt"></p>

ZeeCrypt is a very small, very simple, yet very secure encryption tool that you can use to protect your files. It's a Windows-only fork of [Picocrypt](https://github.com/Picocrypt/Picocrypt), designed to be the <i>go-to</i> tool for file encryption, with a focus on security, simplicity, and reliability. ZeeCrypt uses the secure XChaCha20 cipher and the Argon2id key derivation function to provide a high level of security.

🚀 **This repo is actively maintained.** Unlike the original (now-archived) Picocrypt, ZeeCrypt is under active development — bug reports, feature requests, and suggestions are welcome, so feel free to open an issue. See [CONTRIBUTING.md](CONTRIBUTING.md) if you'd like to contribute code, and [SECURITY.md](SECURITY.md) to report a vulnerability.

<br>
<p align="center"><img align="center" src="/images/screenshot.png" width="318" alt="ZeeCrypt"></p>

# Downloads

ℹ️ **You are highly recommended to read through the [Features](#features) section below to fully understand the features and limitations of ZeeCrypt before using it.** ℹ️

Make sure to only download ZeeCrypt from this repository. When sharing ZeeCrypt with others, be sure to link to this repository to prevent any confusion.

## Windows
To download the latest, standalone, and portable executable for Windows, click <a href="https://github.com/TheZeekA/ZeeCrypt/releases/latest/download/ZeeCrypt.exe">here</a>.

If you use ZeeCrypt frequently, you can also download the [installer](https://github.com/TheZeekA/ZeeCrypt/releases/latest/download/ZeeCrypt-Installer.msi) for Start Menu and Desktop shortcuts, automatic file extension association, and a right-click "Open with ZeeCrypt" entry in Explorer. This installs to Program Files, so it requires administrator privileges (a UAC prompt) during installation.

If your antivirus flags ZeeCrypt as a virus, please report it as a false positive to help everyone.

ZeeCrypt targets Windows 11 only; it is not built or tested for macOS or Linux.

# Comparison
Here's how ZeeCrypt compares to other popular encryption tools.

|                | ZeeCrypt       | VeraCrypt      | 7-Zip GUI      | BitLocker      | Cryptomator    |
| -------------- | -------------- | -------------- | -------------- | -------------- | -------------- |
| Free           |✅ Yes         |✅ Yes          |✅ Yes         |✅ Bundled      |✅ Yes         |
| Open Source    |✅ GPLv3       |✅ Multi        |✅ LGPL        |❌ No           |✅ GPLv3       |
| Cross-Platform |❌ Windows only |✅ Yes         |❌ No          |❌ No           |✅ Yes         |
| Size           |✅ 3 MiB       |❌ 20 MiB       |✅ 2 MiB       |✅ N/A          |❌ 50 MiB      |
| Portable       |✅ Yes         |✅ Yes          |❌ No          |✅ Yes          |❌ No          |
| Permissions    |✅ None        |❌ Admin        |❌ Admin       |❌ Admin        |❌ Admin       |
| Ease-Of-Use    |✅ Easy        |❌ Hard         |✅ Easy        |✅ Easy         |🟧 Medium      |
| Cipher         |✅ XChaCha20   |✅ AES-256      |✅ AES-256     |🟧 AES-128      |✅ AES-256     |
| Key Derivation |✅ Argon2      |🟧 PBKDF2       |❌ SHA-256     |❓ Unknown      |✅ Scrypt      |
| Data Integrity |✅ Always      |❌ No           |❌ No          |❓ Unknown      |✅ Always      |
| Deniability    |✅ Supported   |✅ Supported    |❌ No          |❌ No           |❌ No          |
| Reed-Solomon   |✅ Yes         |❌ No           |❌ No          |❌ No           |❌ No          |
| Compression    |✅ Yes         |❌ No           |✅ Yes         |✅ Yes          |❌ No          |
| Telemetry      |✅ None        |✅ None         |✅ None        |❓ Unknown      |✅ None        |

Keep in mind that while ZeeCrypt does most things better than other tools, it's not a one-size-fits-all and doesn't try to be. There are use cases such as full-disk encryption where VeraCrypt and BitLocker would be a better (and the only) choice. So while ZeeCrypt is a great choice for the majority of people doing file encryption on Windows, you should still do your own research and use what's best for you.

# Features
ZeeCrypt is a very simple tool and most users will intuitively understand how to use it in a few seconds. On a basic level, simply dropping your files, entering a password, and hitting Encrypt is all that's needed to encrypt your files. Dropping the output back into ZeeCrypt, entering the password, and hitting Decrypt is all that's needed to decrypt those files. Pretty simple, right?

While being simple, ZeeCrypt also strives to be powerful in the hands of knowledgeable and advanced users. Thus, there are some additional options that you may use to suit your needs. Read through their descriptions carefully as some of them can be complex to use correctly.
<ul>
	<li><strong>Password generator</strong>: ZeeCrypt provides a secure password generator that you can use to create cryptographically secure passwords. You can customize the password length, as well as the types of characters to include.</li>
	<li><strong>Comments</strong>: Use this to store <strong>non-sensitive</strong> text along with the volume (<strong>it won't be encrypted</strong> and simply can't be by design). For example, you can put a description of the file you're encrypting before sending it to someone. When the person you sent it to drops the volume into ZeeCrypt, your description will be shown to that person. Or, if you're backing up personal files, you can give a description of the volume's contents so you can quickly remind yourself without having to fully decrypt. Since comments are neither encrypted nor authenticated, it can be freely read and modified by an attacker. <strong>Thus, it should only be used for non-sensitive, informational purposes in trusted environments.</strong></li>
	<li><strong>Keyfiles</strong>: ZeeCrypt supports the use of keyfiles as an additional form of authentication (or the only form of authentication). Any file can be used as a keyfile, and a secure keyfile generator is provided for convenience. Not only can you use multiple keyfiles, but you can also require the correct order of keyfiles to be present for a successful decryption to occur. A particularly good use case of multiple keyfiles is creating a shared volume, where each person holds a keyfile, and all of them (and their keyfiles) must be present to decrypt the shared volume. By checking the "Require correct order" box and dropping your keyfile in last, you can also ensure that you'll always be the one clicking the Decrypt button. <strong>Use the keyfile generator whenever possible for the best security.</strong></li>
	<li><strong>Paranoid mode</strong>: Using this mode will encrypt your data with both XChaCha20 and Serpent in a cascade fashion, and use HMAC-SHA3 to authenticate data instead of BLAKE2b. Argon2 parameters will be increased significantly as well. This is recommended for protecting top-secret files and provides the highest level of practical security attainable. For a hacker to break into your encrypted data, both the XChaCha20 cipher and the Serpent cipher must be broken, assuming you've chosen a good password. It's safe to say that in this mode, your files are impossible to crack. Keep in mind, however, that this mode is slower and isn't really necessary unless you're a government agent with classified data or a whistleblower under threat.</li>
	<li><strong>Reed-Solomon</strong>: This feature is very useful if you are planning to archive important data on a cloud provider or external medium for a long time. If checked, ZeeCrypt will use the Reed-Solomon error correction code to add 8 extra bytes for every 128 bytes of data to prevent file corruption. This means that up to ~3% of your file can corrupt and ZeeCrypt will still be able to correct the errors and decrypt your files with no corruption. Of course, if your file corrupts very badly (e.g., you dropped your hard drive), ZeeCrypt won't be able to fully recover your files, but it will try its best to recover what it can. Note that this option will slow down encryption and decryption speeds significantly.</li>
	<li><strong>Force decrypt</strong>: ZeeCrypt automatically checks for file integrity upon decryption. If the file has been modified or is corrupted, ZeeCrypt will automatically delete the output for the user's safety. If you would like to override these safeguards, check this option. Also, if this option is checked and the Reed-Solomon feature was used on the encrypted volume, ZeeCrypt will attempt to recover as much of the file as possible during decryption.</li>
	<li><strong>Split into chunks</strong>: Don't feel like dealing with gargantuan files? No worries! With ZeeCrypt, you can choose to split your output file into custom-sized chunks, so large files can become more manageable and easier to upload to cloud providers. Simply choose a unit (KiB, MiB, GiB, or TiB) and enter your desired chunk size for that unit. To decrypt the chunks, simply drag one of them into ZeeCrypt and the chunks will be automatically recombined during decryption.</li>
	<li><strong>Compress files</strong>: By default, ZeeCrypt uses a zip file with no compression to quickly merge files together when encrypting multiple files. If you would like to compress these files, however, simply check this box and the standard Deflate compression algorithm will be applied during encryption.</li>
	<li><strong>Deniability</strong>: ZeeCrypt volumes typically follow an easily recognizable header format. However, if you want to hide the fact that you are encrypting your files, enabling this option will provide you with plausible deniability. The output volume will be indistinguishable from a stream of random bytes, and no one can prove it is a volume without the correct password. This can be useful in an authoritarian country where the only way to transport your files safely is if they don't "exist" in the first place. Keep in mind that this mode slows down encryption and decryption speeds, requires you to manually rename the volume afterward, renders comments useless, and also voids the extra security precautions of the paranoid mode, so you should only use it if absolutely necessary. <strong>If you've never heard of plausible deniability, this feature is not for you.</strong></li>
	<li><strong>Recursively</strong>: If you want to encrypt and/or decrypt a large set of files individually, this option will tell ZeeCrypt to go through every recursive file that you drop in and encrypt/decrypt it separately. This is useful, for example, if you are encrypting thousands of large documents and want to be able to decrypt any one of them in particular without having to download and decrypt the entire set of documents. <strong>Keep in mind that this is a very complex feature that should only be used if you know what you are doing.</strong></li>
	<li><strong>Explorer integration</strong>: If you installed ZeeCrypt with the MSI installer, right-clicking a file or folder shows an "Open with ZeeCrypt" entry. ZeeCrypt automatically detects whether to encrypt or decrypt based on what you open, so there's no separate Encrypt/Decrypt option to pick - just right-click and go. Selecting multiple files or folders and right-clicking opens them all in one window.</li>
	<li><strong>Update checker</strong>: Click the version number at the bottom-right of the window to check for a new release. Nothing happens automatically - checking only happens when you click, and if an update is found, you'll see the release notes with an "Update Now" button rather than anything downloading or installing on its own. The downloaded update is verified against its published checksum before it replaces the running executable.</li>
</ul>

# Security
For more information on how ZeeCrypt handles cryptography, see <a href="Internals.md">Internals</a> for the technical details. ZeeCrypt is a fork of [Picocrypt](https://github.com/Picocrypt/Picocrypt), which was [independently audited](https://www.radicallyopensecurity.com/) before this fork's changes were made; ZeeCrypt itself has not yet been separately audited, so treat its Windows-only changes accordingly.

<strong>ZeeCrypt operates under the assumption that the host machine it is running on is safe and trusted. If that is not the case, no piece of software will be secure, and you will have much bigger problems to worry about. As such, ZeeCrypt is designed for the offline security of volumes and does not attempt to protect against side-channel analysis.</strong>

ZeeCrypt makes no network requests on its own. The only exception is the update checker (bottom-right of the window), which only runs when you click it — it queries the GitHub Releases API and, if you choose to install an update, verifies its SHA-256 checksum before replacing the running executable. Nothing is ever downloaded or applied without you explicitly clicking to do so.

# FAQ
**Does the "Delete files" feature shred files?**

No, it doesn't shred any files and just deletes them as your file manager would. On modern storage mediums like SSDs, there is no such thing as shredding a file since wear leveling makes it impossible to overwrite a particular sector. Thus, to prevent giving users a false sense of security, ZeeCrypt doesn't include any shredding features at all.

**Is ZeeCrypt quantum-secure?**

Yes, ZeeCrypt is secure against quantum computers. All of the cryptography used in ZeeCrypt works off of a private key, and private-key cryptography is considered to be resistant against all current and future developments, including quantum computers.

# License
This project is licensed under **GPL-3.0-only**, as a fork of [Picocrypt](https://github.com/Picocrypt/Picocrypt) (also GPL-3.0-only).

# Acknowledgements
ZeeCrypt is a fork of [Picocrypt](https://github.com/Picocrypt/Picocrypt) by Evan Su. Everything below credits the people who supported the original Picocrypt project prior to this fork.

A thank you from the bottom of my heart to the significant contributors on [Open Collective](https://opencollective.com/picocrypt):
<ul>
	<li><strong>Mikołaj ($1674)</strong></li>
	<li><strong>Guest ($842)</strong></li>
	<li><strong>YellowNight ($818)</strong></li>
	<li>Incognito ($135)</li>
	<li>akp ($98)</li>
	<li>JC ($90)</li>
	<li>evelian ($50)</li>
	<li>jp26 ($50)</li>
	<li>guest-116103ad ($50)</li>
	<li>Guest ($27)</li>
	<li>Gittan Pade ($25)</li>
	<li>Pokabu ($20)</li>
	<li>oli ($20)</li>
	<li>Bright ($20)</li>
	<li>Incognito ($20)</li>
	<li>Guest ($20)</li>
	<li>JokiBlue ($20)</li>
	<li>Guest ($20)</li>
	<li>Markus ($15)</li>
	<li>EN ($15)</li>
	<li>Guest ($13)</li>
	<li>Tybbs ($10)</li>
	<li>N. Chin ($10)</li>
	<li>Manjot ($10)</li>
	<li>Phil P. ($10)</li>
	<li>Raymond ($10)</li>
	<li>Cohen ($10)</li>
	<li>EuA ($10)</li>
	<li>geevade ($10)</li>
	<li>Guest ($10)</li>
	<li>Hilebrinest ($10)</li>
	<li>gabu.gu ($10)</li>
	<li>Boat ($10)</li>
	<li>Guest ($10)</li>
</ul>
<!-- Last updated July 12, 2024 -->

Also, a huge thanks to the following people who were the first to donate and support Picocrypt:
<ul>
	<li>W.Graham</li>
	<li>N. Chin</li>
	<li>Manjot</li>
	<li>Phil P.</li>
	<li>E. Zahard</li>
</ul>

Finally, thanks to these people/organizations for helping out the original Picocrypt project when needed:
<ul>
	<li>u/greenreddits for constant feedback and support</li>
	<li>u/Tall_Escape for helping test Picocrypt</li>
	<li>u/NSABackdoors for doing plenty of testing</li>
	<li>@samuel-lucas6 for feedback, suggestions, and support</li>
	<li>@AsuxAX and @Minibus93 for testing new features</li>
	<li>@mdanish-kh and @stephengillie for the WinGet package</li>
	<li>@Retengart for helping create the Flatpak and housekeeping it</li>
	<li><a href="https://privacyguides.org">Privacy Guides</a> for (previously) listing Picocrypt</li>
	<li><a href="https://www.radicallyopensecurity.com/">Radically Open Security</a> for auditing Picocrypt</li>
</ul>
