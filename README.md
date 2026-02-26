# Borg Backup - Native Windows Build

This is a fork of [BorgBackup](https://github.com/borgbackup/borg) 1.4.x with native Windows support.

Most all commands work the same as BorgBackup on linux works with the exception of the below:

#### Restoring files to their original location

Windows does not have the same root structure for Volumes as Linux & Mac. So Windows drive letters are stored as the first path component in archives (e.g. `C:\Users\johnsmith\file.txt` becomes `C/Users/johnsmith/file.txt`). To restore files back to their original location, use `--strip-components 1` to remove the drive letter folder:

```powershell
cd C:\
borg.exe extract /path/to/repo::archive --strip-components 1
```

For multi-drive restores, extract each drive separately:
```powershell
cd C:\
borg.exe extract /path/to/repo::archive C --strip-components 1
cd D:\
borg.exe extract /path/to/repo::archive D --strip-components 1
```


## What was done

This fork adds the ability to compile and run Borg natively on Windows (not through WSL or Cygwin). The key changes are:

### Windows NTFS ACL support
- **Backup and restore of Windows file permissions** (owner, group, and DACL) using the Win32 Security API
- Permissions are serialized as [SDDL](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format) strings (the Windows equivalent of POSIX `acl_to_text()`)
- Stored under the `acl_windows` key in each archive item
- Graceful privilege degradation: attempts to restore owner/group + DACL, falls back to DACL-only if the process lacks `SE_RESTORE_NAME` privilege

### MSVC build fixes
- Conditional compiler flags (MSVC doesn't understand GCC `-Wall`/`-Wextra`)
- `ssize_t` typedef for MSVC in `_chunker.c` (POSIX type not available on Windows)
- OpenSSL library path fix for Windows OpenSSL installations
- `advapi32` library linking for Win32 Security API functions

### Files modified
| File | Change |
|------|--------|
| `src/borg/platform/windows.pyx` | Full `acl_get`/`acl_set` implementation (~200 lines of Cython) |
| `src/borg/platform/__init__.py` | Wire in Windows ACL imports |
| `src/borg/item.pyx` | Add `acl_windows` property |
| `src/borg/constants.py` | Register `acl_windows` in `ITEM_KEYS` |
| `setup.py` | MSVC cflags, advapi32 linking, OpenSSL lib path |
| `src/borg/_chunker.c` | `ssize_t` typedef for MSVC |
| `src/borg/testsuite/platform.py` | Windows ACL test cases (4 tests) |

## What does NOT work

- **`borg mount`** - FUSE is a Linux/macOS concept. There is no FUSE equivalent bundled for Windows. Use `borg extract` or `borg export-tar` instead.
- **xattrs** - Windows does not have POSIX extended attributes. NTFS Alternate Data Streams are not currently supported.
- **BSD file flags** - Not applicable on Windows.
- **Special files** - Block devices, character devices, FIFOs, and sockets are not supported on Windows.

## Building from source

### Prerequisites

- Python 3.11 (64-bit)
- Visual Studio 2022 or 2025 with C++ Desktop workload
- [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html) (64-bit, installed to `C:\Program Files\OpenSSL-Win64`)
- [vcpkg](https://github.com/microsoft/vcpkg) with: `vcpkg install lz4:x64-windows zstd:x64-windows xxhash:x64-windows`

### Build steps

```powershell
# Set environment variables pointing to your library installations
$env:BORG_OPENSSL_PREFIX = "C:\Program Files\OpenSSL-Win64"
$env:BORG_LIBLZ4_PREFIX = "C:\vcpkg\installed\x64-windows"
$env:BORG_LIBZSTD_PREFIX = "C:\vcpkg\installed\x64-windows"
$env:BORG_LIBXXHASH_PREFIX = "C:\vcpkg\installed\x64-windows"

# Install Python dependencies
pip install -r requirements.d/development.txt

# Build and install in development mode
pip install -e .

# Copy runtime DLLs next to the compiled .pyd extensions
# (Python 3.8+ restricts DLL search paths for security)
$dlls = @(
    "C:\vcpkg\installed\x64-windows\bin\lz4.dll",
    "C:\vcpkg\installed\x64-windows\bin\zstd.dll",
    "C:\vcpkg\installed\x64-windows\bin\xxhash.dll",
    "C:\Program Files\OpenSSL-Win64\bin\libcrypto-3-x64.dll",
    "C:\Program Files\OpenSSL-Win64\bin\libssl-3-x64.dll"
)
foreach ($dll in $dlls) {
    Copy-Item $dll src\borg\ -Force
    Copy-Item $dll src\borg\algorithms\ -Force
    Copy-Item $dll src\borg\crypto\ -Force
    Copy-Item $dll src\borg\platform\ -Force
}

# Verify it works
borg --version
```

## Building a standalone distribution with PyInstaller

The `windows/` directory contains files for creating a standalone `borg.exe` that doesn't require Python:

```powershell
pip install pyinstaller

# Copy the entry point and spec file to your source root
Copy-Item windows\borg-entry.py .
Copy-Item windows\borg.spec .

# Build (edit borg.spec first if your DLL paths differ)
pyinstaller borg.spec --noconfirm

# Result is in dist\borg\ - copy the whole folder to distribute
```

The `dist\borg\` folder (~34 MB) contains everything needed. No Python installation required on the target machine.

## Installing from a wheel

If you have a pre-built wheel and the runtime DLLs (see `windows/install.ps1`):

```powershell
cd path\to\borg-portable
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

This requires Python 3.11 on the target machine.

## License

Same as BorgBackup - BSD 3-clause. See [LICENSE](LICENSE).
