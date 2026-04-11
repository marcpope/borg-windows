# Borg Backup - Native Windows Build

This is a fork of [BorgBackup](https://github.com/borgbackup/borg) 1.4.x with native Windows support.

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

### Windows path handling (v1.4.4-win2..win5)

- Paths are stored in archives as forward slashes (`C:/Users/me/file.txt`) so archives are portable across OSes.
- Drive letters are preserved as a path component (`C:` → folder `C`) — multi-drive backups keep their drive identity. Use `--strip-components 1` on extract to remove the drive letter folder.
- `strip_components`, pattern matching, and `--strip-components` on extract all normalized to `/` instead of `os.sep`.
- `borg serve` over SSH works with `ssh://user@host//absolute/path` syntax.

### Ssh child process reliability (v1.4.4-win6)

- **Job Object / kill-on-exit**: the `ssh.exe` child spawned by `RemoteRepository` is assigned to a Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. When borg.exe exits (clean, crash, or force-kill), Windows guarantees ssh.exe dies with it — no more orphaned ssh children hanging around waiting for a network timeout.
- **`CTRL_BREAK_EVENT` handling**: borg on Windows now installs a `SIGBREAK` handler that raises `SigTerm`, so a parent supervisor (e.g. BBS agent) cancelling borg via `CTRL_BREAK_EVENT` flows through the normal orderly-exit path instead of skipping finalizers.
- **Safer `RemoteRepository.close()` teardown**: closes stdin first, drains+joins the Windows reader threads, bounded `p.wait(timeout=30)` with `kill()` fallback, then closes stdout/stderr. This prevents an abortive pipe shutdown from racing the server's commit and leaving the server-side lock behind.

### Files modified
| File | Change |
|------|--------|
| `src/borg/platform/windows.pyx` | Full `acl_get`/`acl_set` implementation + `assign_process_to_kill_on_exit_job` helper |
| `src/borg/platform/__init__.py` | Wire in Windows ACL imports and Job Object helper |
| `src/borg/item.pyx` | Add `acl_windows` property |
| `src/borg/constants.py` | Register `acl_windows` in `ITEM_KEYS` |
| `src/borg/remote.py` | Windows SSH fixes + Job Object assignment + safer `close()` teardown |
| `src/borg/archiver.py` | `SIGBREAK` handler on Windows; path-normalization fixes |
| `src/borg/helpers/fs.py` | `make_path_safe` drive-letter to path-component conversion |
| `src/borg/patterns.py`, `shellpattern.py` | Forward-slash pattern matching on Windows |
| `setup.py` | MSVC cflags, advapi32 linking, OpenSSL lib path |
| `src/borg/_chunker.c` | `ssize_t` typedef for MSVC |
| `src/borg/testsuite/platform.py` | Windows ACL test cases (4 tests) |

## What does NOT work

- **`borg mount`** - FUSE is a Linux/macOS concept. There is no FUSE equivalent bundled for Windows. Use `borg extract` or `borg export-tar` instead.
- **xattrs** - Windows does not have POSIX extended attributes. NTFS Alternate Data Streams are not currently supported.
- **BSD file flags** - Not applicable on Windows.
- **Special files** - Block devices, character devices, FIFOs, and sockets are not supported on Windows.

## SSH client requirement — use Git for Windows' ssh

**Important:** borg on Windows spawns `ssh` via `subprocess.Popen(stdin=PIPE, ...)` and writes the RPC wire protocol to ssh's stdin. Some versions of the **Windows built-in OpenSSH** (`C:\Windows\System32\OpenSSH\ssh.exe`, e.g. `OpenSSH_for_Windows_9.5p2`) have a subprocess-stdin forwarding issue that causes borg to hang forever after connecting to the remote server — the TCP handshake and server-side stderr flow back fine, but the client's msgpack bytes never reach the remote `borg serve` process.

If you install Git for Windows, it bundles an OpenSSH port (MSYS2) at `C:\Program Files\Git\usr\bin\ssh.exe` that does not have this issue. Point borg at it with `BORG_RSH`:

```powershell
$env:BORG_RSH = '"C:\Program Files\Git\usr\bin\ssh.exe" -o BatchMode=yes'
```

If you hit "borg init hangs forever" when initializing a remote repo on Windows, **this is almost certainly the cause**. Set `BORG_RSH` to Git's ssh and retry.

You can verify your ssh client with a one-line test (from PowerShell):

```powershell
echo test | & "C:\Program Files\Git\usr\bin\ssh.exe" -p 22 user@host "cat"
```

If that echoes `test` back, the ssh client is fine for use as borg's transport.

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

# The fork uses tags of the form v1.4.4-winN which current setuptools_scm
# rejects as non-PEP440. Override the version explicitly for the build:
$env:SETUPTOOLS_SCM_PRETEND_VERSION = "1.4.4+win6"

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
