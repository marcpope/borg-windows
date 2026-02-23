# -*- mode: python ; coding: utf-8 -*-
import os
import sys

block_cipher = None

# Paths to DLLs
vcpkg_bin = r'C:\vcpkg\installed\x64-windows\bin'
openssl_bin = r'C:\Program Files\OpenSSL-Win64\bin'

# Collect all runtime DLLs
binaries = [
    (os.path.join(vcpkg_bin, 'lz4.dll'), '.'),
    (os.path.join(vcpkg_bin, 'zstd.dll'), '.'),
    (os.path.join(vcpkg_bin, 'xxhash.dll'), '.'),
    (os.path.join(openssl_bin, 'libcrypto-3-x64.dll'), '.'),
    (os.path.join(openssl_bin, 'libssl-3-x64.dll'), '.'),
]

# Hidden imports - Cython extensions and submodules PyInstaller can't detect
hidden_imports = [
    'borg.chunker',
    'borg.compress',
    'borg.hashindex',
    'borg.item',
    'borg.crypto.low_level',
    'borg.algorithms.checksums',
    'borg.platform',
    'borg.platform.base',
    'borg.platform.windows',
    'borg.platform.xattr',
    'borg.platformflags',
    'borg.helpers',
    'borg.helpers.checks',
    'borg.helpers.datastruct',
    'borg.helpers.errors',
    'borg.helpers.fs',
    'borg.helpers.manifest',
    'borg.helpers.misc',
    'borg.helpers.msgpack',
    'borg.helpers.parseformat',
    'borg.helpers.process',
    'borg.helpers.progress',
    'borg.helpers.time',
    'borg.helpers.yes',
    'borg.crypto',
    'borg.crypto.key',
    'borg.crypto.keymanager',
    'borg.crypto.file_integrity',
    'borg.crypto.nonces',
    'borg.archive',
    'borg.archiver',
    'borg.cache',
    'borg.constants',
    'borg.fuse',
    'borg.locking',
    'borg.logger',
    'borg.lrucache',
    'borg.nanorst',
    'borg.patterns',
    'borg.remote',
    'borg.repository',
    'borg.selftest',
    'borg.shellpattern',
    'borg.upgrader',
    'borg.version',
    'borg._version',
    'borg.xattr',
    # selftest imports these testsuite modules
    'borg.testsuite',
    'borg.testsuite.hashindex',
    'borg.testsuite.crypto',
    'borg.testsuite.chunker',
    # msgpack is a runtime dependency
    'msgpack',
    'msgpack.fallback',
    'msgpack._cmsgpack',
]

a = Analysis(
    ['borg-entry.py'],
    pathex=[],
    binaries=binaries,
    datas=[],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='borg',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='borg',
)
