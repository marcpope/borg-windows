import os
import platform
from functools import lru_cache

from ..helpers import safe_encode


from libc.stddef cimport wchar_t

cdef extern from "Python.h":
    object PyUnicode_FromWideChar(const wchar_t *w, Py_ssize_t size)
    wchar_t* PyUnicode_AsWideCharString(object unicode, Py_ssize_t *size)
    void PyMem_Free(void *p)

cdef extern from 'windows.h':
    ctypedef void* HANDLE
    ctypedef void* LPVOID
    ctypedef int BOOL
    ctypedef unsigned long DWORD
    ctypedef unsigned short WORD
    ctypedef const char* LPCSTR
    ctypedef char* LPSTR
    ctypedef const wchar_t* LPCWSTR
    ctypedef wchar_t* LPWSTR

    BOOL CloseHandle(HANDLE hObject)
    HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dbProcessId)
    DWORD GetLastError()
    void LocalFree(HANDLE hMem)

    cdef extern int PROCESS_QUERY_INFORMATION


# Security descriptor / ACL types
cdef extern from 'windows.h':
    ctypedef void* PSECURITY_DESCRIPTOR
    ctypedef void* PACL
    ctypedef void* PSID

    ctypedef DWORD SECURITY_INFORMATION

    cdef extern SECURITY_INFORMATION DACL_SECURITY_INFORMATION
    cdef extern SECURITY_INFORMATION SACL_SECURITY_INFORMATION
    cdef extern SECURITY_INFORMATION OWNER_SECURITY_INFORMATION
    cdef extern SECURITY_INFORMATION GROUP_SECURITY_INFORMATION

    cdef extern int SE_FILE_OBJECT


cdef extern from 'aclapi.h':
    DWORD GetNamedSecurityInfoW(
        LPCWSTR pObjectName,
        int ObjectType,
        SECURITY_INFORMATION SecurityInfo,
        PSID *ppsidOwner,
        PSID *ppsidGroup,
        PACL *ppDacl,
        PACL *ppSacl,
        PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
    )

    DWORD SetNamedSecurityInfoW(
        LPWSTR pObjectName,
        int ObjectType,
        SECURITY_INFORMATION SecurityInfo,
        PSID psidOwner,
        PSID psidGroup,
        PACL pDacl,
        PACL pSacl,
    )


cdef extern from 'sddl.h':
    BOOL ConvertSecurityDescriptorToStringSecurityDescriptorW(
        PSECURITY_DESCRIPTOR SecurityDescriptor,
        DWORD RequestedStringSDRevision,
        SECURITY_INFORMATION SecurityInformation,
        LPWSTR *StringSecurityDescriptor,
        DWORD *StringSecurityDescriptorLen,
    )

    BOOL ConvertStringSecurityDescriptorToSecurityDescriptorW(
        LPCWSTR StringSecurityDescriptor,
        DWORD StringSDRevision,
        PSECURITY_DESCRIPTOR *SecurityDescriptor,
        DWORD *SecurityDescriptorSize,
    )


# SDDL revision constant
cdef DWORD SDDL_REVISION_1 = 1

# What we store: owner + group + DACL.
# We skip SACL because reading/writing it requires SE_SECURITY_NAME privilege
# (audit log permissions), which even Administrators don't have by default.
cdef SECURITY_INFORMATION ACL_READ_INFO = 0x00000001 | 0x00000002 | 0x00000004  # OWNER | GROUP | DACL
cdef SECURITY_INFORMATION ACL_WRITE_DACL_INFO = 0x00000004  # DACL_SECURITY_INFORMATION
cdef SECURITY_INFORMATION ACL_WRITE_OWNER_INFO = 0x00000001 | 0x00000002  # OWNER | GROUP


@lru_cache(maxsize=None)
def uid2user(uid, default=None):
    return default


@lru_cache(maxsize=None)
def user2uid(user, default=None):
    return default


@lru_cache(maxsize=None)
def gid2group(gid, default=None):
    return default


@lru_cache(maxsize=None)
def group2gid(group, default=None):
    return default


def getosusername():
    """Return the os user name."""
    return os.getlogin()


def process_alive(host, pid, thread):
    """
    Check if the (host, pid, thread_id) combination corresponds to a potentially alive process.
    """
    if host.split('@')[0].lower() != platform.node().lower():
        # Not running on the same node, assume running.
        return True

    # If the process can be opened, the process is alive.
    handle = OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if handle != NULL:
        CloseHandle(handle)
        return True
    return False


def local_pid_alive(pid):
    """Return whether *pid* is alive."""
    raise NotImplementedError


def acl_get(path, item, st, numeric_ids=False, fd=None):
    """
    Read the Windows DACL (and owner/group SIDs) from a file and store as an SDDL string.

    The SDDL string captures the owner (O:), group (G:), and DACL (D:) portions
    of the security descriptor.  SACL is not included because it requires
    SE_SECURITY_NAME privilege.

    *numeric_ids* is accepted for API compatibility with the POSIX implementations
    but has no effect on Windows — SIDs are always stored as-is in the SDDL string
    (they are already numeric identifiers).
    """
    cdef PSECURITY_DESCRIPTOR pSD = NULL
    cdef LPWSTR sddl_str = NULL
    cdef DWORD sddl_len = 0
    cdef DWORD result
    cdef wchar_t *wpath = NULL
    cdef Py_ssize_t wpath_len = 0

    if isinstance(path, bytes):
        path = os.fsdecode(path)

    # Convert Python str to wchar_t* for the W-suffixed Win32 API.
    wpath = PyUnicode_AsWideCharString(path, &wpath_len)
    if wpath == NULL:
        raise MemoryError("failed to convert path to wide string")

    try:
        result = GetNamedSecurityInfoW(
            wpath,
            SE_FILE_OBJECT,
            ACL_READ_INFO,  # OWNER | GROUP | DACL
            NULL,   # ppsidOwner — we get it from the SD
            NULL,   # ppsidGroup
            NULL,   # ppDacl
            NULL,   # ppSacl
            &pSD,
        )
        if result != 0:
            # ERROR_SUCCESS is 0; any other value is a Win32 error code.
            if pSD != NULL:
                LocalFree(pSD)
            raise OSError(None, os.strerror(result), path, result)

        try:
            if not ConvertSecurityDescriptorToStringSecurityDescriptorW(
                pSD,
                SDDL_REVISION_1,
                ACL_READ_INFO,  # emit O:, G: and D: sections
                &sddl_str,
                &sddl_len,
            ):
                err = GetLastError()
                raise OSError(None, os.strerror(err), path, err)

            try:
                # sddl_str is a null-terminated wide string allocated by Windows.
                # Convert to Python str, then encode to bytes for storage
                # (all other platforms store ACL data as bytes in the item dict).
                # Use -1 to let Python find the null terminator itself.
                py_sddl = PyUnicode_FromWideChar(sddl_str, -1)
                item['acl_windows'] = safe_encode(py_sddl)
            finally:
                LocalFree(sddl_str)
        finally:
            LocalFree(pSD)
    finally:
        PyMem_Free(wpath)


def acl_set(path, item, numeric_ids=False, fd=None):
    """
    Restore a Windows DACL (and owner/group SIDs) from a stored SDDL string.

    This attempts to restore the full DACL first.  If setting the owner/group
    fails (requires SE_RESTORE_NAME privilege), the DACL is still applied.

    *numeric_ids* is accepted for API compatibility but has no effect on Windows.
    """
    cdef DWORD result

    sddl_bytes = item.get('acl_windows')
    if not sddl_bytes:
        return

    if isinstance(path, bytes):
        path = os.fsdecode(path)

    # Decode the stored bytes back to a Python str (which Cython passes as a wide string).
    sddl_text = os.fsdecode(sddl_bytes) if isinstance(sddl_bytes, bytes) else sddl_bytes

    # Apply owner + group + DACL in one call.  Setting owner/group requires
    # SE_RESTORE_NAME privilege (typically only available to Administrators with
    # elevated tokens).  If that fails, fall back to DACL-only.
    result = _apply_security_from_sddl(path, sddl_text, ACL_READ_INFO)
    if result != 0:
        # Fall back: try DACL only (no owner/group).
        result = _apply_security_from_sddl(path, sddl_text, ACL_WRITE_DACL_INFO)
        if result != 0:
            raise OSError(None, os.strerror(result), path, result)


cdef extern from 'windows.h':
    BOOL GetSecurityDescriptorDacl(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        BOOL *lpbDaclPresent,
        PACL *pDacl,
        BOOL *lpbDaclDefaulted,
    )
    BOOL GetSecurityDescriptorOwner(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        PSID *pOwner,
        BOOL *lpbOwnerDefaulted,
    )
    BOOL GetSecurityDescriptorGroup(
        PSECURITY_DESCRIPTOR pSecurityDescriptor,
        PSID *pGroup,
        BOOL *lpbGroupDefaulted,
    )


cdef DWORD _apply_security_from_sddl(path, sddl_text, SECURITY_INFORMATION sec_info):
    """
    Parse an SDDL string into a security descriptor, extract the requested
    components (owner, group, DACL), and apply them to the given path.

    Returns 0 on success, or a Win32 error code on failure.
    """
    cdef PSECURITY_DESCRIPTOR pSD = NULL
    cdef DWORD sd_size = 0
    cdef PACL pDacl = NULL
    cdef PSID pOwner = NULL
    cdef PSID pGroup = NULL
    cdef BOOL bPresent = 0
    cdef BOOL bDefaulted = 0
    cdef DWORD result
    cdef wchar_t *wsddl = NULL
    cdef wchar_t *wpath = NULL
    cdef Py_ssize_t sddl_len = 0
    cdef Py_ssize_t path_len = 0

    wsddl = PyUnicode_AsWideCharString(sddl_text, &sddl_len)
    if wsddl == NULL:
        return GetLastError()

    wpath = PyUnicode_AsWideCharString(path, &path_len)
    if wpath == NULL:
        PyMem_Free(wsddl)
        return GetLastError()

    try:
        if not ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wsddl, SDDL_REVISION_1, &pSD, &sd_size,
        ):
            return GetLastError()

        try:
            # Extract the DACL pointer from the parsed SD.
            if sec_info & 0x00000004:  # DACL_SECURITY_INFORMATION
                if not GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefaulted):
                    return GetLastError()
                if not bPresent:
                    pDacl = NULL

            # Extract owner SID.
            if sec_info & 0x00000001:  # OWNER_SECURITY_INFORMATION
                if not GetSecurityDescriptorOwner(pSD, &pOwner, &bDefaulted):
                    return GetLastError()

            # Extract group SID.
            if sec_info & 0x00000002:  # GROUP_SECURITY_INFORMATION
                if not GetSecurityDescriptorGroup(pSD, &pGroup, &bDefaulted):
                    return GetLastError()

            result = SetNamedSecurityInfoW(
                wpath,
                SE_FILE_OBJECT,
                sec_info,
                pOwner,
                pGroup,
                pDacl,
                NULL,  # no SACL
            )
            return result
        finally:
            LocalFree(pSD)
    finally:
        PyMem_Free(wsddl)
        PyMem_Free(wpath)
