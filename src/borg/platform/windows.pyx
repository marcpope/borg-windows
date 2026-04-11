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
    ctypedef unsigned long long ULONGLONG
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
    cdef extern int PROCESS_SET_QUOTA
    cdef extern int PROCESS_TERMINATE

    # Job Object APIs for killing the ssh.exe child when borg exits.
    HANDLE CreateJobObjectW(void* lpJobAttributes, LPCWSTR lpName)
    BOOL SetInformationJobObject(HANDLE hJob, int JobObjectInfoClass, void* lpJobObjectInfo, DWORD cbJobObjectInfoLength)
    BOOL AssignProcessToJobObject(HANDLE hJob, HANDLE hProcess)

    cdef extern int JobObjectExtendedLimitInformation
    cdef extern DWORD JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

    ctypedef struct IO_COUNTERS:
        ULONGLONG ReadOperationCount
        ULONGLONG WriteOperationCount
        ULONGLONG OtherOperationCount
        ULONGLONG ReadTransferCount
        ULONGLONG WriteTransferCount
        ULONGLONG OtherTransferCount

    ctypedef struct JOBOBJECT_BASIC_LIMIT_INFORMATION:
        long long PerProcessUserTimeLimit
        long long PerJobUserTimeLimit
        DWORD LimitFlags
        size_t MinimumWorkingSetSize
        size_t MaximumWorkingSetSize
        DWORD ActiveProcessLimit
        size_t Affinity
        DWORD PriorityClass
        DWORD SchedulingClass

    ctypedef struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION:
        JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation
        IO_COUNTERS IoInfo
        size_t ProcessMemoryLimit
        size_t JobMemoryLimit
        size_t PeakProcessMemoryUsed
        size_t PeakJobMemoryUsed


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


# Module-level handle to the single "kill when borg exits" Job Object.
# Created lazily on first use. When borg.exe exits (cleanly or via crash),
# Windows closes its handles; the last handle to the job going away triggers
# JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, which terminates every process still
# assigned to the job. Caching the handle at module scope keeps it alive for
# the whole borg process lifetime.
cdef HANDLE _kill_on_exit_job = NULL


cdef HANDLE _ensure_kill_on_exit_job() except? NULL:
    """
    Return a cached Job Object handle configured with
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. Create it on first call.
    """
    global _kill_on_exit_job
    cdef JOBOBJECT_EXTENDED_LIMIT_INFORMATION info
    cdef HANDLE job

    if _kill_on_exit_job != NULL:
        return _kill_on_exit_job

    job = CreateJobObjectW(NULL, NULL)
    if job == NULL:
        raise OSError(None, 'CreateJobObjectW failed', None, GetLastError())

    # Zero-initialize the struct, then set only the kill-on-close limit flag.
    info.BasicLimitInformation.PerProcessUserTimeLimit = 0
    info.BasicLimitInformation.PerJobUserTimeLimit = 0
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    info.BasicLimitInformation.MinimumWorkingSetSize = 0
    info.BasicLimitInformation.MaximumWorkingSetSize = 0
    info.BasicLimitInformation.ActiveProcessLimit = 0
    info.BasicLimitInformation.Affinity = 0
    info.BasicLimitInformation.PriorityClass = 0
    info.BasicLimitInformation.SchedulingClass = 0
    info.IoInfo.ReadOperationCount = 0
    info.IoInfo.WriteOperationCount = 0
    info.IoInfo.OtherOperationCount = 0
    info.IoInfo.ReadTransferCount = 0
    info.IoInfo.WriteTransferCount = 0
    info.IoInfo.OtherTransferCount = 0
    info.ProcessMemoryLimit = 0
    info.JobMemoryLimit = 0
    info.PeakProcessMemoryUsed = 0
    info.PeakJobMemoryUsed = 0

    if not SetInformationJobObject(
        job,
        JobObjectExtendedLimitInformation,
        &info,
        sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
    ):
        err = GetLastError()
        CloseHandle(job)
        raise OSError(None, 'SetInformationJobObject failed', None, err)

    _kill_on_exit_job = job
    return _kill_on_exit_job


def assign_process_to_kill_on_exit_job(int pid):
    """
    Assign *pid* to the process-wide kill-on-close Job Object so that Windows
    terminates the process automatically when borg.exe exits, regardless of
    how borg exited (clean, crash, SIGBREAK, force-kill).

    This is used to make sure the ssh.exe child spawned by RemoteRepository
    cannot outlive borg: the lingering-ssh problem that otherwise holds
    server-side state (locks, network) until ssh's own I/O timeout fires.

    Safe to call multiple times. Raises OSError on failure; callers should
    log and continue — the worst case without a job is the pre-fix behavior,
    which is not a regression.
    """
    cdef HANDLE job
    cdef HANDLE hProcess

    job = _ensure_kill_on_exit_job()
    if job == NULL:
        return

    hProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
    if hProcess == NULL:
        raise OSError(None, 'OpenProcess failed', None, GetLastError())

    try:
        if not AssignProcessToJobObject(job, hProcess):
            raise OSError(None, 'AssignProcessToJobObject failed', None, GetLastError())
    finally:
        CloseHandle(hProcess)


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
