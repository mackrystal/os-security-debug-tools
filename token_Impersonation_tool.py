import ctypes

from ctypes.wintypes import DWORD, BOOL, HANDLE, LPWSTR, WORD, LPBYTE

k_handle = ctypes.WinDLL("Kernel32.dll")
u_handle = ctypes.WinDLL("User32.dll")
a_handle = ctypes.WinDLL("Advapi32.dll")

PROCESS_ALL_ACCESS = (0x000F0000 | 0x0010000 | 0xFFF)

STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATION | TOKEN_QUERY |
                    TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID)

SE_PRIVILEGE_ENABLED = 0x00000002


class LUID(ctypes.Structure):
    __fields__ = [
        ("LowPart", DWORD),
        ("HighPart", DWORD),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    __fields__ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class PRIVILEGE_SET(ctypes.Structure):
    __fields__ = [
        ("PrivilegeCount", DWORD),
        ("Control", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    __fields__ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES),
    ]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    __fields__ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", HANDLE),
        ("nInheritHandle", BOOL),
    ]


class STARTUPINFO(ctypes.Structure):
    __fields__ = [
        ("cb", DWORD),
        ("lpReserved", LPWSTR),
        ("lpDesktop", LPWSTR),
        ("lpTitle", LPWSTR),
        ("dwX", DWORD),
        ("dxY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", DWORD),
        ("cbReserved2", DWORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    __fields__ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]


def enablePrivilege(priv, handle):

    requiredPrivileges = PRIVILEGE_SET()
    requiredPrivileges.PrivilegeCount = 1
    requiredPrivileges.Privileges = LUID_AND_ATTRIBUTES()
    requiredPrivileges.Privileges.Luid = LUID()

    lpSystemName = None
    lpName = priv

    response = a_handle.LookupPrivilegesValueW(
        lpSystemName, lpName, ctypes.byref(requiredPrivileges.Luid))

    if response > 0:
        print("[INFO] Lookup For {0} Worked..".format(priv))
    else:
        print("[ERROR] Lookup for {0} Failed! Error Code: {a}".format(
            priv, k_handle.GetLastError()))
        return 1

    pfResult = ctypes.c_long()

    response = a_handle.PrivilegeCheck(handle, ctypes.byref(
        requiredPrivileges), ctypes.byref(pfResult))

    if response > 0:
        print("[INFO] PrivilegeCheck Worked...")
    else:
        print("[ERROR] PrivilegeCheck Failed! Error Code: {0}".format(
            k_handle.GetLastError()))
        return 1

    if pfResult:
        print("[INFO] Privilege {0} is Enable..".format(priv))
        return 0
    else:
        print("[INFO] Privilege {0} is NOT Enabled...".format(priv))
        requiredPrivileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED

    DisableAllPrivileges = False
    NewState = TOKEN_PRIVILEGES()
    BufferLength = ctypes.sizeof(NewState)
    PriviousState = ctypes.c_void_p()
    ReturnLength = ctypes.c_void_p()

    NewState.PrivilegeCount = 1
    NewState.Privileges = requiredPrivileges.Privileges

    response = a_handle.AdjustTokenPrivileges(
        handle,
        DisableAllPrivileges,
        ctypes.byref(NewState),
        BufferLength,
        ctypes.byref(PriviousState),
        ctypes.byref(ReturnLength))

    if response > 0:
        print("[INFO] AdjustTokenPrivileges of {0} Enabled...".format(priv))
    else:
        print("[ERROR] AdjustTokenPrivileges {0} Not Enable: Error Code: {a}".format(
            priv, k_handle.GetLastError()))
        return 1

    return 0


def openProcessById(pid):
    dwDesiredAcces = PROCESS_ALL_ACCESS
    bInheritHandle = False
    dwProcessId = pid

    hProcess = k_handle.OpenProcess(
        dwDesiredAcces, bInheritHandle, dwProcessId)

    if hProcess <= 0:
        print("[ERROR] Could Not Grab Privileged Handle! Error Code: {0}".format(
            k_handle.GetLastError()))
        return 1

    print("[INFO] Privileged Handle Opened...")
    return hProcess


def OpenProcToken(pHandle):
    ProcessHandle = pHandle
    DesiredAccess = TOKEN_ALL_ACCESS
    TokenHandle = ctypes.c_void_p()

    response = k_handle.OpenProcessToken(
        ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))

    if response > 0:
        print("[INFO] Handle to Process Token Created! Token: {0}".format(
            TokenHandle))
        return TokenHandle
    else:
        print("[ERROR] Could Not Grab Privileged Handle to Process! Error Code: {0}".format(
            k_handle.GetLastError()))
        return 1
