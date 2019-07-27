# https://code.activestate.com/lists/python-tutor/111100/
import ctypes
from ctypes.wintypes import WORD, DWORD, LPVOID, HANDLE, HMODULE
import win32process

PVOID = LPVOID
SIZE_T = ctypes.c_size_t

MEM_COMMIT = 0x1000
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_WRITECOPY = 0x80
PROCESS_ALL_ACCESS = 0x001F0FFF

# https://msdn.microsoft.com/en-us/library/aa383751#DWORD_PTR
if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulonglong):
    DWORD_PTR = ctypes.c_ulonglong
elif ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_ulong):
    DWORD_PTR = ctypes.c_ulong


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """https://msdn.microsoft.com/en-us/library/aa366775"""
    _fields_ = [
        ('BaseAddress', PVOID),
        ('AllocationBase',    PVOID),
        ('AllocationProtect', DWORD),
        ('RegionSize', SIZE_T),
        ('State',   DWORD),
        ('Protect', DWORD),
        ('Type',    DWORD)
    ]


class SYSTEM_INFO(ctypes.Structure):
    """https://msdn.microsoft.com/en-us/library/ms724958"""
    class _U(ctypes.Union):
        class _S(ctypes.Structure):
            _fields_ = (('wProcessorArchitecture', WORD),
                        ('wReserved', WORD))
        _fields_ = (('dwOemId', DWORD), # obsolete
                    ('_s', _S))
        _anonymous_ = ('_s',)
    _fields_ = (('_u', _U),
                ('dwPageSize', DWORD),
                ('lpMinimumApplicationAddress', LPVOID),
                ('lpMaximumApplicationAddress', LPVOID),
                ('dwActiveProcessorMask',   DWORD_PTR),
                ('dwNumberOfProcessors',    DWORD),
                ('dwProcessorType',         DWORD),
                ('dwAllocationGranularity', DWORD),
                ('wProcessorLevel',    WORD),
                ('wProcessorRevision', WORD))
    _anonymous_ = ('_u',)


PMEMORY_BASIC_INFORMATION = ctypes.POINTER(MEMORY_BASIC_INFORMATION)
PSYSTEM_INFO = ctypes.POINTER(SYSTEM_INFO)


kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)


# System Info
kernel32.GetSystemInfo.restype = None
kernel32.GetSystemInfo.argtypes = (PSYSTEM_INFO,)

sysinfo = SYSTEM_INFO()
kernel32.GetSystemInfo(ctypes.byref(sysinfo))
page_size = sysinfo.dwPageSize
print('SYS PAGE SIZE:', page_size)

# Process info
pid = 3224
# address = 0x00007FFC0C950000

# Open other process
handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
print('HANDLE:', handle)

# Get the process base address
modules = win32process.EnumProcessModules(handle)

# Setup VirtualQueryEx
VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.restype = SIZE_T
VirtualQueryEx.argtypes = (HANDLE, LPVOID, PMEMORY_BASIC_INFORMATION, SIZE_T)


mbi = MEMORY_BASIC_INFORMATION()

for address in modules:
    if VirtualQueryEx(handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi)) < ctypes.sizeof(mbi):
        print('BAD VIRTUAL QUERY!')
        exit(1)

    flag = mbi.AllocationProtect

    # Check for executable flag: https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    if (flag & 0x10) | (flag & 0x20) | (flag & 0x40) | (flag & 0x80):
        print('==========')
        print('BASE ADDR:', hex(mbi.BaseAddress))

        # Is it executable?
        print('PERMISSIONS:', hex(mbi.AllocationProtect))

