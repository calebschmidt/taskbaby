from ctypes import *
from ctypes.wintypes import *
import win32process
import binascii
import sys

try:
    import psutil
except ImportError:
    print('psutil not installed -- please install to run')
    print('~$ pip3 install psutil')
    exit(1)


PVOID = LPVOID
SIZE_T = ctypes.c_size_t
DWORD_PTR = ctypes.c_ulonglong

# Flags that allow us full access to a process
PROCESS_ALL_ACCESS = 0x001F0FFF


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


PMEMORY_BASIC_INFORMATION = ctypes.POINTER(MEMORY_BASIC_INFORMATION)


class ProcessTool:
    '''
    A class housing the main functionality for a
    stripped process-monitoring tool.
    '''

    def __init__(self, *args, **kwargs):
        self.command = args[0].lower()
        self.kwargs = kwargs

        self.pid = kwargs.get('pid')
        self.memory_address = kwargs.get('memory_address')

        # Get a handle for the kernel32 DLL
        kernel32 = WinDLL('kernel32')
        self._open_process = kernel32.OpenProcess
        self._read_process_memory = kernel32.ReadProcessMemory

        # Set argument and return types of the functions we need
        # so we can call from Python
        self._open_process.argtypes = DWORD, BOOL, DWORD
        self._open_process.restype = HANDLE

        self._read_process_memory.argtypes = HANDLE, LPVOID, LPVOID, c_size_t, POINTER(c_size_t)
        self._read_process_memory.restype = BOOL

    def run(self):
        '''
        TODO: Documentation
        '''
        if self.command == '-p':
            self.enumerate_processes()
        elif self.command == '-t':
            self.enumerate('t')
        elif self.command == '-m':
            self.enumerate('m')
        elif self.command == '-g':
            self.enumerate('g')
        elif self.command == '-e':
            self.read_process_memory()

    def _process_from_pid(self, pid):
        '''
        TODO: Documentation
        '''
        try:
            process = psutil.Process(pid)
            return process
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            return None

    def enumerate_processes(self):
        '''
        TODO: Documentation
        '''
        for proc in psutil.process_iter():
            pid = proc.pid
            name = proc.name()
            print('%s  (PID:%s)' % (name, pid))

    def enumerate(self, processor='t'):
        '''
        TODO: Documentation
        '''
        # If not specified, list all threads
        if self.pid is None:
            for proc in psutil.process_iter():
                pid = proc.pid

                # Skip the System Process
                if pid == 0:
                    continue

                ps = self._process_from_pid(pid)

                if processor == 't':
                    self._print_process_threads(ps)
                elif processor == 'm':
                    self._print_process_modules(ps)
                elif processor == 'g':
                    self._print_process_pages(ps)
        else:
            ps = self._process_from_pid(self.pid)

            if processor == 't':
                self._print_process_threads(ps)
            elif processor == 'm':
                self._print_process_modules(ps)
            elif processor == 'g':
                self._print_process_pages(ps)

    def read_process_memory(self, buffer_size=512, permissions_flags=0x10):
        '''
        Reads the raw memory from the specified PID at the passed address
        and prints a buffer_size hexdump to stdout. Defaults to read only
        access and a buffer size of 512 bytes.

        Inspired largely by the question and answers at:
        https://stackoverflow.com/questions/52521963/reading-data-from-process-memory-with-python
        '''
        # A C-style buffer to save the memory read into
        buffer = create_string_buffer(buffer_size)
        s = c_size_t()

        # Open and read process memory
        process = self._open_process(permissions_flags, 0, self.pid)
        if self._read_process_memory(process, self.memory_address, buffer, buffer_size, byref(s)):
            # Successful memory read, print it out
            self._print_raw_memory(buffer.raw)
        else:
            # Something went wrong reading memory
            print('[Error reading memory for PID %d @ 0x%x]' % (self.pid, self.memory_address))

    def _print_raw_memory(self, raw):
        '''
        Prints a pretty, readable hexdump of the passed raw binary
        string.
        Inspired by the implementation of a similar feature at:
        https://bitbucket.org/techtonik/hexdump/src/default/hexdump.py
        '''
        hex_string = binascii.hexlify(raw).decode('ascii')

        # Title
        print('Memory for PID %d @ 0x%x' % (self.pid, self.memory_address))
        print()

        # Hexdump header
        print('0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  | 0123456789ABCDEF')
        print('================================================|=================')

        line = ''

        # Print each byte and accumulate an ASCII representation
        for i in range(0, len(hex_string), 2):
            if i and not i % 32:
                # After 32 hex characters, print the ASCII line and go to next line
                print('|', line)

                # Reset line
                line = ''

            # Get the hex string representation of byte
            byte = hex_string[i:i + 2]

            # Get an integer representation of byte
            as_int = int(byte, base=16)

            # Get if printable ASCII character
            if 0x20 <= as_int <= 0x7e:
                as_char = chr(as_int)
            # Use '.' as placeholder for unprintables
            else:
                as_char = '.'

            # Show the hex string of the byte
            print(byte, end=' ')

            # Add character to the ASCII string version
            line += as_char

        print('|', line)

    def _print_process_threads(self, process):
        '''
        TODO: Documentation
        '''
        header = 'Threads for %s  (PID: %s)' % (process.name(), process.pid)
        print(header)
        print('=' * len(header))

        thread_ids = [thread.id for thread in process.threads() if thread.id]

        if not len(thread_ids):
            print('[No additional threads spawned]\n')
        else:
            for tid in thread_ids:
                print('Thread ID: %s' % tid)

        print()

    def _print_process_modules(self, process):
        '''
        TODO: Documentation
        '''
        header = 'Modules for %s  (PID: %s)' % (process.name(), process.pid)
        print(header)
        print('=' * len(header))

        try:
            for module in process.memory_maps():
                print('%s' % module.path.split('\\')[-1])
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            print('[Unable to access modules for process %s]' % process.pid)

        print()

    def _print_process_pages(self, process):
        '''
        TODO: Documentation
        '''
        header = 'Executable memory pages for %s  (PID: %s)' % (process.name(), process.pid)
        print(header)
        print('=' * len(header))

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Open process
        handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process.pid)
        if not handle:
            print('[Unable to access memory pages for process %s]' % process.pid)
            return

        # Get the process modules -- returns page addresses
        modules = win32process.EnumProcessModules(handle)

        # Setup VirtualQueryEx
        VirtualQueryEx = kernel32.VirtualQueryEx
        VirtualQueryEx.restype = SIZE_T
        VirtualQueryEx.argtypes = (HANDLE, LPVOID, PMEMORY_BASIC_INFORMATION, SIZE_T)

        mbi = MEMORY_BASIC_INFORMATION()

        for address in modules:
            if VirtualQueryEx(handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi)) < ctypes.sizeof(mbi):
                print('Bad VirtualQueryEx for 0x%x!' % address)
                continue

            flags = mbi.AllocationProtect

            # Check for executable flags:
            # https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
            if flags & (0x10 | 0x20 | 0x40 | 0x80):
                print('Page address:', hex(mbi.BaseAddress))

        print()

    def _format_value(self, value):
        '''
        Takes a byte count and returns a nice,
        human-readable version for printing.
        '''
        KB = 1024
        MB = KB**2
        GB = MB**2

        if value > GB:
            return '%.2fGB' % (value / GB)
        elif value > MB:
            return '%.2fMB' % (value / MB)
        elif value > KB:
            return '%.2fKB' % (value / KB)
        return '%sB' % value


def usage():
    print('\npython3 taskbaby.py [ -p | -m [PID] | -t [PID] | -g [PID] | -e PID MEM_ADDR]\n')
    print('============================================================================\n')
    print('-h                   Show help -- You\'re here!\n')
    print('-p                   List all running processes.\n')
    print('-m [PID]             List modules loaded for all running processes')
    print('                     or a specified process.\n')
    print('-t [PID]             List threads for all running processes or a')
    print('                     specified process.\n')
    print('-g [PID]             List executable memory pages for all running')
    print('                     processes or a specified process.\n')
    print('-e PID MEM_ADDR      Print a hexdump of memory at the specified')
    print('                     address for the specified process.\n')


def main():
    wrong_num_args = not 2 <= len(sys.argv) <= 4

    if wrong_num_args:
        usage()
        exit(1)

    flag = sys.argv[1].lower()

    if flag not in '-h -p -m -t -g -e'.split():
        usage()
        exit(1)

    if flag == '-h':
        usage()
        exit(0)

    pid = None
    if len(sys.argv) >= 3:
        pid = sys.argv[2]

    if pid is not None:
        if not pid.isnumeric():
            print('Invalid PID! Must be an integer')
            usage()
            exit(1)
        pid = int(pid)

    memory_address = None
    if len(sys.argv) >= 4:
        memory_address = sys.argv[3]

    if memory_address is not None:
        try:
            memory_address = int(memory_address, base=16)
        except BaseException as e:
            print('Invalid memory address! Must be hex number (e.g., "0xBEEF")')
            usage()
            exit(1)

    pt = ProcessTool(flag, pid=pid, memory_address=memory_address)
    pt.run()


if __name__ == '__main__':
    main()
