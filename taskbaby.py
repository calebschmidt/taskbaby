from ctypes import *
from ctypes.wintypes import *
import win32process
import binascii
import sys


# Warn anytime trying to use this without psutil installed
try:
    import psutil
except ImportError:
    print('psutil not installed -- please install to run')
    print('~$ pip3 install psutil')
    exit(1)


# Aliases for struct field types
PVOID = LPVOID
SIZE_T = c_size_t
DWORD_PTR = c_ulonglong

# Flags that allow us full access to a process
# https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
PROCESS_ALL_ACCESS = 0x001F0FFF


class MEMORY_BASIC_INFORMATION(Structure):
    '''
    A structure used to hold return values of the same
    name from Windows API calls.

    Details can be found at:
    https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_memory_basic_information
    '''
    _fields_ = [
        ('BaseAddress', PVOID),
        ('AllocationBase', PVOID),
        ('AllocationProtect', DWORD),
        ('RegionSize', SIZE_T),
        ('State', DWORD),
        ('Protect', DWORD),
        ('Type', DWORD)
    ]


# Pointer type to the above structure
PMEMORY_BASIC_INFORMATION = ctypes.POINTER(MEMORY_BASIC_INFORMATION)


class TaskBaby:
    '''
    A class housing the main functionality for a
    stripped-down process-monitoring tool.
    '''

    def __init__(self, *args, **kwargs):
        # Parse out the necessary commands
        self.command = args[0].lower()
        self.kwargs = kwargs

        self.pid = kwargs.get('pid')
        self.memory_address = kwargs.get('memory_address')

        # Get a handle for the kernel32 DLL
        kernel32 = WinDLL('kernel32')
        self._open_process = kernel32.OpenProcess
        self._read_process_memory = kernel32.ReadProcessMemory
        self._virtual_query_ex = kernel32.VirtualQueryEx

        # Set argument and return types of the functions
        # we need so we can call from Python
        # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        self._open_process.argtypes = (DWORD, BOOL, DWORD)
        self._open_process.restype = HANDLE

        # https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
        self._read_process_memory.argtypes = (HANDLE, LPVOID, LPVOID, c_size_t, POINTER(c_size_t))
        self._read_process_memory.restype = BOOL

        # https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex
        self._virtual_query_ex.restype = SIZE_T
        self._virtual_query_ex.argtypes = (HANDLE, LPVOID, PMEMORY_BASIC_INFORMATION, SIZE_T)

    def run(self):
        '''
        Delegates execution to the proper handler
        based on the arguments used to intantiate
        the object.
        '''
        if self.command == '-p':
            self.enumerate_processes()
        elif self.command == '-e':
            self.read_process_memory()
        else:
            self._enumerate()

    def _process_from_pid(self, pid):
        '''
        Use the passed PID to generate a
        process object.
        '''
        try:
            process = psutil.Process(pid)
            return process
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            return None

    def enumerate_processes(self):
        '''
        Lists the name and PID for each
        active process on the system
        '''
        for proc in psutil.process_iter():
            pid = proc.pid
            name = proc.name()
            print('%s  (PID:%s)' % (name, pid))

    def _enumerate(self):
        '''
        Calls the correct method based on the specified
        command for the specified process ID, or for
        all of them if no PID is specified.
        '''
        # If pid not specified, run for all of them
        if self.pid is None:
            procs = psutil.process_iter()
        # Otherwise, just the passed PID
        else:
            procs = [self._process_from_pid(self.pid)]

        for proc in procs:
            pid = proc.pid

            # Skip the System Process
            if pid == 0:
                continue

            # Get a process object
            ps = self._process_from_pid(pid)

            # Delegate to the proper method
            if self.command == '-t':
                self._print_process_threads(ps)
            elif self.command == '-m':
                self._print_process_modules(ps)
            elif self.command == '-g':
                self._print_process_pages(ps)
            else:
                raise RuntimeError('Invalid command: \'%s\'' % self.command)

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
        Prints the thread IDs of all threads
        spawned by the specified process.
        '''
        header = 'Threads for %s  (PID: %s)' % (process.name(), process.pid)
        print(header)
        print('=' * len(header))

        # Grab all the thread IDs
        thread_ids = [thread.id for thread in process.threads() if thread.id]

        if not len(thread_ids):
            # If no threads, it means only the main process
            # thread exists for this process
            print('[No additional threads spawned]\n')
        else:
            # Print each thread ID
            for tid in thread_ids:
                print('Thread ID: %s' % tid)

        print()

    def _print_process_modules(self, process):
        '''
        Prints the names of all modules loaded
        by the specified process.
        '''
        header = 'Modules for %s  (PID: %s)' % (process.name(), process.pid)
        print(header)
        print('=' * len(header))

        try:
            # For each module loaded by the
            # process, print its name
            for module in process.memory_maps():
                print('%s' % module.path.split('\\')[-1])
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            # If we encounter an error, note it
            print('[Unable to access modules for process %s]' % process.pid)

        print()

    def _print_process_pages(self, process):
        '''
        Prints the addresses of all executable memory pages
        for the specified process.

        Inspired by similar examples at:
        https://code.activestate.com/lists/python-tutor/111100/
        and discussion of building a Windows debugger in:
        Gray Hat Python by Justin Seitz (2009)
        https://nostarch.com/ghpython.htm
        '''
        header = 'Executable memory pages for %s  (PID: %s)' % (process.name(), process.pid)
        print(header)
        print('=' * len(header))

        # Open process
        handle = self._open_process(PROCESS_ALL_ACCESS, False, process.pid)

        if not handle:
            print('[Unable to access memory pages for process %s]' % process.pid)
            return

        # Get the process modules -- returns page addresses
        modules = win32process.EnumProcessModules(handle)

        # Initialize the data structure that will hold our result
        mbi = MEMORY_BASIC_INFORMATION()

        # For each memory address returned, get its permissions
        for address in modules:
            if self._virtual_query_ex(handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi)) < ctypes.sizeof(mbi):
                # If for some reason we can't query
                # the page, note it and move on
                print('[Bad VirtualQueryEx for 0x%x!]' % address)
                continue

            # Get the protection flags for this
            # piece of allocated memory
            flags = mbi.AllocationProtect

            # Check for executable flags -- flags found at:
            # https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
            if flags & (0x10 | 0x20 | 0x40 | 0x80):
                # If executable, print its location
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

        # Assign the proper units
        if value > GB:
            return '%.2fGB' % (value / GB)
        elif value > MB:
            return '%.2fMB' % (value / MB)
        elif value > KB:
            return '%.2fKB' % (value / KB)
        return '%sB' % value


def usage():
    '''
    Prints the usage/help message for TaskBaby.
    '''
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
    '''
    Parses command-line arguments and runs an instance
    of TaskBaby to execute the given command. Displays
    a help/usage message if invalid commands or arguments
    given.
    '''
    # All commands have 1-3 components
    wrong_num_args = not 2 <= len(sys.argv) <= 4

    # Immediately display help
    # if wrong number of args
    if wrong_num_args:
        usage()
        exit(1)

    # Make sure the first arg is
    # a valid command
    flag = sys.argv[1].lower()
    if flag not in '-h -p -m -t -g -e'.split():
        usage()
        exit(1)

    # Give help if requested
    if flag == '-h':
        usage()
        exit(0)

    # Second argument for any command
    # can only be a PID; validate it
    pid = None
    if len(sys.argv) >= 3:
        pid = sys.argv[2]

    if pid is not None:
        if not pid.isnumeric():
            print('Invalid PID! Must be an integer')
            usage()
            exit(1)
        pid = int(pid)

    # Third argument can only be
    # a memory address; validate it
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

    # Pass the args and run the command
    pt = TaskBaby(flag, pid=pid, memory_address=memory_address)
    pt.run()


if __name__ == '__main__':
    main()
