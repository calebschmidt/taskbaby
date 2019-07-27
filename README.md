# TaskBaby

TaskBaby is a stripped-down process monitoring tool.

## Installation

TaskBaby is a Python script built and tested in Python 3.6 on
Windows 10. A different version of Python or Windows may
affect the functionality of the program. _Caveat executor_. It
depends on the third-party Python modules `psutil` and `win32com`.
These can be installed using `pip`:

```shell
pip install psutil
pip install win32com
```

## Usage

TaskBaby is run using Python 3:

```shell
python3 taskbaby.py [ -p | -m [PID] | -t [PID] | -g [PID] | -e PID MEM_ADDR | -h ]
```

#### Options 
###### `-h`
Show help. Simple enough.

###### `-p`
List all running processes by name and PID.

###### `-m [PID]`
List modules loaded for all running processes or a specified process.

###### `-t [PID]`
List threads for all running processes or a specified process.

###### `-g [PID]`
List executable memory pages for all running processes or a specified process.

###### `-e PID MEM_ADDR`
Print a hexdump of memory at the specified address for the specified process.

