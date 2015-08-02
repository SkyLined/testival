A suite of tools that can be used to automatically check that (shell)code works correctly and to test ret-into-libc attacks.

Testival requires [SkyBuild](http://code.google.com/p/skybuild/) to build automatically.

Testival is used by [ALPHA3](http://code.google.com/p/alpha3/) to test its encoders.

Example usage:
```
testival>w32-testival.exe eip=$ [$]=ascii:writeconsole-shellcodes\w32-writeconsole-shellcode.bin
Hello, world!
testival>w32-testival.exe --loadlibrary writeconsole-shellcodes\w32-writeconsole-shellcode.dll
Hello, world!
```
Help:
```
usage: w32-testival [set register] [set memory] [options...]
or:    w32-testival --loadlibrary "module file name"
(use "w64-testival" if testing x64 shellcodes)

Testival can be used to test shellcode and ret-into-libc stacks or to load a
dll into the process by calling kernel32!LoadLibrary. The later is useful when
testing a dll that executes shellcode when it gets loaded.
The former allocates memory at any valid address, of any valid size,
protection flags and allocation type. It set registers to any values and can
set bytes at any location in memory to any value. It can load binary files
(shellcode or ret-into-libc stacks) at any location in memory.
It can fake a ret-into-libc, an overwritten return address or a JMP to any
address and trigger a debugger break before doing so, to attach your debugger
.Exceptions can be handled to output information about them to stderr.

Registers can be using "{reg}={value}", where {reg} is the name of a register
and {value} is a 32/64-bit hexadecimal value or an offset*.
Memory can be set using "[{address}]={data}", where {address} is the address
or offset* at which to store the data, and {data} can be on of the following:
  value:{value} to write a 32/64-bit hexadecimal number or offset* to the address.
  ascii:{file name} to read the specified file into memory at the given address.
  uncode:{file name} to read the specified file, insert a NULL byte after every
  byte of the file and store the result in memory at the given address.
  (Use "con" as the file name to read data from stdin).

* values and addresses can be entered as a hexadecimal number or as an offset
from the base address of the allocated memory. To specify an offset use one of
the following: $, $+{value} or $-{value}.

Options
    --loadlibrary "module file name"
                     Attempt to load the given module into the process and
                     then terminate the application.
Non "LoadLibrary" options:
    --mem:address    Specify the address at which to allocate memory.
    --mem:size       Specify the number of bytes of memory to allocate.
    --mem:type       Specify the "flAllocationType" argument to be passed to
                     VirtualAlloc - see MSDN for more details.
    --mem:protect    Specify the "flProtect" argument to be passed to
                     VirtualAlloc - see MSDN for more details.
    --ret            Use a RET instruction to set EIP/RIP, instead of the
                     default JMP instruction.
General options:
    --verbose        Output verbose information.
    --delay:time     Wait the given number of milliseconds before executing the
                     shellcode or loading the library.
    --int3           Trigger a debugger breakpoint before setting EIP/RIP or.
                     loading the module into the process.
    --EH             Use a Structured Exception Handler filter to catch all
                     unhandled exceptions and report exception information
                     before terminating the application.
    --EH --EH        Same as "--EH" but add a Vectored Exception Handler to
                     catch first change exceptions and report exception
                     information about them as well.
  (Debug breakpoints are ignored by both --EH settings; no information is
  reported and the application is not terminated).
Stand-alone options:
    --help           Output this information.
    --version        Output version and build information.

Example usage:
  w32-testival.exe eip=$ [$]=ascii:w32-writeconsole-shellcode.bin
  w64-testival.exe --loadlibrary w64-writeconsole-shellcode.dll
```