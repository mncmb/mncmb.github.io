---
layout: post
title: "WinAPI shellcode injection with python"
categories: winapi, python, windows10, code injection
---

Injecting shellcode in a 64 bit process with Python 3.x and the WinAPI. 

## intro

Since I wanted to gain some familiarity with common code injection and using the Windows API, When starting this I thought doing this in Python would be easier. Turns out you can achieve the same in C++ with less issues because there are plenty of examples on how to do simple code injection with VirtualAllocEx and CreateRemoteThread out there. Some of the problems encountered have to do with how `ctypes`, the python library for foreign function calls, interacts with Windows DLLs, the types it uses by default and some changes throughout the versions of `ctypes`. 

Still, if you are not too familiar with the subject this can serve as an introduction into process injection, debugging issues with `ctypes`, as well as gaining some to the Windows API.

This post was inspired by [https://www.andreafortuna.org/2018/08/06/code-injection-on-windows-using-python-a-simple-example/](https://www.andreafortuna.org/2018/08/06/code-injection-on-windows-using-python-a-simple-example/). Check out the site, it offers great information on DFIR and other subjects. 

## Quickly setting up a dev environment
Among my currently active Windows VMs, the next best thing I had to a development environment for this little project was the `Victim`-VM running Windows 10 of Malware Unicorns `Reverse Engineering 101 / 102` course.
This VM was pretty much usable right out of the box. It had pre installed `Process Hacker`, `x64dbg`, `VSCode` and `python3` on a Win10 VM.
As an alternative you could use the windows 10 developer VM with some additional tooling or something like FlareVM.

The Shellcode Injection PoC I was using was from `fdiskyou` and is available here: 

[https://gist.github.com/fdiskyou/557bf139ceb5c1b95b9eb4cb5d9167d2](https://gist.github.com/fdiskyou/557bf139ceb5c1b95b9eb4cb5d9167d2)

As for quick execution: Open powershell in the same directory the script resides by `shift` + rightclicking and then enter the path to python followed by the script. 
If you use one of the above solutions this is:
```
C:\Users\IEUser\AppData\Local\Programs\Python\Python37\python.exe .\code_injection.py <PID>
```


## Running the script 

When running the script out of the box, the first problem encountered with python3 is obviously print related. Fixing this is as simple as adding brackets around the print string.

Afterwards the first real problem can be encountered:
```s
Traceback (most recent call last):
  File ".\code_injection.py", line 51, in <module>
    kernel32.WriteProcessMemory(h_process, arg_address, shellcode, len(shellcode), byref(written))
ctypes.ArgumentError: argument 3: <class 'ValueError'>: embedded null character
```
From a bit of digging into the issue it seems that behaviour in `ctypes` was changed somewhere around python 3.6 and embedded null characters are no longer accepted, even when a size for the buffer has been set. 

In order to avoid the issue we can simply generate new shellcode that eliminates the null bytes by specifying them as bad bytes. This results in different XOR encryptions being tried out until the resulting shellcode no longer contains the specified bad bytes.

The shellcode can be generated as follows with msfvenom:
```s
msfvenom -p windows/x64/exec CMD=calc.exe EXITFUNC=thread -b '\x00' -f python
```

The generated code opens calc.exe and exits the current thread. 

When replacing the shellcode from the POC with this one and executing the python script, it crashes the process. Because I wanted to avoid issues with different [process integrity levels](https://docs.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control), injection was performed on notepad.exe.

## Investigating the crash
In order to debug the crash, start to look into each step of the injection in a debugger.

If we break down the injection then it consists of the following steps:

1. acquire handle to process
2. allocate memory 
3. write memory
4. start new thread at memory

Since the injection code already has some basic error handling when one of the steps fails, we are most likely looking at a problem that occurs after the last step, the execution of our code. This would explain the following output from the script:

```s
PS C:\Users\IEUser\Desktop\documentation_procInj> C:\Users\IEUser\AppData\Local\Programs\Python\Python37\python.exe .\code_injection.py 448
<class 'bytes'>
[*] code injection successfull (thread ID: 0x0000143c)
PS C:\Users\IEUser\Desktop\documentation_procInj>
```

So the injection seems to be successful but a program crash can be observed. This is most likely because the started thread runs into an execution error, since no prior step reported any issues.

Lets look into it by adding some debug output. I added the following debug output after step 1,2 and 3:

```s
print("arg_address ", hex(arg_address))
input("press enter to continue")
```

Other variables were used as print output in the other steps.

Executing the modified code leads to the following output:
```s
C:\Users\IEUser\AppData\Local\Programs\Python\Python37\python.exe .\code_injection.py 308
<class 'bytes'>
h_process  0x1d8
press enter to continue
arg_address  -0x1bb90000
press enter to continue
```

So `arg_address`, which is the location of the memory page that has been allocated, looks wrong. Since this should be the starting address of the memory page it shoudln't be negative. This might just be the bug, that crashes the program or it simply is another issue that just affects how the starting address is displayed. Time to investigate some more!

## Investigating the page allocation issue

When looking for the newly created page in memory, it can be quickly found by searching for pages with read/write/execute permissions or `ERW` in x64dbg. Since this permission is uncommon for normal operations you can spot your page pretty easy through this. As long as you are not altering the protection status ([VirtualProtect function](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)).

![externally allocated page](/assets/images/pysh_inj/finding_virtualallocex.png)

You can see the selected page in the above image and how it has the `ERW` permissions. This permission stands out among other pages and it is uncommon for processes to rewrite instructions on memory pages that get executed. In general the loader sets everything up in advance and a legitimate process generally has no `ERW` pages. Seeing `Execute`, `Read` and `Write` permissions together is often an indicator for malicious activity. 

From the Memory Map we can gather that the allocation worked. The next step in verifying the corretness of the operations is transforming the address from signed to unsigned.

A simple way of converting from what seems to be a signed value is by adding 2^32 to it. If we do that for the printed value we get

```s
>>> hex(int(-0x1bb90000) + 2**32)
'0xe4470000'
```
Our Memory Map showed us that the newly allocated memory page starts at `0x 0253 E447 0000`.
The latter part does match but the address does seem to be cut off. 
__After a bit of digging I found some posts suggesting an undocumented change in ctypes. In order to get a correct return value, the return type of the method has to be changed.__

We could continue with the execution of the script but since we got a wrong address we will most likely run into a problem when our thread gets started at that location.

Switching over to the log in x64dbg shows the following:
![wrong address log](/assets/images/pysh_inj/exception_wrong_address.png)

By continuing the execution we ran into a problem at `0x007FFA2732FBFE`. This address is outside of the addressing space that the highest memory page in our program has (compare to memory map).

## Modifying the return type to get a 64 bit address

Changing the return type is actually really simple but comes with its own sets of problems.
The type can be changed by adding the following statement before the VirtualAllocEx Method
```py
kernel32.VirtualAllocEx.restype=c_void_p  # c_ulonglong
```
The return type can be either a pointer `c_void_p` or an unsigned longlong `u_longlong`. In the case of my win10 x64 dev box, both of these seem to be identical. 

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

Ok, so now we get the right address returned, which is `0x27703400000` (compare with x64dbg), but `WriteProcessMemory` fails because the function expects argument 2 to be an int and it is longer than size_int.

Fixing these issues is done by specifying the argument types.

## Modifying argument types

First we might need to import certain windows specific types via `ctypes`.
This can be done as such
```s
from ctypes.wintypes import HANDLE, LPCVOID, LPVOID, DWORD
SIZE_T = c_size_t
```
There are loads of unique Windows types available and in general it would be best to provide the right arguments to each function by looking it up and setting the argument types accordingly. Further information on this can be taken from the [ctypes](https://docs.python.org/3/library/ctypes.html) and [windows data types](https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types) documentation.

`SIZE_T` is provided as `c_size_t` by the `ctypes` library.

Now to the argument types, they have to be redefined. I haven't found a way to get the current types of one or all of the function arguments or a way to change only a single type. So you have to look up the expected types from the documentation of each function and set the types accordingly. 

Looking up the expected types led to the following declarations: 
```s
kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, c_size_t, POINTER(c_int)]
kernel32.CreateRemoteThread.argtypes = [HANDLE, LPVOID, SIZE_T, LPVOID, LPVOID, SIZE_T, LPVOID]
```

Alternatively you could use a correct "meta type". Since most types are simply pointers, you can use the general `c_void_p`. This way the amount of function lookups can be reduced.
```s
kernel32.WriteProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t, c_void_p]
kernel32.CreateRemoteThread.argtypes = [c_void_p, c_void_p, c_size_t, c_void_p, c_void_p, c_size_t, c_void_p]
```
`c_void_p` or `size_t` are pretty much all that is needed for most functions. 

## Running the injection script
Once everything is ported you can start the code and follow along with the changes on your allocated memory page by attaching x64dbg on the process that you inject into.

After the allocation took place you can inspect the page either by finding it by its `ERW` permissions or by the memory address printed on the console.

![](/assets/images/pysh_inj/finding_mem_final.png)

Right click the page and select follow in disassembler (or dump if you want to better compare your shellcode to the data on the page).

![](/assets/images/pysh_inj/shellcode_in_mem.png)

Continuing through the debug statements leads to the shellcode being executed and calc.exe getting started!