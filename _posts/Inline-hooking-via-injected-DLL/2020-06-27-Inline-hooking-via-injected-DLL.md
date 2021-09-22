---
layout: post
title: "Inline hooking via injected DLL"
date: 2020-06-27 01:00 +0100
modified: 2021-08-03 16:00:00 +0100
description: Placing inline hooks on a chosen WinAPI function through an injected DLL.
tag: 
  - windows
  - WinAPI hooks
  - dll injection
--- 

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/_posts/Inline-hooking-via-injected-DLL/tim-marshall-iBY2XCgPwDA-unsplash.jpg">
<figcaption>image by tim marshall</figcaption>
</figure>

## intro

I've recently completed reenz0h's / sektor7 `Red Team Operator: Essentials` course and became interested in hooking techniques prior to it. So with some more knowledge on my hands I wanted to implement some kind of inline hook. 

If you look at the basics, there are essentially two common hooking techniques - `IAT` and `inline hooks`. IAT hooks modify a pointer from the import address table. The hook is done by replacing the legitimate reference to a WinAPI function with a pointer to a substitute function. 
On first thought, this is the easier of the two approaches since it doesn't require modifications to the existing code. The reference can be to any valid memory address and you could even chain the substitute and the original function by keeping track of the original reference that got replaced.

For more details on IAT hooks and a nice graph see [here](https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking)

This post is about inline hooks and modifying existing functions though and that is what we are going to do. 

The code used throughout this post can be found [here](https://github.com/mncmb/shellcode_runner/tree/master/inline_hooking).


## overview

This basic exercise in inline hooking consists of the following steps:
- first we pick a simple windows API we can use as a practice target and write a small program around it
- then we write an injector that can load a dll into the process and executes it (starting dllmain on attach).
- finally the dll is developed that performs the hook on the chosen API function

## setup 
A Windows VM with some development tools is needed. I recommend installing chocolatey and at least the following packages:

```
choco install -y 7zip firefox hxd vscode visualstudio2019-workload-nativedesktop x64dbg.portable git
```
If you prefer a GUI you might also install `visualstudio2019community`. 

The build tools that are invoked in the accompanying builder bat scripts are available via the `native developer tool` command prompt / environment. You can find it by pressing start/ win-key and searching for it. I recommend pinning it to the task menu.

### choosing a windows API function
When your first thought is about picking some networking APIs, hooking them and intercepting and possibly redirecting packets containing a magic header to build a super stealthy user land trojan then you might want to reconsider.
I have considerably down sized this project during it's course because I wanted to finish the primary task (inline hooking) instead of starting a longer dive into the necessary research. While that intro statement certainly would be a cool project, time constraints are real and there is just so much to learn and an abundance of other interesting topics so that I chose to keep the scope small.

This led me to selecting a very simple API that was a perfect fit for getting acquainted with the subject. 

May I present to you [OutputDebugStringW](https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-outputdebugstringw).
If you look into Malware Reversing (or the other side of the fence) you might have heard of this function as a simple way of checking for the presence of a debugger - atleast prior to Windows Vista as this [checkpoint article ](https://anti-debug.checkpoint.com/techniques/interactive.html#outputdebugstring) on the subject points out.
For this exercise it is a perfect fit. Normally it would print it's output to a debugger but not to the standard output. We will modify the function so that it prints to stdout by hooking it and intercepting the input argument.


#### test program
The test program we are going to use is the following:

```c
#include <windows.h>
#include <stdio.h>

void main(){
    char supersecret[100] = "This is my super secret supersecret.\0";
    printf("press enter for first call to OutputDebugStringA...");
    getchar();
    
    OutputDebugStringA(supersecret);
    
    printf("Inject dll now and press enter for second call to OutputDebugStringA ....");
    getchar();
    
    OutputDebugStringA(supersecret);
}
```
It contains a secret string which gets printed via OutputDebugString and is therefor only visible if a debugger is attached. 
In order to easily step through the program, we use getchar() as a marker and cheap pseudo breakpoint.

### the injector
The injector is based on RTO course material with some slight adjustments. First, it will loop through all processes and look for a process with the specified name. Keep in mind, that the full name, including extension, is required. 

The other adjustment is regarding the injected DLL which can be submitted via relative path/ DLL-name in the case that the DLL is in the current working directory.

Other than that, the injection works as follows:
```c
bufferEx = VirtualAllocEx(pHandle, NULL, strlen(dll), MEM_COMMIT, PAGE_READWRITE);	
	
WriteProcessMemory(pHandle, bufferEx, (LPVOID) dll, strlen(dll), NULL);

CreateRemoteThread(pHandle, NULL, 0, pLoadLibrary, bufferEx, 0, NULL);
```
A new memory page with the `READWRITE` permissions gets allocated in the remote process pointed to by `pHandle`. This remote process is the process the injector is injecting into. 
The page has to be at least of the size `strlen(dll)`, which is the length of the string that holds the full path to the DLL that is being injected.

In the next function call, the full path to the injected DLL is written to the newly allocated page.

Afterwards, a new thread is started. This thread calls the LoadLibrary function with a pointer to the full DLL path as it's argument. The LoadLibrary function was dynamically resolved prior to the above process, which is why it is submitted as an argument to the CreateRemoteThread function (`pLoadLibrary`). 

So to sum up the injection process, a new thread is started with the instruction pointer set to the `LoadLibrary` function and the DLL name as an argument to the function.

### hook DLL

For the hook, the following needs to be done:
1. the address of the to-be-hooked function has to be resolved
2. the replacing function has to be defined
3. a redirection to the replacing function has to be installed on the to-be-hooked function

__Resolving__ the to-be-hooked function can be resolved via `GetProcAddress`:
```c
// get Address of OutputDebugStringA function
funcAdress = (void*)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "OutputDebugStringA");
```

As for the __replacing__ function, it is simply defined in the DLL and prints the first argument via `printf`.
```c
void __stdcall myOutputDebugStringA(LPCSTR lpOutputString) {
    printf(lpOutputString);
}
```

The __redirection__ is done by patching the first instructions of the `OutputDebugString` function.
```c
memcpy_s(patch, 1, "\x48", 1); // mov
memcpy_s(patch+1, 1, "\xb8", 1); // rax,
memcpy_s(patch+2, 8, &HookOutputDebugStringA, 8); // 64bit value
memcpy_s(patch+10, 1, "\x50", 1); // push rax
memcpy_s(patch+11, 1, "\xc3",1); // ret
```
The patch puts the location of the replacing function (_HookOutputDebugStringA_) in register RAX, pushes the contents of RAX on the stack and then essentially performs a jump to the address pointed to by RAX via `ret` instruction. 

The patch was adapted from the [windows API hooking](https://ired.team/offensive-security/code-injection-process-injection/how-to-hook-windows-api-using-c++) example to 64bit.
The main difference between 32bit and 64bit patches lies within jumps to code locations that should get executed. The jump instruction from the original code only allows to specify 32bit values as a relative address to jump to. This means the different code locations might only be 2GB apart. So in order to jump to code that is further apart, other instructions have to be used. 

A pretty neat discussion of different `trampoline` instruction sequences can be found at the [ragestorm blog](https://www.ragestorm.net/blogs/?p=107) and [this stackoverflow question](https://stackoverflow.com/questions/16917643/how-to-push-a-64bit-int-in-nasm).

As for arguments, the first is passed in `ECX`. `ECX` is the first argument for all common windows calling conventions, be it 32 or 64 bit. See `ECX` contents in the following image being __secret 123412__.

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/_posts/Inline-hooking-via-injected-DLL/failedSimpleProg_OutputDebugString_JumpTable.png">
<figcaption>ECX contents prior to OutputDebugString call</figcaption>
</figure>


#### debugging injected DLLs

Because it is nice to debug code in one way or another, I looked up different debugging options for injected DLLs. Two things came up, first the nice and clean way and good old dirty printf debugging.   
Obviously I picked the latter.  
Nonetheless having other options is always nice so I will keep information on both options here.

##### Visual Studio injected DLL debugging
It is actually pretty easy to debug an injected DLL with Visual Studio. You just need to open a DLL project, build your DLL and attach VS to the process you want to inject the DLL into. Then comes the injection and thats it.

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/_posts/Inline-hooking-via-injected-DLL/dll_debug_attach_to_process.png">
<figcaption>Visualstudio debugger attach to process</figcaption>
</figure>

For more information on this see ([Game Hacking forums](https://guidedhacking.com/threads/debugging-dll-for-internal-hack.7760/)).

##### print Debugging of DLL code
The printf debugging works by creating a console window and directing standard input, output and error towards it. This comes really handy since It allows to output debug information in an extra window. Keep in mind though that this does not redirect output to an already existing window but creates one of it's own. So if you want to use printf from a DLL to generate output among that of the acutal executable this is not the way (maybe [GetStdHandle](https://docs.microsoft.com/en-us/windows/console/getstdhandle)can help though?).

In order to get the output of the DLL, the following code has to be included:

```c
    AllocConsole();
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

```

The functions are pretty self explanatory by name or input. Now we can debug and easily analyze the exe or dll with x64dbg and `printf` and `getchar`.

The code was taken from this post [printf for dll debugging](https://www.codeproject.com/Tips/227809/Good-Old-Dirty-printf-Debugging-in-a-Non-console-C).


#### compiling the DLL
As for compiling the DLL the following flags are used for cl: `cl.exe /O2 /D_USRDLL /D_WINDLL hook.c /MT /link /DLL /OUT:Hook.dll`.
As can be gathered from the [microsoft documentation](https://docs.microsoft.com/en-us/cpp/build/reference/compiler-options?view=msvc-160)on [compiler options](https://docs.microsoft.com/en-us/cpp/build/reference/compiler-options-listed-alphabetically?view=msvc-160), `O2` creates fast code, `D_USERDLL`, `/MT` creates a multi threaded executable and includes LIBCMT.lib, `/link` passes the options following the flag to the linker and `/DLL` is the linker option to create a DLL. The `_USRDLL` and `_WINDLL` parameters seem to be necessary [preprocessor define options](https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-6.0/aa235516(v=vs.60)?redirectedfrom=MSDN)

Alternatively, as described [here](https://stackoverflow.com/questions/1130479/how-to-build-a-dll-from-the-command-line-in-windows-using-msvc), the same can be achieved with just `cl /LD <files>`.

## Wrapping up

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/_posts/Inline-hooking-via-injected-DLL/hook.gif">
<figcaption>Applying the hook</figcaption>
</figure>

As you can see in the above gif, executing the program in powershell doesn't give any output. After hooking the function and redirecting the `OutputDebugString` arg into printf, the secret is revealed.