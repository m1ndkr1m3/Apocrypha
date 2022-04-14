<div align="center">
<pre>
░█████╗░██████╗░░█████╗░░█████╗░██████╗░██╗░░░██╗██████╗░██╗░░██╗░█████╗░
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗██║░░██║██╔══██╗
███████║██████╔╝██║░░██║██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝███████║███████║
██╔══██║██╔═══╝░██║░░██║██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░██╔══██║██╔══██║
██║░░██║██║░░░░░╚█████╔╝╚█████╔╝██║░░██║░░░██║░░░██║░░░░░██║░░██║██║░░██║
╚═╝░░╚═╝╚═╝░░░░░░╚════╝░░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚═╝
      __...--~~~~~-._   _.-~~~~~--...__
     //               `V'               \\ 
   //                 |                 \\ 
  //__...--~~~~~~-._  |  _.-~~~~~~--...__\\ 
 //__.....----~~~~._\ | /_.~~~~----.....__\\
====================\\|//====================
\`---`
</pre>
</div>
<pre>
█░█░█
▀▄▀▄▀ith the Lich defeated and the kingdom saved, you make your way to leave the crumbling, decrepit mausoleum 
to claim your rightly-earned fortune and fame. But as you turn around, something silver and shiny catches 
your eye lying in the tattered robes that previously enshrouded your ancient foe. A tome engraved with strange 
sigils on its face! This should be worth something to the Royal Wizards once you get back to the capital. 
You begin the long trek back from deep within the earth, passing dusty bones and long-forgotten memorials. 
Seconds turn to minutes. Minutes turn to hours. How could you be lost? Isn't that the same corridor you 
just came from? And you can't shake the uneasy feeling that you're hearing whispers. Unintelligble mumblings 
that don't sound as if they are coming from any particular direction, but as if they are coming from inside 
your own head. What about these pulsing symbols on the walls... how come you never noticed them before? 
They move in unnatural, slithering motions that seem to all interconnect into one another. Is it just you 
or do they resemble the same markings on the book you recovered from the Lich? Trying to focus on one for too 
long causes a searing pain to blossom inside your skull, but at the same time it's comforting. Welcoming almost. 
Maybe you should sit down and read some more.
Just for a little bit longer...
</pre>

## About
Apocrypha is a Windows malware generation framework designed to generate shellcode using position independent C code and wrap it in various formats. It provides a series of anti-analysis and obfuscation modules that can be chosen from for all your EDR bypass needs.

Requirements:
Python 3.5+
MinGW
NASM

Apocrypha uses series of python scripts which template out and compile C and assembly code for Windows as separate subprocess calls. While not the most efficient, this makes it easy for you to rip apart Apocrypha.py and integrate each step into a CICD pipeline if you desire.

## Usage
Example:
```
usage: apocrypha.py [-h] [-u [{pathofsteel}]] -w [{dll,exe,none}] -f FILENAME [-d] [-e [{xor}]] [-c CUSTOM]

Apocrypha flags:
- Anti-Analysis:
    '-u','--unhook'
         Which technique do you want to use to bypass EDR ntdll trampolines?
          - pathofsteel - Mapping a KnownDLL section object like ntdll in a process's virtual memory twice 
            is sus anyways, so smash over the top of the existing hooked functions' opcodes to restore the 
            original syscall instructions. This technique parses the syscall ids out of the ntdll.dll
            in src/ntdll.dll so make sure to replace it with your target's version as syscall ids can change.
          - pathofshadow - COMING SOON
          - pathofspirit - COMING SOON
          
    - MORE FLAGS COMING SOON

-w [{dll,exe,none}], --wrapper [{dll,exe,none}]
    What type of loader do you want the shellcode wrapped in?
-f FILENAME, --filename FILENAME
    What would you like the final file called
-d, --debug           
    if set, then don't delete any files in output/
-e [{xor}], --encrypt [{xor}]
    What type of encryption algorithm do you want to use on the shellcode? Currently only multibyte xor
    - MORE TO COME SOON
-c CUSTOM, --custom CUSTOM
    filepath of the custom PIC file you want to include in shellcode
```
## Custom Flag (-c --custom)
Point this filepath to your custom PIC. You can use the mycustomcode.c as a template. It must follow 3 constraints:
1. The code must be in a function named "custom"
2. getFunctionPtr(dll_name, function_name) which dynamically resolves function addresses takes djb2 hashes of the strings for the module name (unicode string) and function name (ANSI string). You can use djb2.py to generate djb2 hashes for this.
3. It must be position independent (duh). Go look at the credits section at codewhitesec's HandleKatz project. The PDF in there (PICYourMalware.pdf) has everything you need to know.
## Credits
- Implementation of PIC by https://github.com/codewhitesec/HandleKatz and all their relevant credit section folks.

