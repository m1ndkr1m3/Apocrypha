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
Apocrypha is a framework designed to create Windows shellcode using position independent C code and/or wrap shellcode in various formats.

Requirements (all available on PATH):
Go
Rust
MinGW
NASM

## Install 
Run ```go build``` from top level Apocrypha/ directory

## Usage
Example:
```
usage: Apocrypha [-h|--help] [-c|--config_yaml "<value>"]

Arguments:

  -h  --help         Print help information
  -c  --config_yaml  Filepath to the config file
```

## Config file
```yaml
---
mode: "shellcode"               # required ['shellcode','wrapper']
in_file: "_lib/mycustomcode.cpp"    # required - string - Path to input file
out_filename: "testing"    # required - string - give your file a name (no extension)
encrypt: "xor"                  # string - ["xor", ""] - this option can be used in both modes
debug: false                    # bool - true || false
shellcode_opts: 
  edr_hooks: "stomp"              # ['stomp'] or leave field empty
  edr_tool: "cylance"         # ['crowdstrike', 'cylance', 'sentinelone'] - required if edr_hooks is set
  hide_call_stack: false           # WIP - bool - true || false    
  polymorph: false              # bool - true || false
  antianalysis: false           # bool - true || false
wrapper_opts:
  format: ""                  # required in wrapper mode - string - options are the folder names under wrappers. Make sure you have a relevant meta.yml file in the directory as well

```
## Modes
Apocrypha operates in two modes: shellcode mode and wrapper mode. The shellcode mode will take position independant code (PIC) C (see shellcode mode below) and generate shellcode out of it. This shellcode can the be re-ran through Apocrypha in wrapper mode to be wrapped or used for other purposes (process injections, used in shellcode writes or persistence, etc...)

### Shellcode mode
Shellcode mode generates shellcode from C code written following PIC rules (see number 3 below). Point the in_file attribute to your custom PIC. You can use the _lib/mycustomcode.c as a template. It must follow 3 constraints:
1. The code must be in a function named "custom"
2. getFunctionPtr(dll_name, function_name) which dynamically resolves function addresses takes djb2 hashes of the strings for the module name and function name. You can use djb2.py to generate djb2 hashes for this. Walks PEB->LDR entries for all function and module resolution.
3. It must be position independent (duh). Go look at the credits section at codewhitesec's HandleKatz project. The PDF in there (PICYourMalware.pdf) has everything you need to know for how to write PIC C.

### Wrapper mode
Wrapper mode will take a raw shellcode file and wrap it in various formats. This raw shellcode can be something built from Apocrypha's shellcode mode or external tool shellcode (like a C2 implant's generated shellcode). When you select wrapper mode, you must select a format. The format choices are the names of all the directories inside the wrappers/ folder. The directory and filenames must all be lowercase.

#### Meta.yml in wrappers
Wrapper templates require a meta.yml file. The meta.yml does not have a defined structure. This allows for custom options on a per wrapper template basis. The only requirements are that it contains the following 4 attributes:

```yaml
---
detected: false  # bool - required
template_filename: "go_dll.go.template" # string - required - should follow the format: <folder_name>.<filetype>.template
language: "go" # string - required
filetype: "dll" # string - required
```

### Other Options
In shellcode mode: 
 - the polymorph option uses the SpiderPIC project to polymorph the PIC code. I've found that some EDRs instantly hate this at a static analysis level even when set to low. For now, I generally leave this off. Need to look into this more.
 - the antianalysis option contains several anti-sandbox checks that get prepended to run prior to the custom shellcode. I recommend commenting out what you do and do not want or adding your own. In the future, this will get broken out into a more end-user friendly, configurable state, probably a yaml file or something.
 - the hidecallstack option - WIP - currently only supports functions with 6 arguments. Is from Paranoid Ninja research - https://0xdarkvortex.dev/hiding-in-plainsight/. Will update to use a non-blogged about function in the future. To use this callstack evasion in your custom code, follow the templated example in _lib/callstack_evasion_example.cpp

## Credits
- Implementation of PIC and SpiderPIC by https://github.com/codewhitesec/ and all their credit section folks.
- https://0xdarkvortex.dev/