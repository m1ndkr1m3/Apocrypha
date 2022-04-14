#!/usr/bin/python3
import argparse
from fileinput import filename
import subprocess
from sys import modules

def errorHandler(message):
    print(message)
    quit() 

def compile_entry_patch():
    subprocess.run("nasm -f win64 ./output/adjuststack.asm -o ./output/adjuststack.o", shell=True, check=True)

    return 0

def copy_custom_code(filepath):
    subprocess.run("cp "+filepath+" ./output/custom.c", shell=True, check=True)

    return 0
def dump_syscalls():
    subprocess.run("python3 ./src/modules/dump_syscalls.py -n ./src/ntdll.dll -o ./output/syscalls.csv -s", shell=True, check=True)
    return 0

def build_module_templates(modules_delimthis, filename):
    subprocess.run("cp ./src/APIresolve.h ./output/ && cp ./src/ntdll.h ./output/", shell=True, check=True)
    objs_to_link = ""
    #first compile each module into an shared object
    for module in modules_delimthis.split(" "):
        objs_to_link += "./output/"+module+".o "
        compiler_cmdline = "x86_64-w64-mingw32-gcc ./output/"+module+".c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ./output/"+module+".o -Wl,-T./output/linker.ld,--no-seh"
        subprocess.run(compiler_cmdline, shell=True, check=True)
    #now link all the object files together
    #trim last space from objs_to_link
    objs_to_link = objs_to_link[:-1]
    subprocess.run("x86_64-w64-mingw32-ld -s "+objs_to_link+" ./output/adjuststack.o -o ./output/PIC.exe", shell=True, check=True)
    #dump .text section to file
    subprocess.run("objcopy -j .text -O binary ./output/PIC.exe ./output/"+filename+".bin", shell=True, check=True)

    return 0

def create_unhook_template(technique):
    if technique == "pathofsteel":
        subprocess.run("python3 ./src/modules/pathofsteel.py", shell=True, check=True)
        
    return 0

def encrypt_shellcode(algorithm, filename):
    subprocess.run("python3 ./src/modules/"+algorithm+"_encrypt.py --filename "+filename, shell=True, check=True)
    return 0
        
def create_wrapper(fileformat, filename, encrypt):
    py_arguments = "--filename "+filename
    if encrypt:
        py_arguments += " --encrypt "+encrypt

    if fileformat == "dll":
        subprocess.run("python3 ./src/modules/dll_template.py "+py_arguments, shell=True, check=True)
        subprocess.run("x86_64-w64-mingw32-gcc -Wall -shared ./output/"+filename+".c -o ./output/"+filename+".dll", shell=True, check=True)
    if fileformat == "exe":
        subprocess.run("python3 ./src/modules/exe_template.py "+py_arguments, shell=True, check=True)
        subprocess.run("x86_64-w64-mingw32-gcc -Wall ./output/"+filename+".c -o ./output/"+filename+".exe", shell=True, check=True)
    if fileformat == "none":
        subprocess.run("python3 ./src/modules/hex_shellcode.py "+py_arguments, shell=True, check=True)

    return 0

def create_entry_patch(arg_namespace):
    modules_for_entrypatch = ""
    for key,value in vars(arg_namespace).items():
        if key == "unhook" and value:
            modules_for_entrypatch += value+" "
    if arg_namespace.custom:
        modules_for_entrypatch += "custom "

    if not modules_for_entrypatch:
        errorHandler("No PIC module to build, please use at least one module")

    #remove last comma from string
    modules_for_entrypatch = modules_for_entrypatch[:-1]
    subprocess.run("python3 ./src/modules/create_entry_patch.py --modules "+modules_for_entrypatch, shell=True, check=True)

    return 0, modules_for_entrypatch

def main():
    logo = """

    ░█████╗░██████╗░░█████╗░░█████╗░██████╗░██╗░░░██╗██████╗░██╗░░██╗░█████╗░
    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗╚██╗░██╔╝██╔══██╗██║░░██║██╔══██╗
    ███████║██████╔╝██║░░██║██║░░╚═╝██████╔╝░╚████╔╝░██████╔╝███████║███████║
    ██╔══██║██╔═══╝░██║░░██║██║░░██╗██╔══██╗░░╚██╔╝░░██╔═══╝░██╔══██║██╔══██║
    ██║░░██║██║░░░░░╚█████╔╝╚█████╔╝██║░░██║░░░██║░░░██║░░░░░██║░░██║██║░░██║
    ╚═╝░░╚═╝╚═╝░░░░░░╚════╝░░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚═╝

    """
    #reminder: new arguments that don't relate to modules but to meta (e.g. filename, wrapper, encrypt) do NOT need to be added to the conditional in create_entry_patch
    parser = argparse.ArgumentParser(description=logo)
    parser.add_argument('-u','--unhook', nargs='?', required=False, choices=['pathofsteel'], help='Which technique do you choose for bypassing edr trampolines in ntdll?')
    parser.add_argument('-w','--wrapper', nargs='?', required=True, choices=['dll','exe','none'], help='What type of loader do you want the shellcode wrapped in?')
    parser.add_argument('-f','--filename', required=True, help='What would you like the final file called')
    parser.add_argument('-d','--debug', required=False, action='store_true', help="if set, then don't delete any files in output")
    parser.add_argument('-e','--encrypt', required=False, nargs='?', choices=['xor'], help='What type of encryption algorithm do you want to use on the shellcode?')
    parser.add_argument('-c','--custom', required=False, help='filepath of the custom PIC C file you want to include in shellcode')
    args = parser.parse_args()

    result,modules_string = create_entry_patch(args)
    if result:
        errorHandler("Generating entry patch template failed")

    if compile_entry_patch():
        errorHandler("Compiling adjuststack.asm failed")

    if args.unhook:
        if args.unhook == 'pathofsteel':
            if dump_syscalls():
                errorHandler("Generating syscalls.csv failed")
        if create_unhook_template(args.unhook):
           errorHandler("Generating unhook template failed")
    
    if args.custom:
        if copy_custom_code(args.custom):
            errorHandler("Copying custom PIC C code from "+args.custom+" failed")
    
    if build_module_templates(modules_string, args.filename):
        errorHandler("Compiling files and linking objects failed")

    if args.encrypt:
        if encrypt_shellcode(args.encrypt, args.filename):
            errorHandler("Compiling files and linking objects failed")

    if args.wrapper:
        if create_wrapper(args.wrapper, args.filename, args.encrypt):
            errorHandler("Generating wrapper template failed")

    if not args.debug:
        if args.wrapper == 'none':
            extension = 'hex'
        else:
            extension = args.wrapper

        subprocess.run("find ./output/ -type f ! -name '"+args.filename+"."+extension+"' ! -name '.gitignore' -delete", shell=True, check=True)

       
if __name__ == "__main__":
    main()