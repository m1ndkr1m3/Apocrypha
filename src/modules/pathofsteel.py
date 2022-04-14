#!/usr/bin/python3
import struct
from string import Template

def unicode_hash_djb2(s):                                                                                                                                
    hash = 5381
    for x in s:
        hash = (( hash << 5) + hash) + ord(x)
    return hash & 0xFFFFFFFF

def hash_djb2(s):
    hash = 5381
    for x in s:
        hash = (( hash << 5) + hash) + x
    return hash & 0xFFFFFFFF

with open("./output/syscalls.csv", 'r') as f:
    num_of_lines = str(len(f.readlines()))


# The following code's ugly but basically it creates each objects for each line in the parsed out syscalls file in this struct:
# typedef struct {
#    int hashed_name;                       //djb2 hashed c string of the function name (function names are ANSI in the exports name table
#                                           // unlike like DLL names in ldr entries which are unicode)
#    unsigned char patch_bytes[8];          // byte array of the original opcodes we are going to patch over the edr trampoline
# } HookedFunction;

target_funcs = ""        
with open("./output/syscalls.csv", 'r') as f:
    for line in f:
        items = line.strip().split(",")
        name_hash = hex(hash_djb2(items[0].encode('ascii','ignore')))
        structLine = "\t{"+str(name_hash)+", {"
        for index,c in enumerate(items[1].strip()):
            #grab 2 bytes at a time
            if (index % 2) != 0 and index != 0:
                structLine += "0x"+items[1][index-1]+items[1][index]+","
            #if its the last entry we don't want to append a comma
            if index+1 == len(items[1]):
                structLine = structLine[:-1]

        structLine += "}},\n"
        target_funcs += structLine
 #if its the last line we don't want to append a comma and newline
target_funcs = target_funcs[:-2]

with open("./src/templates/pathofsteel.c.template", 'r') as f:
    t = Template(f.read())

with open("./output/pathofsteel.c", 'w') as g:
    g.write(t.safe_substitute({'num':num_of_lines,'init_objs': target_funcs}))
