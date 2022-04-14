#!/usr/bin/python3
from string import Template
import argparse
from xor_string import xor_function

parser = argparse.ArgumentParser(description='Generate template for exe wrapper')
parser.add_argument('--filename', required=True, help='name of file')
parser.add_argument('--encrypt', nargs='?', choices=['xor'], help='What type of encryption algorithm was used on the shellcode?')

args = parser.parse_args()

def xor_template(xor_function):
    #get key
    with open("./output/encrypt.key", "rb") as f:
        data = f.read()

    key = "unsigned char key[] = {"
    for b in data:
        key += format(b, '#04x')+","

    #strip comma from last byte
    key = key[:-1]
    key += "};\n"

    xor_function = key + xor_function

    return xor_function


if args.encrypt:
    if args.encrypt == "xor":
        crypto_string = xor_template(xor_function)
else:
    crypto_string = "\n"


with open("./output/"+args.filename+".bin", "rb") as f:
    data = f.read()

shellcode = ""
for b in data:
    shellcode += format(b, '#04x')+","

#strip comma from last byte
shellcode = shellcode[:-1]

with open("./src/templates/exe_template.c.template", 'r') as f:
    t = Template(f.read())

with open("./output/"+args.filename+".c", 'w') as g:
    g.write(t.safe_substitute({'shellcode': shellcode, 'crypto': crypto_string}))
