import argparse

parser = argparse.ArgumentParser(description='Generate files for entry point trampoline')
parser.add_argument('--filename', required=True, help='name of file')

args = parser.parse_args()

with open("./output/"+args.filename+".bin", "rb") as f:
    data = f.read()

shellcode = "{"
for b in data:
    shellcode += format(b, '#04x')+","

#strip comma from last byte
shellcode = shellcode[:-1]
shellcode += "}"

with open("./output/"+args.filename+".hex", 'w') as g:
    g.write(shellcode)