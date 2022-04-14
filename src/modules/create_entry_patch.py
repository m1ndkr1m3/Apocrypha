#!/usr/bin/python3
from string import Template
import argparse

parser = argparse.ArgumentParser(description='Generate files for entry point trampoline')
parser.add_argument('--modules', nargs='+', required=True, help='names of each module separated by a space')

args = parser.parse_args()

linker_sections = ""
asm_externobjects = ""
asm_callstatements = ""
for index, module in enumerate(args.modules):
    linker_sections += "*(.text."+module+")\n"
    asm_externobjects += "extern "+module+"\n"
    asm_callstatements += "call "+module+"\n"   
    #if its the last item remove the new line
    if index+1 == len(args.modules):
        linker_sections = linker_sections[:-1]
        asm_externobjects = asm_externobjects[:-1]
        asm_callstatements = asm_callstatements[:-1]

with open("./src/templates/linker.ld.template", 'r') as f:
    t = Template(f.read())

with open("./output/linker.ld", 'w') as g:
    g.write(t.safe_substitute({'pic_sections': linker_sections}))

with open("./src/templates/adjuststack.asm.template", 'r') as f:
    t = Template(f.read())

with open("./output/adjuststack.asm", 'w') as g:
    g.write(t.safe_substitute({'external_objects': asm_externobjects, 'call_statements': asm_callstatements}))
