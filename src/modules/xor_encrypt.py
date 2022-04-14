#!/usr/bin/python3
import os
import argparse

parser = argparse.ArgumentParser(description='encrypt PIC bin file')
parser.add_argument('--filename', required=True, help='name of PIC bin file')

args = parser.parse_args()

size = 8
key = os.urandom(size)
with open("./output/encrypt.key", 'wb') as f:
   f.write(key)


with open("./output/"+args.filename+".bin", "rb") as g:
    data = g.read()

ciphertext = bytearray(len(data))
count = 0
for i, b in enumerate(data):
    ciphertext[i] = b ^ key[count]
    if count == size - 1:
        count = 0
    else:
        count += 1

with open("./output/"+args.filename+".bin", "wb") as h:
    h.write(ciphertext)

