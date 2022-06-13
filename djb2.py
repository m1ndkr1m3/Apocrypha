#!/usr/bin/python3
import sys

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

if sys.argv[1] == 'a':
    print(hex(hash_djb2(sys.argv[2].encode('ascii','ignore'))))
elif sys.argv[1] == 'u':
    print(hex(unicode_hash_djb2(sys.argv[2])))
else:
    print("Unknown encoding... the only options are 'a' for ASCII or 'u' for unicode\n Syntax: python3 djb2.py u kernel32.dll")
