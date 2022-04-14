#!/usr/bin/python
import sys
import pefile
import argparse

parser = argparse.ArgumentParser(description='Extract syscall IDs or all 8 overwrite bytes from ntdll.dll')
parser.add_argument('-n','--ntdll', default='./ntdll.dll', help='If no arguments are given it assumes ntdll.dll is in local directory.')
parser.add_argument('-o','--outfile', default='syscalls.csv', help='Output file name')
parser.add_argument('-s', '--stomp', action='store_true', help='Return all 8 syscall overwrite bytes')
args = parser.parse_args()

# args
ntdll=args.ntdll
out_file=args.outfile
stomp=False
if args.stomp:
    stomp=True

pe = pefile.PE(ntdll)

syscalls=[]
hooked_functions = [
    "NtProtectVirtualMemory",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "NtSuspendThread",
    "NtResumeThread",
    "NtSetContextThread",
    "NtQueueApcThreadEx",
    "NtMapViewOfSectionEx",
    "NtGetContextThread",
    "NtAllocateVirtualMemoryEx",
    "NtSetInformationProcess",
    "NtMapViewOfSection",
    "NtDeviceIoControlFile",
    "NtAllocateVirtualMemory",
    "NtQueryInformationThread",
    "NtSetInformationThread",
    "NtQueueApcThread",
    "NtUnmapViewOfSection",
    "NtUnmapViewOfSectionEx"
]
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    # Only get functions that start 'Nt'
    try:
        if not (exp.name).startswith(b'Nt'):
            continue
    except:
        continue
    
    # Get bytes
    sysBytes = pe.get_data(exp.address, 8)

    # Syscalls start '\xb8'
    if not sysBytes.startswith(b'\x4c'):
        continue

    # Convert bytes to string w/out '\x'
    finStr=''.join('{:02x}'.format(b) for b in sysBytes)
    
    # If 'stomp' not argument given, return only the syscall bytes
    if not stomp:
        finStr=finStr[8:12]
        if finStr != '0000':
            finStr=finStr.rstrip('0') 
        else:
            finStr = '00'
    
    # Append finStr to 'syscalls' list
    if (exp.name).decode('utf-8') in hooked_functions:
        syscalls.append(((exp.name).decode('utf-8'), finStr))

with open(out_file, 'w') as fout:
    for s in syscalls:
        fout.write(s[0] + ',' + s[1] + '\n')
