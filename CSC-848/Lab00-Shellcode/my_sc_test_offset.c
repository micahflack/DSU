#include <windows.h>
#include <stdio.h> 



char shellcode[] = "";


int main(int argc, char **argv) {



	HINSTANCE hInstLib = LoadLibrary(TEXT("user32.dll"));
	
	int i = 0, len = 0, target_addy = 0, offset = 0x0;

	void*stage = VirtualAlloc(0, 0x1000, 0x1000,0x40 );

	printf("[*] Memory allocated: 0x%08x\n", stage);

	len = sizeof(shellcode);

	printf("[*] Size of Shellcode: %08x\n", len);

	memmove(stage, shellcode, 0x1000);

	printf("[*] Shellcode copied\n");

	target_addy = (char*)stage + offset;

	printf("[*] Adjusting offset: 0x%08x\n", target_addy);
	
	__asm {
		int 3
		mov eax, target_addy
		jmp eax
	}
}