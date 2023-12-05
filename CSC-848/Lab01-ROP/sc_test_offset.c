#include <windows.h>

char shellcode[] = "";

int main(int argc, char **argv) {

	int i = 0, len = 0, target_addy = 0, offset = 0x0;

	void*stage = VirtualAlloc(0, 0x1000, 0x1000,0x40 );

	len = sizeof(shellcode);

	memmove(stage, shellcode, 0x1000);

	target_addy = (char*)stage + offset;
	
	__asm {
		int 3
		mov eax, target_addy
		jmp eax
	}
}