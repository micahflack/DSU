// Use this to test your shellcode
char shellcode[]  = "";

int main(int argc, char **argv) {

	int (*func)();

	func = (int (*)()) shellcode;

	(int)(*func)();
}
