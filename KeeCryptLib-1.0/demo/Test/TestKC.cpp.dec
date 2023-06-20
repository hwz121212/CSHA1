#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#define KCF_NODECL
#include "KeeCryptLib.h"

int main(int argc, char *argv[])
{
	HINSTANCE hLib;
	LPKCENCRYPTFILE lpKcEncryptFile;
	LPKCSELFTEST lpKcSelfTest;
	DWORD dw;

	hLib = LoadLibrary("KeeCryptLib.dll");
	if(hLib == NULL) { printf("Error: Cannot load KeeCrypt.dll library!\n"); return 1; }
	
	lpKcEncryptFile = (LPKCENCRYPTFILE)GetProcAddress(hLib, "KcEncryptFile");
	if(lpKcEncryptFile == NULL) { printf("Error: Encryption function not found!\n"); return 2; }

	lpKcSelfTest = (LPKCSELFTEST)GetProcAddress(hLib, "KcSelfTest");
	if(lpKcSelfTest == NULL) { printf("Error: Self-test function not found!\n"); return 3; }

	dw = lpKcEncryptFile(TRUE, "TestKC.cpp", "TestKC.cpp.enc", "TheKey");
	if(dw == 0) printf("Encryption TestKC.cpp -> TestKC.cpp.enc successful.\n");
	else printf("Encryption TestKC.cpp -> TestKC.cpp.enc failed (%u)!\n", dw);

	dw = lpKcEncryptFile(FALSE, "TestKC.cpp.enc", "TestKC.cpp.dec", "TheKey");
	if(dw == 0) printf("Decryption TestKC.cpp.enc -> TestKC.cpp.dec successful.\n");
	else printf("Encryption TestKC.cpp.enc -> TestKC.cpp.dec failed (%u)!\n", dw);
	
	dw = lpKcEncryptFile(FALSE, "TestKC.cpp.enc", "TestKC.cpp.dec.inv", "TheKeyEx");
	if(dw == 0) printf("Decryption TestKC.cpp.enc -> TestKC.cpp.dec.inv successful (BUG!)!\n");
	else printf("Decryption TestKC.cpp.enc -> TestKC.cpp.dec.inv failed (%u, it should fail).\n", dw);

	dw = lpKcSelfTest();
	if(dw != 0)
	{
		printf("Self-test failed:");
		if(dw & KCTESTERR_CIPHER) printf(" Cipher");
		if(dw & KCTESTERR_HASH) printf(" Hash");
		printf("\n");
	}

	FreeLibrary(hLib); hLib = NULL;

	return 0;
}
