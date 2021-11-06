#include "HeavensGate.h"

int main() {
	//MessageBoxA(NULL, "test", "test", MB_OK);
	//CreateFileA("test2.txt", GENERIC_READ, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	uint64_t kernel32 = GetKernel32();
	uint64_t user32 = LoadLibrary64("user32.dll");
	uint64_t CreateFile64 = GetProcAddress64(kernel32, "CreateFileA");
	uint64_t WriteFile64 = GetProcAddress64(kernel32, "WriteFile");
	uint64_t ReadFile64 = GetProcAddress64(kernel32, "ReadFile");
	uint64_t CloseHandle64 = GetProcAddress64(kernel32, "CloseHandle");
	char path[MAX_PATH];            
	char hacked[] = "Hacked by 34r7hm4n";
	uint64_t hFile;
	char buffer[100] = { 0 };

	GetCurrentDirectoryA(MAX_PATH, path);
	lstrcatA(path, "\\test.txt");
	hFile = X64Call(CreateFile64, 7, (uint64_t)path, (uint64_t)GENERIC_WRITE, (uint64_t)NULL, (uint64_t)NULL, (uint64_t)CREATE_NEW, (uint64_t)FILE_ATTRIBUTE_NORMAL, (uint64_t)NULL);
	X64Call(CloseHandle64, 1, hFile);
	hFile = X64Call(CreateFile64, 7, (uint64_t)path, (uint64_t)GENERIC_WRITE, (uint64_t)NULL, (uint64_t)NULL, (uint64_t)OPEN_EXISTING, (uint64_t)FILE_ATTRIBUTE_NORMAL, (uint64_t)NULL);
	X64Call(WriteFile64, 5, (uint64_t)hFile, (uint64_t)hacked, (uint64_t)lstrlenA(hacked), (uint64_t)NULL, (uint64_t)NULL);
	X64Call(CloseHandle64, 1, hFile);
	hFile = X64Call(CreateFile64, 7, (uint64_t)path, (uint64_t)GENERIC_READ, (uint64_t)NULL, (uint64_t)NULL, (uint64_t)OPEN_EXISTING, (uint64_t)FILE_ATTRIBUTE_NORMAL, (uint64_t)NULL);
	X64Call(ReadFile64, 5, (uint64_t)hFile, (uint64_t)buffer, (uint64_t)sizeof(buffer), (uint64_t)NULL, (uint64_t)NULL);
	X64Call(CloseHandle64, 1, hFile);
	printf("%s\n", buffer);
	system("pause");
}