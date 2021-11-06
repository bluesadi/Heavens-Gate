#include "HeavensGate.h"

void memcpy64(uint64_t dst, uint64_t src, uint64_t sz) {
	static uint8_t code[] = {
		/*	[bits 32]
			push 0x33
			push _next_x64_code
			retf
		*/
		0x6A, 0x33, 0x68, 0x78, 0x56, 0x34, 0x12, 0xCB,
		/*	[bits 64]
			push rsi
			push rdi
			mov rsi, src
			mov rdi, dst
			mov rcx, sz
			rep movsb
			pop rsi
			pop rdi
		*/
		0x56, 0x57,
		0x48, 0xBE, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
		0x48, 0xBF, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
		0x48, 0xB9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
		0xF3, 0xA4,
		0x5E, 0x5F,
		/*	[bits 64]
			push 0x23
			push _next_x86_code
			retfq
		*/
		0x6A, 0x23, 0x68, 0x78, 0x56, 0x34, 0x12, 0x48, 0xCB,
		/*	[bits 32]
			ret
		*/
		0xC3
	};

	static uint32_t ptr = NULL;
	if (!ptr) {
		ptr = (uint32_t)VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		for (int i = 0; i < sizeof(code); i++) ((PBYTE)ptr)[i] = code[i];
	}
	*(uint32_t*)(ptr + 3) = ptr + 8;
	*(uint64_t*)(ptr + 12) = src;
	*(uint64_t*)(ptr + 22) = dst;
	*(uint64_t*)(ptr + 32) = sz;
	*(uint32_t*)(ptr + 47) = ptr + 53;
	((void(*)())ptr)();
}

void GetPEB64(void *peb64) {
	static uint8_t code[] = {
		/*	[bits 32]
			mov esi, peb64
			push 0x33
			push _next_x64_code
			retf
		*/
		0xBE, 0x78, 0x56, 0x34, 0x12, 0x6A, 0x33, 0x68, 0x78, 0x56, 0x34, 0x12, 0xCB,
		/*	[bits 64]
			mov rax, gs:[0x60]
			mov [esi], rax
		*/
		0x65, 0x48, 0xA1, 0x60, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x67, 0x48, 0x89, 0x6,
		/*	[bits 64]
			push 0x23
			push _next_x86_code
			retfq
		*/
		0x6A, 0x23, 0x68, 0x78, 0x56, 0x34, 0x12, 0x48, 0xCB,
		/*	[bits 32]
			ret
		*/
		0xC3
	};

	static uint32_t ptr = NULL;
	if (!ptr) {
		ptr = (uint32_t)VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		for (int i = 0; i < sizeof(code); i++) ((PBYTE)ptr)[i] = code[i];
	}
	*(uint32_t*)(ptr + 1) = (uint32_t)peb64;
	*(uint32_t*)(ptr + 8) = ptr + 13;
	*(uint32_t*)(ptr + 31) = ptr + 37;
	((void(*)())ptr)();
}

uint64_t GetModuleHandle64(const WCHAR *moduleName) {
	uint64_t peb64;
	/*	nt!_PEB_LDR_DATA
	   +0x000 Length           : Uint4B
	   +0x004 Initialized      : UChar
	   +0x008 SsHandle         : Ptr64 Void
	   +0x010 InLoadOrderModuleList : _LIST_ENTRY
	*/
	uint64_t ldrData;
	/*
		ptr to InLoadOrderModuleList
	*/
	uint64_t head;
	/*
		typedef struct _LDR_MODULE {
		  +0x000 LIST_ENTRY              InLoadOrderModuleList;
		  +0x010 LIST_ENTRY              InMemoryOrderModuleList;
		  +0x020 LIST_ENTRY              InInitializationOrderModuleList;
		  +0x030 PVOID                   BaseAddress;
		  +0x038 PVOID                   EntryPoint;
		  +0x040 ULONG                   SizeOfImage;
		  +0x048 UNICODE_STRING          FullDllName;
		  +0x058 UNICODE_STRING          BaseDllName;
		  ...
		} LDR_MODULE, *PLDR_MODULE;
	*/
	uint64_t pNode;
	GetPEB64(&peb64);
	memcpy64((uint64_t)&ldrData, peb64 + 0x18, 8);
	head = ldrData + 0x10;
	memcpy64((uint64_t)&pNode, head, 8);
	while (pNode != head) {
		uint64_t buffer;
		memcpy64((uint64_t)(unsigned)(&buffer), pNode + 96, 8);	// tmp = pNode->BaseDllName->Buffer
		if (buffer) {
			WCHAR curModuleName[32] = {0};
			memcpy64((uint64_t)curModuleName, buffer, 60);
			if (!lstrcmpiW(moduleName, curModuleName)) {
				uint64_t base;
				memcpy64((uint64_t)&base, pNode + 48, 8);
				return base;
			}
		}
		memcpy64((uint64_t)&pNode, pNode, 8);	// pNode = pNode->Flink
	}
	return NULL;
}


uint64_t MyGetProcAddress(uint64_t hModule, const char* func) {
	IMAGE_DOS_HEADER dos;
	memcpy64((uint64_t)&dos, hModule, sizeof(dos));
	IMAGE_NT_HEADERS64 nt;
	memcpy64((uint64_t)&nt, hModule + dos.e_lfanew, sizeof(nt));
	IMAGE_EXPORT_DIRECTORY expo;
	memcpy64((uint64_t)&expo, hModule + nt.OptionalHeader.DataDirectory[0].VirtualAddress, sizeof(expo));

	for (uint64_t i = 0; i < expo.NumberOfNames; i++) {
		DWORD pName;
		memcpy64((uint64_t)&pName, hModule + expo.AddressOfNames + (4 * i), 4);
		char name[64] = {0};
		memcpy64((uint64_t)name, hModule + pName, 64);
		if (!lstrcmpA(name, func)) {
			WORD ord;
			memcpy64((uint64_t)&ord, hModule + expo.AddressOfNameOrdinals + (2 * i), 2);
			uint32_t addr;
			memcpy64((uint64_t)&addr, hModule + expo.AddressOfFunctions + (4 * ord), 4);
			return hModule + addr;
		}
	}
	return NULL;
}

uint64_t GetProcAddress64(uint64_t module, const char* func) {
	static uint64_t K32GetProcAddress = 0;
	if (!K32GetProcAddress)K32GetProcAddress = MyGetProcAddress(GetKernel32(), "GetProcAddress");

	return X64Call(K32GetProcAddress, 2, module, (uint64_t)func);
}

char* MakeUTFStr(const char* str) {
	uint32_t len = lstrlenA(str);
	char* out = (char*)malloc(16 + (len + 1) * 2);
	*(uint16_t*)(out) = (uint16_t)(len * 2); //Length
	*(uint16_t*)(out + 2) = (uint16_t)((len + 1) * 2); //Max Length

	uint16_t* outstr = (uint16_t*)(out + 16);
	for (uint32_t i = 0; i <= len; i++) outstr[i] = str[i];
	*(uint64_t*)(out + 8) = (uint64_t)(out + 16);
	return out;
}

uint64_t X64Call(uint64_t proc, uint32_t argc, ...) {
	uint64_t* args = (uint64_t*)(&argc + 1);
	uint64_t ret = 0;
	static uint8_t code[] = {
		/*	[bits 32]
			push ebx
			mov ebx, esp
			and esp, 0xFFFFFFF8

			push 0x33
			push _next_x64_code
			retf
		*/
		0x53, 0x89, 0xE3, 0x83, 0xE4, 0xF8,
		0x6A, 0x33, 0x68, 0x78, 0x56, 0x34, 0x12, 0xCB,
		/*	[bits 64]
			push rsi
			push rdi
			
			mov rsi, args
			mov rcx, [rsi]
			mov rdx, [rsi+8]
			mov r8, [rsi+16]
			mov r9, [rsi+24]
			
			mov rax, argc
			args_start:
				cmp rax, 4
				jle args_end
				mov rdi, [rsi+8*rax-8]
				push rdi
				dec rax
				jmp args_start
			args_end:

			mov rax, proc
			sub rsp, 32
			call rax

			mov rdi, &ret
			mov [rdi], rax

			pop rdi
			pop rsi
		*/
		0x56, 0x57,
		0x48, 0xBE, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x8B, 0xE, 0x48, 0x8B, 0x56, 0x8, 0x4C, 0x8B, 0x46, 0x10, 0x4C, 0x8B, 0x4E, 0x18,
		0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x83, 0xF8, 0x4, 0x7E, 0xB, 0x48, 0x8B, 0x7C, 0xC6, 0xF8, 0x57, 0x48, 0xFF, 0xC8, 0xEB, 0xEF,
		0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0xD0,
		0x48, 0xBF, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x7,
		0x5F, 0x5E,
		/*	[bits 64]
			push 0x23
			push _next_x86_code
			retfq
		*/
		0x6A, 0x23, 0x68, 0x78, 0x56, 0x34, 0x12, 0x48, 0xCB,
		/*	[bits 32]
			mov esp, ebx
			pop ebx
			ret
		*/
		0x89, 0xDC, 0x5B,
		0xC3
	};

	static uint32_t ptr = NULL;
	if (!ptr) {
		ptr = (uint32_t)VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		for (int i = 0; i < sizeof(code); i++) ((PBYTE)ptr)[i] = code[i];
	}
	*(uint32_t*)(ptr + 9) = ptr + 14;
	*(uint64_t*)(ptr + 18) = (uint64_t)args;
	*(uint64_t*)(ptr + 43) = (uint64_t)argc;
	*(uint64_t*)(ptr + 70) = proc; 
	*(uint64_t*)(ptr + 86) = (uint64_t)&ret;
	*(uint32_t*)(ptr + 102) = ptr + 108;
	((void(*)())ptr)();
	return ret;
}

uint64_t GetKernel32() {
	static uint64_t kernel32 = 0;
	if (kernel32) return kernel32;

	uint64_t ntdll = GetModuleHandle64(L"ntdll.dll");
	uint64_t LdrLoadDll = MyGetProcAddress(ntdll, "LdrLoadDll");
	char* str = MakeUTFStr("kernel32.dll");
	int ret0 = X64Call(LdrLoadDll, 4, (uint64_t)0, (uint64_t)0, (uint64_t)str, (uint64_t)(&kernel32));
	return kernel32;
}

uint64_t LoadLibrary64(const char* name) {
	static uint64_t LoadLibraryA = 0;
	if (!LoadLibraryA) LoadLibraryA = GetProcAddress64(GetKernel32(), "LoadLibraryA");

	return X64Call(LoadLibraryA, 1, (uint64_t)name);
}
