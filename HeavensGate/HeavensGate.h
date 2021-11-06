#ifndef _HEAVENS_GATE_
#define _HEAVENS_GATE_
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>

void memcpy64(uint64_t dst, uint64_t src, uint64_t sz);

void GetPEB64(void* peb64);

uint64_t GetModuleHandle64(const WCHAR *moduleName);

uint64_t GetProcAddress64(uint64_t hModule, const char* func);

uint64_t X64Call(uint64_t proc, uint32_t argc, ...);

char* MakeUTFStr(const char* str);

uint64_t GetKernel32();

uint64_t LoadLibrary64(const char* name);
#endif
