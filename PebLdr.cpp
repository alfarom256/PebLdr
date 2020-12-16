#include "PebLdr.h"

HMODULE getK32() {
	HMODULE r;
#ifdef _WIN64
	PPEB _ppeb = (PPEB)__readgsqword(0x60);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink + 0x20);
#else
	PPEB _ppeb = (PPEB)__readfsdword(0x30);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink + 0x10);
#endif
	return r;
}
