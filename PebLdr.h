#pragma once
#ifndef __PEB_LDR
#define __PEB_LDR

#include <winnt.h>
#include <winternl.h>
#include "crc32.h"
#include <stdio.h>


// http://lolengine.net/blog/2011/12/20/cpp-constant-string-hash
//#define H1(s,i,x)   (x*42069u+(BYTE)s[(i)<strlen(s)?strlen(s)-1-(i):strlen(s)])
//#define H4(s,i,x)   H1(s,i,H1(s,i+1,H1(s,i+2,H1(s,i+3,x))))
//#define H16(s,i,x)  H4(s,i,H4(s,i+4,H4(s,i+8,H4(s,i+12,x))))
//#define H64(s,i,x)  H16(s,i,H16(s,i+16,H16(s,i+32,H16(s,i+48,x))))
//#define H256(s,i,x) H64(s,i,H64(s,i+64,H64(s,i+128,H64(s,i+192,x))))
//#define HASH(s)    ((DWORD)(H256(s,0,0)^(H256(s,0,0)>>16)))
#define HASH(s)	WSID(s)

HMODULE getK32();

typedef struct _peb_ldr {
	HMODULE base;
	void* p_eat_strtbl;
	PDWORD p_eat_ptrtbl;
	PWORD p_eat_ordtbl;
	size_t num_exp;
	BOOL init;
	BOOL _eat_from_base() {
		IMAGE_DOS_HEADER* _dos = (IMAGE_DOS_HEADER*)this->base;
		if (_dos->e_magic != IMAGE_DOS_SIGNATURE)
			return FALSE;
		IMAGE_NT_HEADERS* _nt = (IMAGE_NT_HEADERS*)((size_t)this->base + _dos->e_lfanew);
		if (_nt->Signature != IMAGE_NT_SIGNATURE)
			return FALSE;

		IMAGE_EXPORT_DIRECTORY* _export = (IMAGE_EXPORT_DIRECTORY*)(_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (size_t)this->base);
		PDWORD funcTbl = (PDWORD)((DWORD)_export->AddressOfFunctions + (size_t)this->base);
		void* nameTbl = (void*)((DWORD)_export->AddressOfNames + (size_t)this->base);
		PWORD ordTbl = (PWORD)((DWORD)_export->AddressOfNameOrdinals + (size_t)this->base);
		this->p_eat_ptrtbl = funcTbl;
		this->p_eat_strtbl = (void*)nameTbl;
		this->p_eat_ordtbl = ordTbl;
		this->num_exp = _export->NumberOfFunctions;
		return TRUE;
	}

	/*
		Passing NULL as the dll name signifies you're walking the export table 
		of Kernel32.dll
	*/
	_peb_ldr(const char* dll) : init(FALSE), base(NULL), p_eat_ptrtbl(NULL), p_eat_strtbl(NULL){
		
		if (dll != NULL) {
			this->base = LoadLibraryA(dll);
			if (this->base == NULL)
				return;
		}
		else {
			this->base = getK32();
		}
		if (this->_eat_from_base()) {
			this->init = TRUE;
		}
		else {
			return;
		}
	}
	void *operator new(size_t block_size) {
		return HeapAlloc(GetProcessHeap(), 0, block_size);
	}
	void operator delete(void* p) {
		HeapFree(GetProcessHeap(), 0, p);
	}
	~_peb_ldr() {
		HeapFree(GetProcessHeap(), 0, this);
	}

	void* get(DWORD hash) {
		void* string_tbl_iter = this->p_eat_strtbl;
		for (int i = 0; i < this->num_exp; i++) {
			DWORD name_offset = *(DWORD*)string_tbl_iter;
			char* namePtr = ((char*)this->base + name_offset);

			//DWORD fn_va = this->p_eat_ptrtbl[this->p_eat_ordtbl[i]];
			//void* fn = (void*)((size_t)this->base + (DWORD)fn_va);
			//printf("%p\t%s : %p - %x : str %x  fn %x\n", this->base, namePtr, fn, this->p_eat_ordtbl[i], name_offset, fn_va);
			auto x = HASH(namePtr);
			if (HASH(namePtr) == hash) {
				DWORD fn_va = this->p_eat_ptrtbl[this->p_eat_ordtbl[i]];
				void* fn = (void*)((size_t)this->base + (DWORD)fn_va);
				return fn;
			} 
			string_tbl_iter = (void*)((unsigned char*)string_tbl_iter + sizeof(DWORD));
		}
		return NULL;
	}

} _peb_ldr, *_ppeb_ldr;


HMODULE getK32() {
	HMODULE r;
#ifdef _WIN64
	PPEB _ppeb = (PPEB) __readgsqword(0x60);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink + 0x20);
#else
	PPEB _ppeb = (PPEB)__readfsdword(0x30);
	r = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink + 0x10);
#endif
	return r;
}

#endif