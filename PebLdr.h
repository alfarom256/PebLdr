#pragma once
#ifndef __PEB_LDR
#define __PEB_LDR

#include <Windows.h>
#include <winnt.h>
#include <winternl.h>
#include "crc32.h"
#include <stdio.h>

#define HASH(s)	WSID(s)

HMODULE getK32();

typedef struct _peb_ldr {
	// Get the current module's base address
	HMODULE current_proc;
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
		PDWORD funcTbl = (PDWORD)(_export->AddressOfFunctions + (size_t)this->base);
		void* nameTbl = (void*)(_export->AddressOfNames + (size_t)this->base);
		PWORD ordTbl = (PWORD)(_export->AddressOfNameOrdinals + (size_t)this->base);
		this->p_eat_ptrtbl = funcTbl;
		this->p_eat_strtbl = nameTbl;
		this->p_eat_ordtbl = ordTbl;
		this->num_exp = _export->NumberOfFunctions;
		return TRUE;
	}

	/*
	Passing NULL as the dll name signifies you're walking the export table
	of Kernel32.dll
	*/
	_peb_ldr(const char* dll) : init(FALSE), base(NULL), p_eat_ptrtbl(NULL), p_eat_strtbl(NULL) {

#ifdef _WIN64
		PPEB _ppeb = (PPEB)__readgsqword(0x60);
		current_proc = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink + 0x20);
#else
		PPEB _ppeb = (PPEB)__readfsdword(0x30);
		current_proc = *(HMODULE*)((unsigned char*)_ppeb->Ldr->InMemoryOrderModuleList.Flink + 0x10);
#endif
		
		if (dll != NULL) {
			this->base = GetModuleHandleA(dll);
			if (this->base == NULL) {
				this->base = LoadLibraryA(dll);
				if (this->base == NULL)
					return;
			}
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

	void* currentmodule_iat_hook(DWORD lowercase_dllname_hash, DWORD function_hash, size_t absolute_dest_address) {
		IMAGE_DOS_HEADER* ImgBase = (IMAGE_DOS_HEADER*)this->current_proc;
		if (ImgBase->e_magic != IMAGE_DOS_SIGNATURE)
			return FALSE;

		IMAGE_NT_HEADERS* inth = (IMAGE_NT_HEADERS*)(ImgBase->e_lfanew + (size_t)this->current_proc);

		PIMAGE_OPTIONAL_HEADER pImageOptHdr = &inth->OptionalHeader;
		if ((pImageOptHdr->Magic ^ IMAGE_NT_OPTIONAL_HDR_MAGIC)) {
			return FALSE;
		}
		IMAGE_IMPORT_DESCRIPTOR* importIter = (IMAGE_IMPORT_DESCRIPTOR*)(pImageOptHdr->DataDirectory[1].VirtualAddress + (size_t)this->current_proc);
		while (importIter->Name != NULL) {
			const char* pModString = (const char*)((size_t)this->current_proc + importIter->Name);
			char* pModCpy = new(char[strlen(pModString) + 1]);
			//pModCpy, pModString, strlen(pModString)
			strncpy_s(pModCpy, strlen(pModString) + 1, pModString, strlen(pModString));
			for (size_t i = 0; i < strlen(pModString); i++)
			{
				pModCpy[i] = tolower(pModCpy[i]);
			}

			if (HASH(pModCpy) != lowercase_dllname_hash) {
				importIter++;
				continue;
			}
			//printf("Found dll target : %s\n", pModCpy);

			IMAGE_THUNK_DATA* imgThunk = (PIMAGE_THUNK_DATA)(importIter->FirstThunk + (size_t)this->current_proc);
			IMAGE_THUNK_DATA* OriginalThunk = (PIMAGE_THUNK_DATA)(importIter->OriginalFirstThunk + (size_t)this->current_proc);

			while (imgThunk->u1.Function != NULL) {
				LPVOID func = (LPVOID)(imgThunk->u1.Function);
				PIMAGE_IMPORT_BY_NAME pFname = (PIMAGE_IMPORT_BY_NAME)((size_t)this->current_proc + OriginalThunk->u1.AddressOfData);
				if (HASH(pFname->Name) == function_hash) {

					DWORD oldProtect, junk = 0;
					VirtualProtect(&imgThunk->u1.Function, sizeof(size_t), PAGE_READWRITE, &oldProtect);
					imgThunk->u1.Function = absolute_dest_address;
					VirtualProtect(&imgThunk->u1.Function, sizeof(size_t), oldProtect, &junk);
					return func;
				}
				OriginalThunk++;
				imgThunk++;
			}
		}
		return NULL;
	}


} _peb_ldr, *_ppeb_ldr;



#endif