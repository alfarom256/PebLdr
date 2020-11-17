# PebLdr

Yet another PEB Loader

Refer to Source.cpp for usage.
The basic gist is this:

```C++

#include <Windows.h>
#include "PebLdr.h"
#include <stdio.h>

typedef int(*pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

int main() {
// Must be a constexpr int to be evaluated at compile-time
// Store the crc32 of "MessageBoxA"
	constexpr int y = HASH("MessageBoxA");
  
// create a new loader for "User32.dll"
	_ppeb_ldr pk32 = new _peb_ldr("User32.dll");
// use the get function to retrieve the export who's name equals the crc32 of "MessageBoxA"
	pMessageBoxA _pMessageBoxA = (pMessageBoxA)pk32->get(y);
// call it normally
	_pMessageBoxA(NULL, "Hello", "Hello World!", MB_OK);
	return 0;
}

```