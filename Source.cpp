#include <Windows.h>
#include "PebLdr.h"
#include <stdio.h>

typedef int(*pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

int main() {
	constexpr int y = HASH("MessageBoxA");
	_ppeb_ldr pk32 = new _peb_ldr("User32.dll");
	pMessageBoxA _pMessageBoxA = (pMessageBoxA)pk32->get(y);
	_pMessageBoxA(NULL, "Hello", "Hello World!", MB_OK);
	return 0;
}
