#include <Windows.h>
#include "PebLdr.h"
#include <stdio.h>

typedef int(*pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
pMessageBoxA OriginalMessageBoxA = MessageBoxA;

int HookedMessageBoxA(HWND hWnd, LPCSTR content, LPCSTR title, UINT status) {
	return OriginalMessageBoxA(NULL, "MUAHAHAHAHA Hooked!", "So Long, And Thanks For All The Fish!", MB_OK);
}

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
	
	// Hook the function
	void* lpMsgBoxA = pk32->currentmodule_iat_hook(HASH("user32.dll"), HASH("MessageBoxA"), (size_t)HookedMessageBoxA);
	
	// Call the hooked MessageBoxA
	MessageBoxA(NULL, "Hello", "Hello World!", MB_OK);
	return 0;
}