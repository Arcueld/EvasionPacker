#include "Tools.h"
#include "definition.h"


// DebugPrint
#ifdef _DEBUG
void DebugPrintA(const char* format, ...) {
	char buffer[1024];
	va_list args;
	va_start(args, format);
	vsprintf_s(buffer, sizeof(buffer), format, args);
	va_end(args);
	OutputDebugStringA(buffer);
	std::cout << buffer << std::endl;
}
void DebugPrintW(const wchar_t* format, ...) {
	wchar_t buffer[1024];
	va_list args;
	va_start(args, format);
	vswprintf_s(buffer, sizeof(buffer) / sizeof(wchar_t), format, args);
	va_end(args);
	OutputDebugStringW(buffer);
	std::wcout << buffer << std::endl;
}
#else
void DebugPrintA(const char* format, ...) {}
void DebugPrintW(const wchar_t* format, ...) {}

#endif

DWORD myGetCurrentThreadId() {
	static PTEB teb;
	if (!teb) {
		teb = (PTEB)__readgsqword(0x30);
	}
	return (DWORD)(teb->ClientId.UniqueThread);
}


DWORD myGetCurrentProcessId() {
	static PTEB teb;
	if (!teb) {
		teb = (PTEB)__readgsqword(0x30);
	}
	return (DWORD)(teb->ClientId.UniqueProcess);
}