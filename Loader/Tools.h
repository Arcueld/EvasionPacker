#pragma once
#include <Windows.h>
#include <xstring>
#include <iostream>
#include <string>
#include <gdiplus.h>

#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>
#endif

#pragma comment(lib, "gdiplus.lib")

LPCWSTR charToLPCWSTR(const char* charString);
LPSTR charToLPSTR(const char* str);
LPWSTR charToLPWSTR(const char* charString);

void DebugPrintA(const char* format, ...);
void DebugPrintW(const wchar_t* format, ...);
DWORD myGetCurrentThreadId();
DWORD myGetCurrentProcessId();
ULONG64 AR_getTickcount64();
wchar_t* _strstri_w(const wchar_t* s, const wchar_t* sub_s);
BOOL ExtractShellcodeFromImage(LPCWSTR imagePath, PBYTE *shellcode, DWORD *size);