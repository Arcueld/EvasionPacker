#pragma once
#include <Windows.h>
#include <xstring>
#include <iostream>
#include <string>

void DebugPrintA(const char* format, ...);
void DebugPrintW(const wchar_t* format, ...);
DWORD myGetCurrentThreadId();
DWORD myGetCurrentProcessId();