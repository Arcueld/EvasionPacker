#pragma once
#include <Windows.h>
#include <string>
#include "../Tools.h"
#include "../Function.hpp"
#include "../definition.h"




std::string getCurrentTime();
std::string GetUsername();
std::string GetHostname();
std::string GetAccountPrivilege();
ULONG64 GetPhysicalMemory();
ULONG64 GetCpuCoreNum();
ULONG64 GetBootTime();
ULONG64 GetBootTimeMinute();
ULONG64 GetTempFileNum();
std::string GetResolution();
std::string GetCurrentExeDir();
std::string GetParentProcessName();
std::wstring GetCurrentExecutablePath();
int getTempFileCount();
std::string getTempFileCountStr();
