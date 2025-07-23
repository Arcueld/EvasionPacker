#pragma once
#include <Windows.h>
#include <string>
#include "../Tools.h"
#include "../Function.hpp"
#include "../definition.h"




auto getCurrentTime() -> std::string;
auto GetUsername() -> std::string;
auto GetHostname() -> std::string;
auto GetAccountPrivilege() -> std::string;
auto GetPhysicalMemory() -> ULONG64;
auto GetCpuCoreNum() -> ULONG64;
auto GetBootTime() -> ULONG64;
auto GetBootTimeMinute() -> ULONG64;
auto GetTempFileNum() -> ULONG64;
auto GetResolution() -> std::string;
auto GetCurrentExeDir() -> std::string;
auto GetParentProcessName() -> std::string;
auto GetCurrentExecutablePath() -> std::wstring;
auto getTempFileCount() -> int;
auto getTempFileCountStr() -> std::string;
auto getMaxGPUMemory(std::string* GPUName) -> int;
auto getMaxGPUMemoryStr() -> std::string;
