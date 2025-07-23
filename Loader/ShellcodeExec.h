#pragma once
#include <Windows.h>
#include "Struct.h"

auto ExecuteShellcode(PExecuteShellcodeStruct execStruct) -> BOOLEAN;
auto AllocateMem(LPVOID* lpMem, PSIZE_T size) -> NTSTATUS;
auto isPayloadRunning() -> BOOLEAN;
auto disableETW() -> BOOLEAN;