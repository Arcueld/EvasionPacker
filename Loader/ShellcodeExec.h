#pragma once
#include <Windows.h>
#include "Struct.h"

BOOLEAN ExecuteShellcode(PExecuteShellcodeStruct execStruct);
NTSTATUS AllocateMem(LPVOID* lpMem, PSIZE_T size);
BOOLEAN isPayloadRunning();
BOOLEAN disableETW();