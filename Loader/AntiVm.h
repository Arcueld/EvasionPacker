#pragma once
#include <Windows.h>




EXTERN_C auto query_license_value() -> BOOLEAN;
EXTERN_C auto checkCPUCoreNum() -> BOOLEAN;
EXTERN_C auto checkPhysicalMemory() -> BOOLEAN;
EXTERN_C auto checkBootTime() -> BOOLEAN;
EXTERN_C auto checkHyperVPresent() -> BOOLEAN;
EXTERN_C auto checkGPUMemory() -> BOOLEAN;
EXTERN_C auto checkMacAddrPrefix() -> BOOLEAN;
EXTERN_C auto accelerated_sleep() -> BOOLEAN;
EXTERN_C auto wdCheckEmulatedVFS(VOID) -> VOID;
EXTERN_C auto wdIsEmulatorPresent(VOID) -> NTSTATUS;
EXTERN_C auto wdIsEmulatorPresent2(VOID) -> BOOLEAN;
EXTERN_C auto wdIsEmulatorPresent3(VOID) -> BOOLEAN;
EXTERN_C auto checkDllGetClassObject() -> BOOLEAN;
EXTERN_C auto checkSxInDll() -> BOOLEAN;
EXTERN_C auto timing_SetTimer(UINT delayInMillis) -> BOOLEAN;
EXTERN_C auto checkProcessVX_QQ() -> BOOLEAN;