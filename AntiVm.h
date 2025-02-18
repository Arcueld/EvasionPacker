#pragma once
#include <Windows.h>




EXTERN_C BOOLEAN query_license_value();
EXTERN_C BOOLEAN checkCPUCoreNum();
EXTERN_C BOOLEAN checkPhysicalMemory();
EXTERN_C BOOLEAN checkBootTime();
EXTERN_C BOOLEAN checkHyperVPresent();
EXTERN_C BOOLEAN checkGPUMemory();
EXTERN_C BOOLEAN checkMacAddrPrefix();
EXTERN_C BOOLEAN accelerated_sleep();
EXTERN_C VOID wdCheckEmulatedVFS(VOID);
EXTERN_C NTSTATUS wdIsEmulatorPresent(VOID);
EXTERN_C BOOLEAN wdIsEmulatorPresent2(VOID);
EXTERN_C BOOLEAN wdIsEmulatorPresent3(VOID);
EXTERN_C BOOLEAN checkDllGetClassObject();
EXTERN_C BOOLEAN checkSxInDll();