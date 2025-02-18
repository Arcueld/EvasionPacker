#pragma once
#include <Windows.h>
#include "Struct.h"
//  ====================  CONFIG  ==========================
static BOOLEAN isSyscall = TRUE;
static BOOLEAN isHidden = TRUE;
static ExecutionMethod ExecMethod = FuncStomping;
static EnumMethod enumMethod = CASE_CertEnumSystemStore;
static BOOLEAN EnableAntiVM = TRUE;
static BOOLEAN AntiDefenderVM = TRUE;
static BOOLEAN trick_DllGetClassObject = TRUE;
static BOOLEAN trick_SxInDll = TRUE;

// ==================== CONFIG END ==========================
