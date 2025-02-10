#pragma once
#include <Windows.h>
#include "Struct.h"
//  ====================  CONFIG  ==========================
static BOOLEAN isSyscall = FALSE;
static BOOLEAN isHidden = TRUE;
static ExecutionMethod ExecMethod = EnumCallback;
static EnumMethod enumMethod = CASE_VerifierEnumerateResource;
// ==================== CONFIG END ==========================
