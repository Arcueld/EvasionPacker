#pragma once
#include <cstdint>



typedef enum _ExecutionMethod {
	AlertAPC,
	Fiber,
	WindowsHook,
	EnumCallback,
}ExecutionMethod;

typedef enum _EnumMethod {
	CASE_CertEnumSystemStore,
	CASE_CertEnumSystemStoreLocation,
	CASE_CopyFile2,
	CASE_CopyFileEx,
	CASE_CreateThreadPoolWait,
	CASE_CreateTimerQueueTimer,
	CASE_CryptEnumOIDInfo,
	CASE_EnumCalendarInfo,
	CASE_EnumCalendarInfoEx,
	CASE_EnumChildWindows,
	CASE_EnumDesktopW,
	CASE_EnumDesktopWindows,
	CASE_EnumDirTreeW,
	CASE_EnumDisplayMonitors,
	CASE_EnumFontFamiliesExW,
	CASE_EnumFontFamiliesW,
	CASE_EnumFontsW,
	CASE_EnumLanguageGroupLocalesW,
	CASE_EnumObjects,
	CASE_EnumPwrSchemes,
	CASE_EnumResourceTypesExW,
	CASE_EnumResourceTypesW,
	CASE_EnumSystemLocales,
	CASE_EnumThreadWindows,
	CASE_EnumTimeFormatsEx,
	CASE_EnumUILanguagesW,
	CASE_EnumWindowStationsW,
	CASE_EnumWindows,
	CASE_EnumerateLoadedModules,
	CASE_FlsAlloc,
	CASE_ImmEnumInputContext,
	CASE_InitOnceExecuteOnce,
	CASE_LdrEnumerateLoadedModules,
	CASE_lpRtlUserFiberStart,
	CASE_SetTimer,
	CASE_SetupCommitFileQueueW,
	CASE_SymFindFileInPath,
	CASE_SysEnumSourceFiles,
	CASE_EnumPageFilesW,
	CASE_SymEnumProcesses,
}EnumMethod;

typedef enum _AllocateMethod {
	CASE_NtAllocateVirtualMemory,
	CASE_NtMapOfView,
	CASE_ModuleStomping,
}AllocateMethod;

typedef enum _EncryptMethod {
	CASE_XOR,
	CASE_RC4,
	CASE_AES,
}EncryptMethod;

typedef struct _ExecuteShellcodeStruct {
	LPVOID lpMem;
	SIZE_T memSize;
}ExecuteShellcodeStruct, * PExecuteShellcodeStruct;

typedef struct _FunctionStruct {
	LPVOID funcAddr;
	DWORD funcHash;
}FunctionStruct, * PFunctionStruct;