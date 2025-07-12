#include "function.hpp"

LPVOID GetProcAddressbyHASH(HMODULE hModule, DWORD funcHash) {
	if (hModule == NULL || funcHash == NULL)
		return NULL;
	PBYTE pBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER         pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS         pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER     ImgOptHdr = pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY   pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD  FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD  FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD   FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Hashing every function name pFunctionName
		// If both hashes are equal then we found the function we want
		if (funcHash == HASH(pFunctionName)) {
			return pFunctionAddress;
		}
	}

	return NULL;
}

HMODULE GetMoudlebyName(WCHAR* target) {
	PPEB_LDR_DATA ldrData = peb->LoaderData;
	PLIST_ENTRY moduleList = &ldrData->InLoadOrderModuleList;

	PLIST_ENTRY current = moduleList->Flink;

	while (current != moduleList) {
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)current;
		if (_wcsnicmp(entry->BaseDllName.Buffer, target, wcslen(target)) == 0) {
			return (HMODULE)entry->DllBase;
		}
		current = current->Flink;
	}
	return NULL;
}



HMODULE Ntd1l = GetMoudlebyName(_wcsdup(ENCRYPT_WSTR("ntdll.dll")));
HMODULE Kn32 = GetMoudlebyName(_wcsdup(ENCRYPT_WSTR("Kernel32.dll")));

typedef HMODULE (WINAPI* pLoadLibraryW)(
	_In_ LPCWSTR lpLibFileName
);

HMODULE myLoadLibrary(LPCWSTR moduleName) {
	static pLoadLibraryW LoadLibraryWRoutine;
	if (!LoadLibraryWRoutine) {
		LoadLibraryWRoutine = (pLoadLibraryW)GetProcAddressbyHASH(Kn32, LoadLibraryW_Hashed);
	}
	if (LoadLibraryWRoutine) {
		return LoadLibraryWRoutine(moduleName);
	}
	return NULL;
}

// ======================== Function INIT =================================
FunctionStruct NtAllocateVirtualMemoryStruct = { 0 };
FunctionStruct NtProtectVirtualMemoryStruct = { 0 };
FunctionStruct NtFreeVirtualMemoryStruct = { 0 };
FunctionStruct NtQueryVirtualMemoryStruct = { 0 };
FunctionStruct ZwQueryLicenseValueStruct = { 0 };
FunctionStruct ZwQuerySystemInformationStruct = { 0 };
FunctionStruct RtlExitUserProcessStruct = { 0 };
FunctionStruct RtlInitUnicodeStringStruct = { 0 };
FunctionStruct RtlImageDirectoryEntryToDataStruct = { 0 };
FunctionStruct LdrGetDllHandleExStruct = { 0 };
FunctionStruct NtIsProcessInJobStruct = { 0 };
FunctionStruct NtCompressKeyStruct = { 0 };
FunctionStruct NtCreateMutantStruct = { 0 };
FunctionStruct NtFlushInstructionCacheStruct = { 0 };
FunctionStruct NtQueryInformationProcessStruct = { 0 };
FunctionStruct NtOpenProcessStruct = { 0 };
FunctionStruct NtOpenProcessTokenStruct = { 0 };
FunctionStruct NtQueryInformationTokenStruct = { 0 };
FunctionStruct NtSetInformationProcessStruct = { 0 };
FunctionStruct NtCloseStruct = { 0 };
FunctionStruct NtAdjustPrivilegesTokenStruct = { 0 };

void initAllFunc() {
	NtAllocateVirtualMemoryStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtAllocateVirtualMemory_Hashed);
	NtAllocateVirtualMemoryStruct.funcHash = NtAllocateVirtualMemory_Hashed;
	NtProtectVirtualMemoryStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtProtectVirtualMemory_Hashed);
	NtProtectVirtualMemoryStruct.funcHash = NtProtectVirtualMemory_Hashed;
	NtFreeVirtualMemoryStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtFreeVirtualMemory_Hashed);
	NtFreeVirtualMemoryStruct.funcHash = NtFreeVirtualMemory_Hashed;
	NtQueryVirtualMemoryStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtQueryVirtualMemory_Hashed);
	NtQueryVirtualMemoryStruct.funcHash = NtQueryVirtualMemory_Hashed;
	ZwQueryLicenseValueStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, ZwQueryLicenseValue_Hashed);
	ZwQueryLicenseValueStruct.funcHash = ZwQueryLicenseValue_Hashed;
	ZwQuerySystemInformationStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, ZwQuerySystemInformation_Hashed);
	ZwQuerySystemInformationStruct.funcHash = ZwQuerySystemInformation_Hashed;
	RtlExitUserProcessStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, RtlExitUserProcess_Hashed);
	RtlExitUserProcessStruct.funcHash = RtlExitUserProcess_Hashed;
	RtlInitUnicodeStringStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, RtlInitUnicodeString_Hashed);
	RtlInitUnicodeStringStruct.funcHash = RtlInitUnicodeString_Hashed;
	RtlImageDirectoryEntryToDataStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, RtlImageDirectoryEntryToData_Hashed);
	RtlImageDirectoryEntryToDataStruct.funcHash = RtlImageDirectoryEntryToData_Hashed;
	LdrGetDllHandleExStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, LdrGetDllHandleEx_Hashed);
	LdrGetDllHandleExStruct.funcHash = LdrGetDllHandleEx_Hashed;
	NtIsProcessInJobStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtIsProcessInJob_Hashed);
	NtIsProcessInJobStruct.funcHash = NtIsProcessInJob_Hashed;
	NtCompressKeyStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtCompressKey_Hashed);
	NtCompressKeyStruct.funcHash = NtCompressKey_Hashed;
	NtCreateMutantStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtCreateMutant_Hashed);
	NtCreateMutantStruct.funcHash = NtCreateMutant_Hashed;
	NtFlushInstructionCacheStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtFlushInstructionCache_Hashed);
	NtFlushInstructionCacheStruct.funcHash = NtFlushInstructionCache_Hashed;
	NtQueryInformationProcessStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtQueryInformationProcess_Hashed);
	NtQueryInformationProcessStruct.funcHash = NtQueryInformationProcess_Hashed;
	NtOpenProcessStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtOpenProcess_Hashed);
	NtOpenProcessStruct.funcHash = NtOpenProcess_Hashed;
	NtOpenProcessTokenStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtOpenProcessToken_Hashed);
	NtOpenProcessTokenStruct.funcHash = NtOpenProcessToken_Hashed;
	NtQueryInformationTokenStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtQueryInformationToken_Hashed);
	NtQueryInformationTokenStruct.funcHash = NtQueryInformationToken_Hashed;
	NtSetInformationProcessStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtSetInformationProcess_Hashed);
	NtSetInformationProcessStruct.funcHash = NtSetInformationProcess_Hashed;
	NtCloseStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtClose_Hashed);
	NtCloseStruct.funcHash = NtClose_Hashed;
	NtAdjustPrivilegesTokenStruct.funcAddr = GetProcAddressbyHASH(Ntd1l, NtAdjustPrivilegesToken_Hashed);
	NtAdjustPrivilegesTokenStruct.funcHash = NtAdjustPrivilegesToken_Hashed;
}

// ======================== Function INIT END =================================
