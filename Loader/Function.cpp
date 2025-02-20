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




HMODULE Ntdll = GetMoudlebyName(_wcsdup(L"ntdll.dll"));
HMODULE Kernel32 = GetMoudlebyName(_wcsdup(L"Kernel32.dll"));

typedef HMODULE (WINAPI* pLoadLibraryW)(
	_In_ LPCWSTR lpLibFileName
);

HMODULE myLoadLibrary(LPCWSTR moduleName) {
	static pLoadLibraryW LoadLibraryWRoutine;
	if (!LoadLibraryWRoutine) {
		LoadLibraryWRoutine = (pLoadLibraryW)GetProcAddressbyHASH(Kernel32, LoadLibraryW_Hashed);
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

void initAllFunc() {
	NtAllocateVirtualMemoryStruct.funcAddr = GetProcAddressbyHASH(Ntdll, NtAllocateVirtualMemory_Hashed);
	NtAllocateVirtualMemoryStruct.funcHash = NtAllocateVirtualMemory_Hashed;
	NtProtectVirtualMemoryStruct.funcAddr = GetProcAddressbyHASH(Ntdll, NtProtectVirtualMemory_Hashed);
	NtProtectVirtualMemoryStruct.funcHash = NtProtectVirtualMemory_Hashed;
	NtFreeVirtualMemoryStruct.funcAddr = GetProcAddressbyHASH(Ntdll, NtFreeVirtualMemory_Hashed);
	NtFreeVirtualMemoryStruct.funcHash = NtFreeVirtualMemory_Hashed;
	NtQueryVirtualMemoryStruct.funcAddr = GetProcAddressbyHASH(Ntdll, NtQueryVirtualMemory_Hashed);
	NtQueryVirtualMemoryStruct.funcHash = NtQueryVirtualMemory_Hashed;
	ZwQueryLicenseValueStruct.funcAddr = GetProcAddressbyHASH(Ntdll, ZwQueryLicenseValue_Hashed);
	ZwQueryLicenseValueStruct.funcHash = ZwQueryLicenseValue_Hashed;
	ZwQuerySystemInformationStruct.funcAddr = GetProcAddressbyHASH(Ntdll, ZwQuerySystemInformation_Hashed);
	ZwQuerySystemInformationStruct.funcHash = ZwQuerySystemInformation_Hashed;
	RtlExitUserProcessStruct.funcAddr = GetProcAddressbyHASH(Ntdll, RtlExitUserProcess_Hashed);
	RtlExitUserProcessStruct.funcHash = RtlExitUserProcess_Hashed;
	RtlInitUnicodeStringStruct.funcAddr = GetProcAddressbyHASH(Ntdll, RtlInitUnicodeString_Hashed);
	RtlInitUnicodeStringStruct.funcHash = RtlInitUnicodeString_Hashed;
	RtlImageDirectoryEntryToDataStruct.funcAddr = GetProcAddressbyHASH(Ntdll, RtlImageDirectoryEntryToData_Hashed);
	RtlImageDirectoryEntryToDataStruct.funcHash = RtlImageDirectoryEntryToData_Hashed;
	LdrGetDllHandleExStruct.funcAddr = GetProcAddressbyHASH(Ntdll, LdrGetDllHandleEx_Hashed);
	LdrGetDllHandleExStruct.funcHash = LdrGetDllHandleEx_Hashed;
	NtIsProcessInJobStruct.funcAddr = GetProcAddressbyHASH(Ntdll, NtIsProcessInJob_Hashed);
	NtIsProcessInJobStruct.funcHash = NtIsProcessInJob_Hashed;
	NtCompressKeyStruct.funcAddr = GetProcAddressbyHASH(Ntdll, NtCompressKey_Hashed);
	NtCompressKeyStruct.funcHash = NtCompressKey_Hashed;

	
}

// ======================== Function INIT END =================================
