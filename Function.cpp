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







// ======================== Function INIT =================================
FunctionStruct NtAllocateVirtualMemoryStruct = { 0 };
FunctionStruct NtProtectVirtualMemoryStruct = { 0 };

void initAllFunc() {
	NtAllocateVirtualMemoryStruct.funcAddr = GetProcAddressbyHASH(GetMoudlebyName(_wcsdup(L"ntdll.dll")), NtAllocateVirtualMemory_Hashed);
	NtAllocateVirtualMemoryStruct.funcHash = NtAllocateVirtualMemory_Hashed;
	NtProtectVirtualMemoryStruct.funcAddr = GetProcAddressbyHASH(GetMoudlebyName(_wcsdup(L"ntdll.dll")), NtProtectVirtualMemory_Hashed);
	NtProtectVirtualMemoryStruct.funcHash = NtProtectVirtualMemory_Hashed;
}

// ======================== Function INIT END =================================
