#include "requests.h"

HttpClient::HttpClient() {
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
}

HttpClient::~HttpClient() {
    if (curl) curl_easy_cleanup(curl);
    curl_global_cleanup();
}


std::string HttpClient::sendRequest(const std::string& url,
    const std::string& method,
    const std::string& body,
    const std::vector<std::string>& headers) {
    if (!curl) return "Curl init failed";

    std::string response;
    struct curl_slist* header_list = nullptr;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    }
    else if (method != "GET") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
        if (!body.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        }
    }

    for (const auto& h : headers) {
        header_list = curl_slist_append(header_list, h.c_str());
    }
    if (header_list)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        response = std::string("curl_easy_perform() failed: ") + curl_easy_strerror(res);
    }

    if (header_list)
        curl_slist_free_all(header_list);

    return response;
}

size_t HttpClient::writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

