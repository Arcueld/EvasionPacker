#pragma once
#include <string>
#include <vector>
#include <curl/curl.h>
#include <time.h>

#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "zlib.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "normaliz.lib")


class HttpClient {
private:
    CURL* curl;
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp);

public:
    HttpClient();
    ~HttpClient();

    std::string sendRequest(const std::string& url,
        const std::string& method = "GET",
        const std::string& body = "",
        const std::vector<std::string>& headers = {});

};