#pragma once
#include "requests.h"
#include <ctime>
#include <string>
#include <sstream>
#include <array>
#include "../config.h"

void send_info(const std::string& url);
std::vector<unsigned char> fetch_payload(std::string& serverUrl);