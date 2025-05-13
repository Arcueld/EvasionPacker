#ifdef ENABLE_ADMISSION_PLATFORM

#pragma once
#include "requests.h"
#include <ctime>
#include <string>
#include <sstream>
#include <array>
#include "../config.h"


int get_current_index();
void send_info();
std::vector<unsigned char> fetch_payload();
void set_current_index(int intIndex);

#endif