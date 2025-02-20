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


LPCWSTR charToLPCWSTR(const char* charString);
LPSTR charToLPSTR(const char* str);
LPWSTR charToLPWSTR(const char* charString);

void DebugPrintA(const char* format, ...);
void DebugPrintW(const wchar_t* format, ...);
DWORD myGetCurrentThreadId();
DWORD myGetCurrentProcessId();
ULONG64 AR_getTickcount64();
wchar_t* _strstri_w(const wchar_t* s, const wchar_t* sub_s);
BOOL ExtractShellcodeFromImage(LPCWSTR imagePath, PBYTE *shellcode, DWORD *size);



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
            BYTE* ptr = reinterpret_cast<BYTE*>(str);
            for (size_t i = 0; i < len * sizeof(wchar_t); i++) {
                ptr[i] = ptr[i] ^ key[i % sizeof(key)] ^ (i & 0xFF);
            }
        }

    public:
        constexpr EncryptedWString(const wchar_t* str) : data{}, decrypted(false) {
            for (size_t i = 0; i < N; i++) {
                data[i] = str[i];
                BYTE* ptr = reinterpret_cast<BYTE*>(&data[i]);
                for (size_t j = 0; j < sizeof(wchar_t); j++) {
                    ptr[j] = ptr[j] ^ key[(i * sizeof(wchar_t) + j) % sizeof(key)] ^ ((i * sizeof(wchar_t) + j) & 0xFF);
                }
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