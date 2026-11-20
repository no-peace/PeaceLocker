#pragma once

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <string>
#include <cwctype>
#include <cctype>
#include <memory>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

struct HandleDeleter { void operator()(HANDLE h) { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); } };
using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

struct GDIDeleter { void operator()(HGDIOBJ h) { if (h) DeleteObject(h); } };
using UniqueGDIObject = std::unique_ptr<void, GDIDeleter>;

struct WinHttpHandleDeleter { void operator()(HINTERNET h) { if (h) WinHttpCloseHandle(h); } };
using UniqueWinHttpHandle = std::unique_ptr<void, WinHttpHandleDeleter>;

struct BCryptAlgDeleter { void operator()(BCRYPT_ALG_HANDLE h) { if (h) BCryptCloseAlgorithmProvider(h, 0); } };
using UniqueBCryptAlg = std::unique_ptr<void, BCryptAlgDeleter>;

struct BCryptHashDeleter { void operator()(BCRYPT_HASH_HANDLE h) { if (h) BCryptDestroyHash(h); } };
using UniqueBCryptHash = std::unique_ptr<void, BCryptHashDeleter>;

inline void Log(const std::wstring& msg) {
    OutputDebugStringW((L"[PeaceVault] " + msg + L"\n").c_str());
}

#define WM_APP_BLOCKED  (WM_APP + 1)
#define WM_APP_TRAY     (WM_APP + 2)
#define WM_APP_SHOW_DASHBOARD (WM_APP + 15)
#define WM_APP_REMOTE_PROTECT (WM_APP + 16)
#define TRAY_UID        1001

#define PV_COPYDATA_PROTECT_PATH 0x50565631ULL
#define PV_COPYDATA_VERIFY_PIN   0x50565632ULL

#define APP_NAME_L      L"Peace's Vault"
#define APP_HOST_CLASS  L"PeaceVaultHostWindow"

// Tray/menu command IDs
#define IDM_ADD_APP         2001
#define IDM_ADD_FILE        2002
#define IDM_ADD_IMAGE       2003
#define IDM_ADD_URL         2004
#define IDM_MANAGE          2005
#define IDM_CHANGE_PIN      2006
#define IDM_TOGGLE_AUTO     2007
#define IDM_EXIT            2008
#define IDM_ADD_FOLDER      2009
#define IDM_ADD_AUDIO       2010
#define IDM_REMOVE_PWD      2011
#define IDM_SET_WEBHOOK     2012
#define IDM_OPEN_INTRUDERS  2013
#define IDM_OPEN_DASHBOARD  2014
#define IDM_RESET_PIN       2015
#define IDM_TOGGLE_SHELL    2016

// Shared UI colors
#define CLR_BG       RGB( 19,   8,   8)
#define CLR_CARD     RGB( 35,  13,  13)
#define CLR_ACCENT   RGB(255, 188,  64)
#define CLR_ACCHOV   RGB(255, 208,  92)
#define CLR_TEXT     RGB(255, 242, 214)
#define CLR_DIM      RGB(197, 155, 125)
#define CLR_ERR      RGB(255, 102, 102)
#define CLR_BORDER   RGB( 88,  36,  28)
#define CLR_GRID     RGB( 56,  24,  24)
#define CLR_EDIT     RGB( 25,  10,  10)
#define CLR_BTN      RGB( 53,  22,  18)

inline std::string W2U(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

inline std::wstring U2W(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

inline std::wstring ToLowerW(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

inline std::string ToLowerA(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}
