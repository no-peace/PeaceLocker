#pragma once

#include <windows.h>
#include <shlobj.h>
#include <string>

inline std::wstring GetAppDataPath() {
    wchar_t path[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
        return std::wstring(path);
    }
    return L".";
}

inline bool DirExists(const std::wstring& dir) {
    DWORD attrs = GetFileAttributesW(dir.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

inline std::wstring GetAppLockerRootDir() {
    std::wstring base = GetAppDataPath();
    std::wstring preferred = base + L"\\PeaceVault";
    std::wstring legacy = base + L"\\AppLocker";
    if (DirExists(preferred)) return preferred;
    if (DirExists(legacy)) return legacy;
    return preferred;
}

inline std::wstring GetIntrudersDir() {
    return GetAppLockerRootDir() + L"\\Intruders";
}

inline bool EnsureDir(const std::wstring& dir) {
    if (CreateDirectoryW(dir.c_str(), nullptr)) {
        return true;
    }
    return GetLastError() == ERROR_ALREADY_EXISTS;
}
