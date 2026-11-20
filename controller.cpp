#include "controller.h"
#include "common.h"
#include "config.h"
#include "gui.h"
#include "path_utils.h"
#include <windows.h>
#include <shellapi.h>
#include <commdlg.h>
#include <shlobj.h>
#include <objbase.h>
#include <string>

static std::wstring PickFile(HWND hwnd, const wchar_t* filter, const wchar_t* title) {
    wchar_t buf[MAX_PATH]{};
    OPENFILENAMEW ofn{ sizeof(ofn) };
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = buf;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    return GetOpenFileNameW(&ofn) ? std::wstring(buf) : L"";
}

// Improved folder picker that stays on top of parent window
static std::wstring PickFolder(HWND hwnd) {
    std::wstring result;

    // Use IFileDialog (Vista+) for better UI and proper parent window handling
    IFileDialog* pfd = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pfd));

    if (SUCCEEDED(hr) && pfd) {
        // Set options to pick folders only
        DWORD dwOptions;
        if (SUCCEEDED(pfd->GetOptions(&dwOptions))) {
            pfd->SetOptions(dwOptions | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
        }

        // Set title
        pfd->SetTitle(L"Select a folder to block");

        // Set parent window to ensure proper z-order
        if (hwnd) {
            pfd->Show(hwnd);
        } else {
            pfd->Show(nullptr);
        }

        // Get the result
        IShellItem* psi = nullptr;
        if (SUCCEEDED(pfd->GetResult(&psi))) {
            PWSTR pszPath = nullptr;
            if (SUCCEEDED(psi->GetDisplayName(SIGDN_FILESYSPATH, &pszPath))) {
                result = pszPath;
                CoTaskMemFree(pszPath);
            }
            psi->Release();
        }
        pfd->Release();
    } else {
        // Fallback to old SHBrowseForFolderW if IFileDialog fails
        wchar_t path[MAX_PATH]{};
        BROWSEINFOW bi{};
        bi.hwndOwner = hwnd;
        bi.lpszTitle = L"Select a folder to block";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_SHAREABLE;

        // Ensure parent window is properly set and visible
        if (hwnd) {
            SetForegroundWindow(hwnd);
            BringWindowToTop(hwnd);
        }

        PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
        if (pidl) {
            if (SHGetPathFromIDListW(pidl, path)) {
                result = path;
            }
            CoTaskMemFree(pidl);
        }
    }

    return result;
}

static std::wstring FileBaseName(const std::wstring& path) {
    size_t pos = path.rfind(L'\\');
    return pos != std::wstring::npos ? path.substr(pos + 1) : path;
}

static std::wstring FolderName(const std::wstring& path) {
    std::wstring s = path;
    while (!s.empty() && (s.back() == L'\\' || s.back() == L'/')) {
        s.pop_back();
    }
    size_t pos = s.rfind(L'\\');
    return pos != std::wstring::npos ? s.substr(pos + 1) : s;
}

static std::wstring DetectType(const std::wstring& path) {
    auto dot = path.rfind(L'.');
    if (dot == std::wstring::npos || dot + 1 >= path.size()) return L"file";
    std::wstring ext = path.substr(dot + 1);
    for (auto& c : ext) c = (wchar_t)towlower(c);
    if (ext == L"png" || ext == L"jpg" || ext == L"jpeg" || ext == L"bmp" || ext == L"gif" ||
        ext == L"webp" || ext == L"tiff" || ext == L"ico" || ext == L"svg") return L"image";
    if (ext == L"wav" || ext == L"mp3" || ext == L"flac" || ext == L"aac" || ext == L"ogg" ||
        ext == L"wma" || ext == L"m4a" || ext == L"opus") return L"audio";
    if (ext == L"mp4" || ext == L"avi" || ext == L"mkv" || ext == L"mov" || ext == L"wmv" ||
        ext == L"webm" || ext == L"flv") return L"video";
    if (ext == L"doc" || ext == L"docx" || ext == L"pdf" || ext == L"txt" || ext == L"xls" ||
        ext == L"xlsx" || ext == L"ppt" || ext == L"pptx" || ext == L"odt") return L"document";
    if (ext == L"exe" || ext == L"msi" || ext == L"bat" || ext == L"cmd") return L"app";
    return L"file";
}

static void SignalCleanExit(const wchar_t* exitEventName) {
    UniqueHandle hEv(CreateEventW(nullptr, TRUE, FALSE, exitEventName));
    if (hEv) {
        SetEvent(hEv.get());
    }
}

void ShowTrayMenu(HWND hwnd) {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, APP_NAME_L);
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_OPEN_DASHBOARD, L"Open Dashboard");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_ADD_FILE, L"Add Item...");
    AppendMenuW(menu, MF_STRING, IDM_ADD_APP, L"Block App By Name...");
    AppendMenuW(menu, MF_STRING, IDM_ADD_FOLDER, L"Block Folder...");
    AppendMenuW(menu, MF_STRING, IDM_ADD_URL, L"Block Website...");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_SET_WEBHOOK, L"Discord Alerts (Webhook)...");
    AppendMenuW(menu, MF_STRING, IDM_OPEN_INTRUDERS, L"Open Intruders Folder...");
    AppendMenuW(menu, MF_STRING, IDM_MANAGE, L"Manage Blocked Items...");
    AppendMenuW(menu, MF_STRING, IDM_CHANGE_PIN, L"Change PIN...");
    AppendMenuW(menu, MF_STRING, IDM_RESET_PIN, L"Reset PIN (Recovery Code)...");
    AppendMenuW(menu, MF_STRING, IDM_REMOVE_PWD, L"Remove Password...");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | (IsAutoStartEnabled() ? MF_CHECKED : 0), IDM_TOGGLE_AUTO, L"Start with Windows");
    AppendMenuW(menu, MF_STRING | (IsShellIntegrationEnabled() ? MF_CHECKED : 0), IDM_TOGGLE_SHELL, L"Explorer Right-Click Protect");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, IDM_EXIT, L"Exit vault (PIN)");

    SetForegroundWindow(hwnd);
    POINT pt{};
    GetCursorPos(&pt);
    TrackPopupMenu(menu, TPM_BOTTOMALIGN | TPM_RIGHTALIGN, pt.x, pt.y, 0, hwnd, nullptr);
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

bool HandleTrayCommand(HWND hwnd, HINSTANCE hInst, UINT commandId, bool& isExiting, const wchar_t* exitEventName) {
    switch (commandId) {
    case IDM_OPEN_DASHBOARD:
        if (PromptForLaunchPin(hInst, hwnd)) {
            ShowDashboard(hInst, hwnd);
        }
        return true;
    case IDM_ADD_FILE: {
        auto path = PickFile(hwnd,
            L"All Supported\0*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.webp;*.tiff;*.wav;*.mp3;*.flac;*.aac;*.ogg;*.wma;*.m4a;*.mp4;*.avi;*.mkv;*.mov;*.doc;*.docx;*.pdf;*.txt;*.xls;*.xlsx;*.ppt;*.pptx;*.exe\0"
            L"Images\0*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.webp;*.tiff\0"
            L"Audio\0*.wav;*.mp3;*.flac;*.aac;*.ogg;*.wma;*.m4a\0"
            L"Video\0*.mp4;*.avi;*.mkv;*.mov;*.wmv;*.webm\0"
            L"Documents\0*.doc;*.docx;*.pdf;*.txt;*.xls;*.xlsx;*.ppt;*.pptx\0"
            L"All Files\0*.*\0",
            L"Select a file to block");
        if (!path.empty()) {
            std::wstring type = DetectType(path);
            AddBlocked({ type, ToLowerW(path), FileBaseName(path) });
            std::wstring msg = L"Blocked as [" + type + L"]: " + FileBaseName(path);
            ShowThemedAlert(hInst, hwnd, L"Blocked Item Added", msg.c_str(), false);
        }
        return true;
    }
    case IDM_ADD_APP: {
        auto value = ShowTextPromptDialog(hInst, hwnd, L"Block An App", L"Enter the .exe name (for example: notepad.exe):");
        if (!value.empty()) {
            std::wstring normalized = ToLowerW(value);
            if (normalized.size() < 4 || normalized.substr(normalized.size() - 4) != L".exe") {
                normalized += L".exe";
            }
            AddBlocked({ L"app", normalized, value });
            ShowThemedAlert(hInst, hwnd, L"App Rule Added", (L"Now blocking app: " + value).c_str(), false);
        }
        return true;
    }
    case IDM_ADD_FOLDER: {
        // Ensure COM is initialized for this thread
        HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        auto path = PickFolder(hwnd);

        if (SUCCEEDED(hr)) {
            CoUninitialize();
        }

        if (!path.empty()) {
            std::wstring normalized = ToLowerW(path);
            if (!normalized.empty() && normalized.back() != L'\\') normalized += L'\\';
            AddBlocked({ L"folder", normalized, FolderName(path) });
            ShowThemedAlert(hInst, hwnd, L"Folder Rule Added", (L"Now blocking folder: " + FolderName(path)).c_str(), false);
        }
        return true;
    }
    case IDM_ADD_URL: {
        auto value = ShowTextPromptDialog(hInst, hwnd, L"Block A Website", L"Enter domain (for example: facebook.com):");
        if (!value.empty()) {
            std::wstring domain = ToLowerW(value);
            for (auto pfx : { L"https://", L"http://", L"www." }) {
                std::wstring prefix(pfx);
                if (domain.substr(0, prefix.size()) == prefix) {
                    domain = domain.substr(prefix.size());
                }
            }
            auto slash = domain.find(L'/');
            if (slash != std::wstring::npos) domain = domain.substr(0, slash);
            AddBlocked({ L"url", domain, domain });
            ShowThemedAlert(hInst, hwnd, L"Website Rule Added", (L"Now blocking: " + domain).c_str(), false);
        }
        return true;
    }
    case IDM_MANAGE:
        ShowManageDialog(hInst, hwnd);
        return true;
    case IDM_SET_WEBHOOK:
        ShowWebhookDialog(hInst, hwnd);
        return true;
    case IDM_OPEN_INTRUDERS:
        if (ShowExitPinDialog(hInst, hwnd)) {
            std::wstring rootDir = GetAppLockerRootDir();
            std::wstring intrudersDir = GetIntrudersDir();
            EnsureDir(rootDir);
            EnsureDir(intrudersDir);
            ShellExecuteW(nullptr, L"explore", intrudersDir.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }
        return true;
    case IDM_CHANGE_PIN:
        ShowChangePinDialog(hInst, hwnd);
        return true;
    case IDM_RESET_PIN:
        ShowResetPinDialog(hInst, hwnd);
        return true;
    case IDM_REMOVE_PWD: {
        if (!ShowExitPinDialog(hInst, hwnd)) return true;
        if (ShowThemedConfirm(hInst, hwnd, L"Remove Password",
            L"This will remove your PIN and unblock ALL items.\n\nAre you sure?")) {
            ClearAllData();
            ShowThemedAlert(hInst, hwnd,
                L"Password Removed",
                L"Password removed and all items unblocked.\n\nPeace's Vault will now exit. Run it again to set a new PIN.",
                false);
            isExiting = true;
            SignalCleanExit(exitEventName);
            DestroyWindow(hwnd);
        }
        return true;
    }
    case IDM_TOGGLE_AUTO:
        SetAutoStart(!IsAutoStartEnabled());
        return true;
    case IDM_TOGGLE_SHELL:
        SetShellIntegrationEnabled(!IsShellIntegrationEnabled());
        return true;
    case IDM_EXIT:
        if (ShowExitPinDialog(hInst, hwnd)) {
            // Signal the watchdog FIRST to prevent restarts
            SignalCleanExit(exitEventName);
            isExiting = true;
            
            // Give watchdog a moment to see the signal before closing mutex
            Sleep(100);
            
            DestroyWindow(hwnd);
        }
        return true;
    default:
        return false;
    }
}
