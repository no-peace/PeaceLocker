#include "common.h"
#include "config.h"
#include "monitor.h"
#include "gui.h"
#include "tray.h"
#include "controller.h"
#include "splash.h"
#include <windows.h>
#include <objbase.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <cwctype>
#include <aclapi.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shlwapi.lib")

static HINSTANCE g_hInst{};
static bool g_overlayActive = false;
static UINT WM_TASKBARCREATED = 0;
static bool g_isExiting = false;

static const wchar_t* kMutexMain = L"PeaceVault_Main_9A3B";
static const wchar_t* kMutexWD   = L"PeaceVault_WD_9A3B";
static const wchar_t* kEventExit = L"PeaceVault_CleanExit";

struct LaunchArgs {
    bool watchdog = false;
    bool silent = false;
    std::wstring watchdogTarget;
    std::wstring protectPath;
};

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

static std::wstring NormalizePath(const std::wstring& in) {
    if (in.empty()) return in;
    wchar_t full[MAX_PATH]{};
    DWORD n = GetFullPathNameW(in.c_str(), MAX_PATH, full, nullptr);
    if (n > 0 && n < MAX_PATH) return full;
    return in;
}

static bool AddBlockedUnique(const BlockEntry& entry) {
    auto rules = GetBlocked();
    for (const auto& r : rules) {
        if (r.type == entry.type && r.value == entry.value) return false;
    }
    AddBlocked(entry);
    return true;
}

static bool AddProtectedPathRule(const std::wstring& rawPath, std::wstring& outLabel) {
    std::wstring path = NormalizePath(rawPath);
    if (path.empty()) return false;

    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        std::wstring value = ToLowerW(path);
        if (!value.empty() && value.back() != L'\\') value += L'\\';
        outLabel = FolderName(path);
        return AddBlockedUnique({ L"folder", value, outLabel });
    }

    outLabel = FileBaseName(path);
    return AddBlockedUnique({ DetectType(path), ToLowerW(path), outLabel });
}


static LaunchArgs ParseLaunchArgs() {
    LaunchArgs args{};
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return args;

    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--watchdog") == 0) {
            args.watchdog = true;
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                args.watchdogTarget = argv[++i];
            }
        } else if (_wcsicmp(argv[i], L"--protect") == 0) {
            if (i + 1 < argc) {
                args.protectPath = argv[++i];
            }
        } else if (_wcsicmp(argv[i], L"--silent") == 0) {
            args.silent = true;
        }
    }
    LocalFree(argv);
    return args;
}

static void ProtectProcess() {
    HANDLE hProcess = GetCurrentProcess();
    PACL pOldDACL = nullptr, pNewDACL = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;

    if (GetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pOldDACL, nullptr, &pSD) != ERROR_SUCCESS) return;

    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryoneSID = nullptr;
    if (AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
        EXPLICIT_ACCESS_W ea{};
        ea.grfAccessPermissions = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | WRITE_DAC | WRITE_OWNER;
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = (LPWSTR)pEveryoneSID;

        if (SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL) == ERROR_SUCCESS) {
            SetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewDACL, nullptr);
            LocalFree(pNewDACL);
        }
        FreeSid(pEveryoneSID);
    }
    LocalFree(pSD);
}

static void RunWatchdog(const std::wstring& targetExe) {
    UniqueHandle wdM(CreateMutexW(nullptr, TRUE, kMutexWD));
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        return;
    }

    std::wstring exeToRestart = targetExe;
    if (exeToRestart.empty()) {
        wchar_t self[MAX_PATH]{};
        GetModuleFileNameW(nullptr, self, MAX_PATH);
        exeToRestart = self;
    }

    UniqueHandle hExitEvent(CreateEventW(nullptr, TRUE, FALSE, kEventExit));
    while (true) {
        if (WaitForSingleObject(hExitEvent.get(), 4000) == WAIT_OBJECT_0) break;

        UniqueHandle h(OpenMutexW(SYNCHRONIZE, FALSE, kMutexMain));
        if (!h.get()) {
            if (GetFileAttributesW(exeToRestart.c_str()) != INVALID_FILE_ATTRIBUTES) {
                std::wstring cmd = L"\"" + exeToRestart + L"\"";
                STARTUPINFOW si{ sizeof(si) };
                PROCESS_INFORMATION pi{};
                if (CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
                    UniqueHandle hProc(pi.hProcess);
                    UniqueHandle hThread(pi.hThread);
                }
            }
            Sleep(6000);
        }
    }
}

static void SpawnWatchdog() {
    UniqueHandle h(OpenMutexW(SYNCHRONIZE, FALSE, kMutexWD));
    if (h) {
        return;
    }

    wchar_t exe[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring realExe = exe;

    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring wdDir = std::wstring(tmp) + L"PeaceVaultGuard";
    CreateDirectoryW(wdDir.c_str(), nullptr);
    std::wstring wdExe = wdDir + L"\\PeaceVaultGuard.exe";
    if (!CopyFileW(realExe.c_str(), wdExe.c_str(), FALSE)) {
        wdExe = realExe;
    }

    std::wstring cmd = L"\"" + wdExe + L"\" --watchdog \"" + realExe + L"\"";
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        UniqueHandle hProc(pi.hProcess);
        UniqueHandle hThread(pi.hThread);
    }
}

static bool NotifyRunningInstance(const std::wstring& protectPath) {
    HWND host = FindWindowW(APP_HOST_CLASS, nullptr);
    if (!host) return false;

    PostMessageW(host, WM_APP_SHOW_DASHBOARD, 0, 0);
    if (!protectPath.empty()) {
        COPYDATASTRUCT cds{};
        cds.dwData = PV_COPYDATA_PROTECT_PATH;
        cds.cbData = static_cast<DWORD>((protectPath.size() + 1) * sizeof(wchar_t));
        cds.lpData = const_cast<wchar_t*>(protectPath.c_str());
        DWORD_PTR ignored = 0;
        SendMessageTimeoutW(host, WM_COPYDATA, 0, (LPARAM)&cds, SMTO_ABORTIFHUNG, 1500, &ignored);
    }
    return true;
}

static LRESULT CALLBACK HostProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_TASKBARCREATED && WM_TASKBARCREATED != 0) {
        InitTray(hwnd, g_hInst);
        return 0;
    }

    switch (msg) {
    case WM_APP_BLOCKED:
        if (!g_overlayActive) {
            g_overlayActive = true;
            ShowPinOverlay(g_hInst, hwnd);
            g_overlayActive = false;
        }
        return 0;

    case WM_APP_SHOW_DASHBOARD:
        ShowDashboard(g_hInst, hwnd);
        return 0;

    case WM_COPYDATA: {
        auto* cds = reinterpret_cast<COPYDATASTRUCT*>(lp);
        if (cds && cds->dwData == PV_COPYDATA_VERIFY_PIN && cds->lpData && cds->cbData >= (int)sizeof(wchar_t)) {
            if ((cds->cbData % sizeof(wchar_t)) != 0 || cds->cbData > 256 * (int)sizeof(wchar_t)) {
                return FALSE;
            }
            size_t chars = static_cast<size_t>(cds->cbData / sizeof(wchar_t));
            std::wstring pin(reinterpret_cast<const wchar_t*>(cds->lpData), chars);
            if (!pin.empty() && pin.back() == L'\0') pin.pop_back();
            bool ok = !pin.empty() && VerifyPin(W2U(pin));
            if (!pin.empty()) SecureZeroMemory(&pin[0], pin.size() * sizeof(wchar_t));
            return ok ? TRUE : FALSE;
        }

        if (cds && cds->dwData == PV_COPYDATA_PROTECT_PATH && cds->lpData && cds->cbData >= (int)sizeof(wchar_t)) {
            if ((cds->cbData % sizeof(wchar_t)) != 0 || cds->cbData > 16 * MAX_PATH * (int)sizeof(wchar_t)) {
                return FALSE;
            }
            size_t chars = static_cast<size_t>(cds->cbData / sizeof(wchar_t));
            std::wstring path(reinterpret_cast<const wchar_t*>(cds->lpData), chars);
            if (!path.empty() && path.back() == L'\0') path.pop_back();
            std::wstring label;
            if (!path.empty() && AddProtectedPathRule(path, label)) {
                std::wstring msgText = L"Protected from Explorer: " + label;
                ShowThemedAlert(g_hInst, hwnd, L"Rule Added", msgText.c_str(), false);
            }
            ShowDashboard(g_hInst, hwnd);
            return TRUE;
        }
        break;
    }

    case WM_APP_TRAY: {
        UINT ev = LOWORD(lp);
        // Using NOTIFYICON_VERSION_4 events to avoid double triggering.
        if (ev == NIN_SELECT || ev == NIN_KEYSELECT || ev == WM_LBUTTONDBLCLK) {
            // Left click or Enter: prompt for PIN and show dashboard.
            if (PromptForLaunchPin(g_hInst, hwnd)) {
                ShowDashboard(g_hInst, hwnd);
            }
        } else if (ev == WM_CONTEXTMENU) {
            // Right click or Apps key: show the tray menu.
            ShowTrayMenu(hwnd);
        }
        return 0;
    }

    case WM_COMMAND:
        HandleTrayCommand(hwnd, g_hInst, LOWORD(wp), g_isExiting, kEventExit);
        return 0;

    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == SC_CLOSE) return 0;
        break;

    case WM_CLOSE:
        return 0;

    case WM_DESTROY:
        if (!g_isExiting) return 0;
        StopMonitor();
        CleanupTray(hwnd);
        CleanupOverlay();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int) {
    ProtectProcess();
    g_hInst = hInst;
    WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");
    LaunchArgs args = ParseLaunchArgs();

    if (args.watchdog) {
        RunWatchdog(args.watchdogTarget);
        return 0;
    }

    UniqueHandle mainMtx(CreateMutexW(nullptr, TRUE, kMutexMain));
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (!NotifyRunningInstance(args.protectPath)) {
            ShowThemedAlert(hInst, nullptr, L"Already Running",
                L"Peace's Vault is already running, but the dashboard window was not found.", true);
        }
        return 0;
    }

    ShowStartupSplash(hInst);

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);
    CoInitialize(nullptr);
    InitConfig();

    if (IsFirstRun()) {
        std::string pin = ShowSetupDialog(hInst, nullptr);
        if (pin.empty()) {
            ShowThemedAlert(hInst, nullptr, L"PIN Required",
                L"A PIN is required. Peace's Vault will exit.", true);
            CoUninitialize();
            return 1;
        }
        SetPin(pin);
    } else if (!args.silent && !PromptForLaunchPin(hInst, nullptr)) {
        CoUninitialize();
        return 1;
    }

    std::string recovery = EnsureRecoveryCode();
    if (!recovery.empty()) {
        std::wstring msg = L"Save this recovery code in a safe place:\n\n";
        msg += U2W(recovery);
        msg += L"\n\nYou can use it to reset your PIN.";
        ShowThemedAlert(hInst, nullptr, L"Recovery Code", msg.c_str(), false);
    }

    WNDCLASSEXW wc{ sizeof(wc) };
    wc.lpfnWndProc = HostProc;
    wc.hInstance = hInst;
    wc.lpszClassName = APP_HOST_CLASS;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, APP_HOST_CLASS, APP_NAME_L, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 420, 320, nullptr, nullptr, hInst, nullptr);
    if (!hwnd) {
        CoUninitialize();
        return 1;
    }
    ShowWindow(hwnd, SW_HIDE);

    ChangeWindowMessageFilterEx(hwnd, WM_TASKBARCREATED, MSGFLT_ALLOW, nullptr);
    ChangeWindowMessageFilterEx(hwnd, WM_APP_TRAY, MSGFLT_ALLOW, nullptr);
    ChangeWindowMessageFilterEx(hwnd, WM_COPYDATA, MSGFLT_ALLOW, nullptr);

    InitTray(hwnd, hInst);
    StartMonitor(hwnd);

    // Ensure auto-start is properly set on each launch
    if (IsAutoStartEnabled()) {
        SetAutoStart(true);
    }
    if (IsShellIntegrationEnabled()) {
        SetShellIntegrationEnabled(true);
    }

    SpawnWatchdog();

    if (!args.protectPath.empty()) {
        std::wstring label;
        if (AddProtectedPathRule(args.protectPath, label)) {
            std::wstring msg = L"Protected from Explorer: " + label;
            ShowThemedAlert(hInst, hwnd, L"Rule Added", msg.c_str(), false);
        }
    }
    
    if (!args.silent) {
        ShowDashboard(hInst, hwnd);
    }

    MSG msg{};
    while (true) {
        BOOL bRet = GetMessageW(&msg, nullptr, 0, 0);
        if (bRet == 0) {
            if (!g_isExiting) continue;
            break;
        }
        if (bRet == -1) break;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CoUninitialize();
    return (int)msg.wParam;
}
