import sys

base_path = r'c:\Users\Nipun\Desktop\HoHo Hub\Pranks\V8\\'

try:
    with open(base_path + 'config.h', 'r', encoding='utf-8') as f:
        text = f.read()
    if 'IsLogAllEnabled' not in text:
        text = text.replace('bool IsShellIntegrationEnabled();', 'bool IsShellIntegrationEnabled();\nbool IsLogAllEnabled();\nvoid SetLogAllEnabled(bool enabled);')
        with open(base_path + 'config.h', 'w', encoding='utf-8') as f:
            f.write(text)

    with open(base_path + 'config.cpp', 'r', encoding='utf-8') as f:
        text = f.read()
    if 'g_logAll' not in text:
        text = text.replace('static bool g_shellIntegration = true;', 'static bool g_shellIntegration = true;\nstatic bool g_logAll = false;')
        text = text.replace('    g_shellIntegration = true;', '    g_shellIntegration = true;\n    g_logAll = false;')
        text = text.replace('else if (key == "shell") g_shellIntegration = (value != "0");', 'else if (key == "shell") g_shellIntegration = (value != "0");\n        else if (key == "logall") g_logAll = (value == "1");')
        text = text.replace('out << "shell=" << (g_shellIntegration ? "1" : "0") << "\\n";', 'out << "shell=" << (g_shellIntegration ? "1" : "0") << "\\n";\n    out << "logall=" << (g_logAll ? "1" : "0") << "\\n";')

        funcs = """
bool IsLogAllEnabled() {
    std::lock_guard<std::mutex> lock(g_mtx);
    return g_logAll;
}

void SetLogAllEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(g_mtx);
    g_logAll = enabled;
    Save();
}

std::string GetWebhookUrl() {"""
        text = text.replace('std::string GetWebhookUrl() {', funcs)
        with open(base_path + 'config.cpp', 'w', encoding='utf-8') as f:
            f.write(text)

    with open(base_path + 'gui.cpp', 'r', encoding='utf-8') as f:
        text = f.read()
    if 'IDC_DASH_LOGALL' not in text:
        text = text.replace('constexpr int IDC_DASH_EXIT = 7114;', 'constexpr int IDC_DASH_EXIT = 7114;\nconstexpr int IDC_DASH_LOGALL = 7115;')
        text = text.replace('    HWND hShell{};', '    HWND hShell{};\n    HWND hLogAll{};')
        text = text.replace('    SetWindowTextW(ctx->hShell, shellLabel.c_str());', '    SetWindowTextW(ctx->hShell, shellLabel.c_str());\n\n    std::wstring logAllLabel = IsLogAllEnabled() ? L"Log Opened Items: ON" : L"Log Opened Items: OFF";\n    if (ctx->hLogAll) SetWindowTextW(ctx->hLogAll, logAllLabel.c_str());')
        text = text.replace('ctx->hShell = makeBtn(IDC_DASH_SHELL, L"Explorer Protect: ON", bx, by); by += 40;', 'ctx->hShell = makeBtn(IDC_DASH_SHELL, L"Explorer Protect: ON", bx, by); by += 40;\n        ctx->hLogAll = makeBtn(IDC_DASH_LOGALL, L"Log Opened Items: OFF", bx, by); by += 40;')
        cmd_logall = """        case IDC_DASH_LOGALL:
            SetLogAllEnabled(!IsLogAllEnabled());
            RefreshDashboardList(ctx);
            break;
        case IDC_DASH_CLOSE:"""
        text = text.replace('        case IDC_DASH_CLOSE:', cmd_logall)
        with open(base_path + 'gui.cpp', 'w', encoding='utf-8') as f:
            f.write(text)

    with open(base_path + 'capture.h', 'r', encoding='utf-8') as f:
        text = f.read()
    if 'SendDiscordWebhookTextLogAsync' not in text:
        text = text.replace('void CaptureIntruderPhotoAsync(const std::wstring& attemptedItem);', 'void CaptureIntruderPhotoAsync(const std::wstring& attemptedItem);\nvoid SendDiscordWebhookTextLogAsync(const std::wstring& itemName);')
        with open(base_path + 'capture.h', 'w', encoding='utf-8') as f:
            f.write(text)

    with open(base_path + 'capture.cpp', 'r', encoding='utf-8') as f:
        text = f.read()
        
    func = r"""
void SendDiscordWebhookTextLogAsync(const std::wstring& itemName) {
    std::wstring nameCopy = itemName;
    std::thread([nameCopy]() {
        std::string urlStr = GetWebhookUrl();
        if (urlStr.empty()) return;

        std::wstring wUrl = U2W(urlStr);
        URL_COMPONENTS urlComp{ sizeof(urlComp) };
        wchar_t hostName[256]; urlComp.lpszHostName = hostName; urlComp.dwHostNameLength = 256;
        wchar_t urlPath[1024]; urlComp.lpszUrlPath = urlPath; urlComp.dwUrlPathLength = 1024;

        if (!WinHttpCrackUrl(wUrl.c_str(), 0, 0, &urlComp)) return;

        UniqueWinHttpHandle hSession(WinHttpOpen(L"PeaceVault", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
        if (!hSession) return;

        UniqueWinHttpHandle hConnect(WinHttpConnect(hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0));
        if (!hConnect) return;

        UniqueWinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"POST", urlComp.lpszUrlPath, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0));
        if (!hRequest) return;

        time_t now = time(nullptr);
        struct tm ti; localtime_s(&ti, &now);
        char timeStr[128]; strftime(timeStr, 128, "%Y-%m-%d %H:%M:%S", &ti);

        std::string payload_json = "{\"content\": \":eye: **Item Opened**\\n:clock1: Time: " + std::string(timeStr) + "\\n:mag: Item: `" + W2U(nameCopy) + "`\"}";

        std::wstring contentType = L"Content-Type: application/json";

        if (WinHttpSendRequest(hRequest.get(), contentType.c_str(), (DWORD)-1, (LPVOID)payload_json.data(), (DWORD)payload_json.size(), (DWORD)payload_json.size(), 0)) {
            WinHttpReceiveResponse(hRequest.get(), nullptr);
        }
    }).detach();
}
"""
    if 'SendDiscordWebhookTextLogAsync' not in text:
        text = text + func
        with open(base_path + 'capture.cpp', 'w', encoding='utf-8') as f:
            f.write(text)

    with open(base_path + 'monitor.cpp', 'r', encoding='utf-8') as f:
        text = f.read()

    if 'ForegroundMonLoop' not in text:
        text = text.replace('#include "monitor.h"', '#include "monitor.h"\n#include "capture.h"')
        text = text.replace('static std::thread       g_folderThread;', 'static std::thread       g_folderThread;\nstatic std::thread       g_fgThread;')

        fg_loop = r"""
static void ForegroundMonLoop() {
    HWND prevFg = nullptr;
    while (g_running) {
        Sleep(1000);
        if (!IsLogAllEnabled()) continue;
        
        HWND fg = GetForegroundWindow();
        if (fg && fg != prevFg) {
            prevFg = fg;
            wchar_t title[1024]{};
            GetWindowTextW(fg, title, 1023);
            std::wstring tl = title;
            if (!tl.empty() && tl != L"Task Switching" && tl != APP_NAME_L && tl != L"Task View" && tl != L"Program Manager") {
                DWORD pid = 0;
                GetWindowThreadProcessId(fg, &pid);
                UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
                std::wstring procName = L"Unknown";
                if (snap.get() != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32W pe{sizeof(pe)};
                    if (Process32FirstW(snap.get(), &pe)) {
                        do {
                            if (pe.th32ProcessID == pid) {
                                procName = pe.szExeFile;
                                break;
                            }
                        } while (Process32NextW(snap.get(), &pe));
                    }
                }
                
                std::wstring logText = procName + L" - " + tl;
                SendDiscordWebhookTextLogAsync(logText);
            }
        }
    }
}

void StartMonitor(HWND hwnd) {"""
        text = text.replace('void StartMonitor(HWND hwnd) {', fg_loop)
        text = text.replace('g_folderThread = std::thread(FolderMonLoop);', 'g_folderThread = std::thread(FolderMonLoop);\n    g_fgThread = std::thread(ForegroundMonLoop);')
        text = text.replace('if (g_folderThread.joinable()) g_folderThread.join();', 'if (g_folderThread.joinable()) g_folderThread.join();\n    if (g_fgThread.joinable()) g_fgThread.join();')

        with open(base_path + 'monitor.cpp', 'w', encoding='utf-8') as f:
            f.write(text)

    print("SUCCESS")
except Exception as e:
    print("FAILED", e)
