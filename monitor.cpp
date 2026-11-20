#include "monitor.h"
#include "capture.h"
#include "config.h"
#include "common.h"
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <shellapi.h>
#include <set>
#include <map>
#include <queue>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <uiautomation.h>
#include <shobjidl.h>
#include <exdisp.h>
#include <shlwapi.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

typedef LONG(NTAPI* NtSuspProc)(HANDLE);
typedef LONG(NTAPI* NtResuProc)(HANDLE);
typedef NTSTATUS(NTAPI* NtQIP_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
static NtSuspProc g_susp{};
static NtResuProc g_resu{};
static NtQIP_t    g_NtQIP{};

static HWND              g_hwnd{};
static std::atomic<bool> g_running{false};
static std::thread       g_procThread;
static std::thread       g_urlThread;
static std::thread       g_folderThread;
static std::thread       g_fgThread;

static std::mutex        g_qMtx;
static std::queue<QueuedBlock> g_queue;
static std::mutex        g_inQMtx;
static std::set<DWORD>   g_inQueue;

static std::mutex        g_unlockMtx;
static std::map<std::wstring, ULONGLONG> g_unlocked;

static void RefreshUnlock(const std::wstring& label) {
    std::lock_guard<std::mutex> l(g_unlockMtx);
    if (g_unlocked.count(label)) g_unlocked[label] = GetTickCount64();
}

static bool IsTempUnlocked(const std::wstring& label) {
    std::lock_guard<std::mutex> l(g_unlockMtx);
    auto it = g_unlocked.find(label);
    if (it == g_unlocked.end()) return false;
    if (GetTickCount64() - it->second > 2000) { g_unlocked.erase(it); return false; }
    return true;
}

static std::wstring GetProcessCommandLine(DWORD pid) {
    UniqueHandle h(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!h) h.reset(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!h) return L"";
    std::wstring result;
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG rlen = 0;
    if (g_NtQIP && g_NtQIP(h.get(), ProcessBasicInformation, &pbi, sizeof(pbi), &rlen) >= 0 && pbi.PebBaseAddress) {
        PEB peb{};
        if (ReadProcessMemory(h.get(), pbi.PebBaseAddress, &peb, sizeof(peb), nullptr) && peb.ProcessParameters) {
            RTL_USER_PROCESS_PARAMETERS params{};
            if (ReadProcessMemory(h.get(), peb.ProcessParameters, &params, sizeof(params), nullptr)) {
                USHORT len = params.CommandLine.Length;
                if (len > 0 && len < 32768 && params.CommandLine.Buffer) {
                    std::wstring buf(len / sizeof(wchar_t), 0);
                    if (ReadProcessMemory(h.get(), params.CommandLine.Buffer, buf.data(), len, nullptr))
                        result = buf;
                }
            }
        }
    }
    return ToLowerW(result);
}

struct WinTitleCtx { DWORD pid; std::wstring combined; };

static BOOL CALLBACK EnumTitlesCb(HWND hwnd, LPARAM lp) {
    auto* ctx = (WinTitleCtx*)lp;
    DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
    if (pid != ctx->pid) return TRUE;
    wchar_t title[1024]{}; GetWindowTextW(hwnd, title, 1023);
    if (title[0]) { ctx->combined += L" "; ctx->combined += title; }
    return TRUE;
}

static std::wstring GetProcessWindowTitles(DWORD pid) {
    WinTitleCtx ctx{pid, L""};
    EnumWindows(EnumTitlesCb, (LPARAM)&ctx);
    return ToLowerW(ctx.combined);
}

static void EnqueueBlock(DWORD pid, const std::wstring& label, const std::wstring& type) {
    if (pid == GetCurrentProcessId()) return;
    { std::lock_guard<std::mutex> l(g_inQMtx); if (g_inQueue.count(pid)) return; g_inQueue.insert(pid); }
    UniqueHandle hProc(OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE, FALSE, pid));
    bool susp = false;
    if (hProc && type != L"url" && type != L"folder" && g_susp) susp = (g_susp(hProc.get()) >= 0);
    { std::lock_guard<std::mutex> l(g_qMtx); g_queue.push({pid, std::move(hProc), label, type, susp}); }
    PostMessageW(g_hwnd, WM_APP_BLOCKED, 0, 0);
    Log(L"Blocked: " + label + L" (type: " + type + L") PID: " + std::to_wstring(pid));
}

static std::wstring ExtractFileName(const std::wstring& path) {
    auto p = path.rfind(L'\\');
    if (p == std::wstring::npos) p = path.rfind(L'/');
    return p != std::wstring::npos ? path.substr(p + 1) : path;
}

static std::set<DWORD> GetVisiblePIDs() {
    std::set<DWORD> pids;
    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        if (IsWindowVisible(hwnd)) {
            DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
            ((std::set<DWORD>*)lp)->insert(pid);
        }
        return TRUE;
    }, (LPARAM)&pids);
    return pids;
}

static void ProcMonLoop() {
    std::set<DWORD> known;
    {
        UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (snap.get() != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{sizeof(pe)};
            if (Process32FirstW(snap.get(), &pe))
                do { known.insert(pe.th32ProcessID); } while (Process32NextW(snap.get(), &pe));
        }
    }
    while (g_running) {
        Sleep(150);
        auto blocks = GetBlocked();
        if (blocks.empty()) continue;

        std::vector<BlockEntry> appBlocks, fileBlocks, folderBlocks;
        for (auto& b : blocks) {
            if (b.type == L"url") continue;
            if (b.type == L"app") appBlocks.push_back(b);
            else if (b.type == L"folder") folderBlocks.push_back(b);
            else fileBlocks.push_back(b);
        }

        std::set<DWORD> visPids = GetVisiblePIDs();
        UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (snap.get() == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32W pe{sizeof(pe)};
        std::set<DWORD> current;

        if (Process32FirstW(snap.get(), &pe)) {
            do {
                DWORD pid = pe.th32ProcessID;
                current.insert(pid);
                if (pid == GetCurrentProcessId()) continue;
                bool in_queue = false;
                { std::lock_guard<std::mutex> l(g_inQMtx); in_queue = g_inQueue.count(pid); }

                known.insert(pid);
                std::wstring name = ToLowerW(pe.szExeFile);

                // 1) App blocks
                for (auto& b : appBlocks) {
                    std::wstring bval = b.value;
                    if (bval.size() < 4 || bval.substr(bval.size()-4) != L".exe") bval += L".exe";
                    if (name == bval) {
                        if (visPids.count(pid)) {
                            if (IsTempUnlocked(b.label)) RefreshUnlock(b.label);
                            else if (!in_queue) EnqueueBlock(pid, b.label, b.type);
                        }
                        goto next_proc;
                    }
                }

                if (!fileBlocks.empty() || !folderBlocks.empty()) {
                    std::wstring cmdline = GetProcessCommandLine(pid);
                    std::wstring titles = GetProcessWindowTitles(pid);
                    std::wstring combined = cmdline + L" " + titles;

                    if (!combined.empty()) {
                        for (auto& b : fileBlocks) {
                            std::wstring fname = ExtractFileName(b.value);
                            if (cmdline.find(b.value) != std::wstring::npos || (!fname.empty() && titles.find(fname) != std::wstring::npos)) {
                                if (visPids.count(pid)) {
                                    if (IsTempUnlocked(b.label)) RefreshUnlock(b.label);
                                    else if (!in_queue) EnqueueBlock(pid, b.label, b.type);
                                }
                                goto next_proc;
                            }
                        }
                        for (auto& b : folderBlocks) {
                            if (combined.find(b.value) != std::wstring::npos) {
                                if (visPids.count(pid)) {
                                    if (IsTempUnlocked(b.label)) RefreshUnlock(b.label);
                                    else if (!in_queue) EnqueueBlock(pid, b.label, b.type);
                                }
                                goto next_proc;
                            }
                        }
                    }
                }
                next_proc:;
            } while (Process32NextW(snap.get(), &pe));
        }
        for (auto it = known.begin(); it != known.end(); )
            current.count(*it) ? ++it : it = known.erase(it);
    }
}

struct FolderScanCtx {
    std::vector<BlockEntry> folderBlocks;
};

static BOOL CALLBACK EnumExplorerCb(HWND hwnd, LPARAM lp) {
    auto* ctx = (FolderScanCtx*)lp;
    if (!IsWindowVisible(hwnd)) return TRUE;
    DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
    bool in_queue = false;
    { std::lock_guard<std::mutex> l(g_inQMtx); in_queue = g_inQueue.count(pid); }

    wchar_t cls[256]{}; GetClassNameW(hwnd, cls, 255);
    std::wstring clsName = cls;
    if (clsName != L"CabinetWClass" && clsName != L"ExploreWClass") return TRUE;

    std::wstring realPath;
    IShellWindows* pSW = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_ShellWindows, nullptr, CLSCTX_ALL, IID_PPV_ARGS(&pSW)))) {
        long count = 0;
        if (SUCCEEDED(pSW->get_Count(&count))) {
            for (long i = 0; i < count; i++) {
                VARIANT v; VariantInit(&v); v.vt = VT_I4; v.lVal = i;
                IDispatch* pDisp = nullptr;
                if (SUCCEEDED(pSW->Item(v, &pDisp)) && pDisp) {
                    IWebBrowserApp* pApp = nullptr;
                    if (SUCCEEDED(pDisp->QueryInterface(IID_PPV_ARGS(&pApp)))) {
                        SHANDLE_PTR explorerHwnd = 0;
                        if (SUCCEEDED(pApp->get_HWND(&explorerHwnd)) && (HWND)explorerHwnd == hwnd) {
                            BSTR bstrUrl = nullptr;
                            if (SUCCEEDED(pApp->get_LocationURL(&bstrUrl)) && bstrUrl) {
                                wchar_t localPath[MAX_PATH];
                                DWORD localPathLen = MAX_PATH;
                                if (SUCCEEDED(PathCreateFromUrlW(bstrUrl, localPath, &localPathLen, 0))) {
                                    realPath = ToLowerW(localPath);
                                }
                                SysFreeString(bstrUrl);
                            }
                        }
                        pApp->Release();
                    }
                    pDisp->Release();
                }
                if (!realPath.empty()) break;
            }
        }
        pSW->Release();
    }

    if (realPath.empty()) {
        wchar_t title[1024]{}; GetWindowTextW(hwnd, title, 1023);
        realPath = ToLowerW(title);
        if (realPath.empty()) return TRUE;
    }
    
    if (!realPath.empty() && realPath.back() != L'\\') realPath += L'\\';

    for (auto& b : ctx->folderBlocks) {
        std::wstring lockedPath = b.value;
        if (!lockedPath.empty() && lockedPath.back() != L'\\') lockedPath += L'\\';
        
        bool isBlocked = false;
        if (realPath.substr(0, lockedPath.size()) == lockedPath) {
            isBlocked = true;
        } else {
            auto slash = lockedPath.rfind(L'\\', lockedPath.size() - 2);
            std::wstring folderName = (slash != std::wstring::npos) ? lockedPath.substr(slash + 1) : lockedPath;
            if (!folderName.empty() && folderName.back() == L'\\') folderName.pop_back();
            if (!folderName.empty() && realPath.find(folderName) != std::wstring::npos) {
                 isBlocked = true;
            }
        }

        if (isBlocked) {
            if (IsTempUnlocked(b.label)) {
                RefreshUnlock(b.label);
            } else if (!in_queue) {
                EnqueueBlock(pid, b.label, b.type);
            }
            return TRUE;
        }
    }
    return TRUE;
}

static void FolderMonLoop() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    while (g_running) {
        Sleep(500);
        auto blocks = GetBlocked();
        FolderScanCtx ctx;
        for (auto& b : blocks) if (b.type == L"folder") ctx.folderBlocks.push_back(b);
        if (ctx.folderBlocks.empty()) continue;
        EnumWindows(EnumExplorerCb, (LPARAM)&ctx);
    }
    CoUninitialize();
}

static const wchar_t* kBrowsers[] = {
    L"Brave.exe", L"firefox.exe", L"msedge.exe", L"opera.exe",
    L"brave.exe", L"vivaldi.exe", L"iexplore.exe", nullptr
};

struct UrlScanCtx {
    std::set<DWORD> browserPids;
    std::vector<BlockEntry> urlBlocks;
};

static IUIAutomation* g_pAutomation = nullptr;
static std::map<HWND, std::pair<std::wstring, std::wstring>> g_urlCache;

static std::wstring GetBrowserUrlUIA(HWND hwnd, const std::wstring& tl) {
    auto it = g_urlCache.find(hwnd);
    if (it != g_urlCache.end() && it->second.first == tl) {
        return it->second.second;
    }

    if (!g_pAutomation) {
        CoCreateInstance(__uuidof(CUIAutomation), nullptr, CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&g_pAutomation);
        if (!g_pAutomation) return L"";
    }
    
    IUIAutomationElement* pRoot = nullptr;
    if (FAILED(g_pAutomation->ElementFromHandle(hwnd, &pRoot)) || !pRoot) return L"";

    std::wstring foundUrl;
    
    // 1. Try Document focus first (usually the most reliable for current page)
    VARIANT varDoc; VariantInit(&varDoc); varDoc.vt = VT_I4; varDoc.lVal = UIA_DocumentControlTypeId;
    IUIAutomationCondition* pDocCond = nullptr;
    if (SUCCEEDED(g_pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId, varDoc, &pDocCond)) && pDocCond) {
        IUIAutomationElement* pDoc = nullptr;
        if (SUCCEEDED(pRoot->FindFirst(TreeScope_Descendants, pDocCond, &pDoc)) && pDoc) {
            VARIANT varVal; VariantInit(&varVal);
            if (SUCCEEDED(pDoc->GetCurrentPropertyValue(UIA_ValueValuePropertyId, &varVal)) && varVal.vt == VT_BSTR && varVal.bstrVal) {
                foundUrl = varVal.bstrVal;
            }
            VariantClear(&varVal);
            pDoc->Release();
        }
        pDocCond->Release();
    }
    
    // 2. If no document URL, search for the ADDRESS BAR (Edit control)
    if (foundUrl.empty()) {
        VARIANT varEdit; VariantInit(&varEdit); varEdit.vt = VT_I4; varEdit.lVal = UIA_EditControlTypeId;
        IUIAutomationCondition* pEditCond = nullptr;
        if (SUCCEEDED(g_pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId, varEdit, &pEditCond)) && pEditCond) {
            IUIAutomationElementArray* pList = nullptr;
            if (SUCCEEDED(pRoot->FindAll(TreeScope_Descendants, pEditCond, &pList)) && pList) {
                int count = 0; pList->get_Length(&count);
                std::wstring validUrl;
                bool isTyping = false;
                for (int i = 0; i < count; i++) {
                    IUIAutomationElement* pE = nullptr;
                    if (SUCCEEDED(pList->GetElement(i, &pE)) && pE) {
                        BSTR name = nullptr, cls = nullptr;
                        pE->get_CurrentName(&name);
                        pE->get_CurrentClassName(&cls);
                        std::wstring wsName = name ? name : L"";
                        std::wstring wsCls = cls ? cls : L"";
                        if (name) SysFreeString(name);
                        if (cls) SysFreeString(cls);

                        bool isAddr = (wsName.find(L"Address") != std::wstring::npos || 
                                       wsName.find(L"URL") != std::wstring::npos ||
                                       wsCls.find(L"Omnibox") != std::wstring::npos ||
                                       wsCls.find(L"Address") != std::wstring::npos);

                        if (isAddr) {
                            VARIANT varFocus; VariantInit(&varFocus);
                            if (SUCCEEDED(pE->GetCurrentPropertyValue(UIA_HasKeyboardFocusPropertyId, &varFocus)) && varFocus.vt == VT_BOOL && varFocus.boolVal == VARIANT_TRUE) {
                                isTyping = true;
                                VariantClear(&varFocus);
                                pE->Release();
                                break;
                            }
                            VariantClear(&varFocus);

                            if (validUrl.empty()) {
                                VARIANT varVal; VariantInit(&varVal);
                                if (SUCCEEDED(pE->GetCurrentPropertyValue(UIA_ValueValuePropertyId, &varVal)) && varVal.vt == VT_BSTR && varVal.bstrVal) {
                                    std::wstring val = varVal.bstrVal;
                                    if (!val.empty() && (val.find(L".") != std::wstring::npos || val.find(L"://") != std::wstring::npos)) {
                                        validUrl = val;
                                    }
                                }
                                VariantClear(&varVal);
                            }
                        }
                        pE->Release();
                    }
                }
                if (!isTyping) {
                    foundUrl = validUrl;
                }
                pList->Release();
            }
            pEditCond->Release();
        }
    }
    
    pRoot->Release();
    std::wstring result = ToLowerW(foundUrl);
    g_urlCache[hwnd] = {tl, result};
    return result;
}

static BOOL CALLBACK EnumWinCb(HWND hwnd, LPARAM lp) {
    auto* ctx = (UrlScanCtx*)lp;
    if (!IsWindowVisible(hwnd)) return TRUE;
    DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
    if (!ctx->browserPids.count(pid)) return TRUE;
    bool in_queue = false;
    { std::lock_guard<std::mutex> l(g_inQMtx); in_queue = g_inQueue.count(pid); }
    
    wchar_t title[1024]{}; GetWindowTextW(hwnd, title, 1023);
    std::wstring tl = ToLowerW(title);
    if (tl.empty()) return TRUE;
    
    std::wstring url = GetBrowserUrlUIA(hwnd, tl);
    
    for (auto& b : ctx->urlBlocks) {
        
        bool matched = false;
        
        // 1. Direct UIA Address Bar Match
        if (!url.empty() && url.find(b.value) != std::wstring::npos) {
            matched = true;
        }
        
        if (!matched) {
            std::wstring target = b.value;
            auto dot = target.rfind(L'.');
            if (dot != std::wstring::npos) target = target.substr(0, dot); // facebok.com -> facebook
            if (tl.find(target) != std::wstring::npos) matched = true;
        }
        
        if (matched) {
            if (IsTempUnlocked(b.label)) {
                RefreshUnlock(b.label);
            } else if (!in_queue) {
                EnqueueBlock(pid, b.label, b.type); 
                return FALSE;
            }
        }
    }
    return TRUE;
}

static void UrlMonLoop() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    while (g_running) {
        Sleep(800);
        auto blocks = GetBlocked();
        UrlScanCtx ctx;
        for (auto& b : blocks) if (b.type == L"url") ctx.urlBlocks.push_back(b);
        if (ctx.urlBlocks.empty()) continue;
        UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (snap.get() != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{sizeof(pe)};
            if (Process32FirstW(snap.get(), &pe)) {
                do {
                    std::wstring n = ToLowerW(pe.szExeFile);
                    for (int i = 0; kBrowsers[i]; i++)
                        if (n == kBrowsers[i]) { ctx.browserPids.insert(pe.th32ProcessID); break; }
                } while (Process32NextW(snap.get(), &pe));
            }
        }
        if (!ctx.browserPids.empty()) EnumWindows(EnumWinCb, (LPARAM)&ctx);
    }
    
    if (g_pAutomation) { g_pAutomation->Release(); g_pAutomation = nullptr; }
    CoUninitialize();
}


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

void StartMonitor(HWND hwnd) {
    g_hwnd = hwnd;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    g_susp  = (NtSuspProc)GetProcAddress(ntdll, "NtSuspendProcess");
    g_resu  = (NtResuProc)GetProcAddress(ntdll, "NtResumeProcess");
    g_NtQIP = (NtQIP_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
    g_running = true;
    g_procThread   = std::thread(ProcMonLoop);
    g_urlThread    = std::thread(UrlMonLoop);
    g_folderThread = std::thread(FolderMonLoop);
    g_fgThread = std::thread(ForegroundMonLoop);
}

void StopMonitor() {
    g_running = false;
    if (g_procThread.joinable())   g_procThread.join();
    if (g_urlThread.joinable())    g_urlThread.join();
    if (g_folderThread.joinable()) g_folderThread.join();
    if (g_fgThread.joinable()) g_fgThread.join();
}

void MonitorAllow(QueuedBlock& targetItem) {
    if (targetItem.hProc && g_resu) g_resu(targetItem.hProc.get());
    { std::lock_guard<std::mutex> l(g_unlockMtx); g_unlocked[targetItem.label] = GetTickCount64(); }
    
    std::lock_guard<std::mutex> lq(g_qMtx);
    std::queue<QueuedBlock> newQueue;
    while (!g_queue.empty()) {
        auto item = std::move(g_queue.front()); g_queue.pop();
        if (item.label == targetItem.label) {
            if (item.hProc && g_resu) g_resu(item.hProc.get());
            // CloseHandle is automatic via UniqueHandle
            { std::lock_guard<std::mutex> lin(g_inQMtx); g_inQueue.erase(item.pid); }
        } else {
            newQueue.push(std::move(item));
        }
    }
    g_queue = std::move(newQueue);
    { std::lock_guard<std::mutex> lin(g_inQMtx); g_inQueue.erase(targetItem.pid); }
}

void MonitorKillPid(DWORD pid) {
    UniqueHandle h(OpenProcess(PROCESS_TERMINATE, FALSE, pid));
    if (h) { TerminateProcess(h.get(), 1); }
    { std::lock_guard<std::mutex> l(g_inQMtx); g_inQueue.erase(pid); }
}

bool PopBlock(QueuedBlock& out) {
    std::lock_guard<std::mutex> l(g_qMtx);
    if (g_queue.empty()) return false;
    out = std::move(g_queue.front()); g_queue.pop();
    return true;
}

bool HasQueuedBlocks() {
    std::lock_guard<std::mutex> l(g_qMtx);
    return !g_queue.empty();
}
