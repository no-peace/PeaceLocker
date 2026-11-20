#include "capture.h"
#include "config.h"
#include "common.h"
#include "path_utils.h"
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mferror.h>
#include <string>
#include <thread>
#include <ctime>
#include <fstream>
#include <sstream>
#include <winhttp.h>
#include <atomic>
#include <mutex>

#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mfreadwrite.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "mf.lib")
#pragma comment(lib, "winhttp.lib")

// Track if Media Foundation is initialized
static std::atomic<bool> g_mfInitialized{false};
static std::mutex g_captureMutex;
static std::atomic<ULONGLONG> g_lastWebhookTime{0};

static bool SaveBMP(const std::wstring& filename, const BYTE* rgbData, LONG width, LONG height) {
    UniqueHandle hFile(CreateFileW(filename.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!hFile) return false;

    DWORD bytesWritten = 0;
    DWORD dataSize = width * height * 4;

    BITMAPFILEHEADER bfh{};
    bfh.bfType = 0x4D42; // "BM"
    bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dataSize;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    BITMAPINFOHEADER bih{};
    bih.biSize = sizeof(BITMAPINFOHEADER);
    bih.biWidth = width;
    bih.biHeight = -height; 
    bih.biPlanes = 1;
    bih.biBitCount = 32;
    bih.biCompression = BI_RGB;

    WriteFile(hFile.get(), &bfh, sizeof(bfh), &bytesWritten, nullptr);
    WriteFile(hFile.get(), &bih, sizeof(bih), &bytesWritten, nullptr);
    WriteFile(hFile.get(), rgbData, dataSize, &bytesWritten, nullptr);

    return true;
}

static std::string EscapeJsonString(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (static_cast<unsigned char>(c) <= 0x1F) {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
            out += buf;
        } else {
            out += c;
        }
    }
    return out;
}

static void SendDiscordWebhook(const std::wstring& imagePath, const std::wstring& itemLabel) {
    std::string urlStr = GetWebhookUrl();
    if (urlStr.empty()) return;

    ULONGLONG nowTicks = GetTickCount64();
    if (g_lastWebhookTime.load() != 0 && nowTicks - g_lastWebhookTime.load() < 300000) {
        Log(L"Webhook suppressed (rate limit)");
        return;
    }

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

    std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    std::wstring contentType = L"Content-Type: multipart/form-data; boundary=" + U2W(boundary);

    std::ifstream file(imagePath, std::ios::binary);
    std::string fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (!fileData.empty()) {
        time_t now = time(nullptr);
        struct tm ti; localtime_s(&ti, &now);
        char timeStr[128]; strftime(timeStr, 128, "%Y-%m-%d %H:%M:%S", &ti);

        std::string embed = R"({
            "embeds": [{
                "title": "\u26a0\ufe0f Intruder Alert",
                "description": "An unauthorized access attempt was detected.",
                "color": 16711680,
                "fields": [
                    {"name": "\uD83D\uDD50 Time", "value": ")" + std::string(timeStr) + R"(", "inline": true},
                    {"name": "\uD83C\uDFAF Target", "value": "`)" + EscapeJsonString(W2U(itemLabel)) + R"(`", "inline": true}
                ]
            }]
        })";
        std::string payload_json = embed;

        std::ostringstream body;
        body << "--" << boundary << "\r\n"
            << "Content-Disposition: form-data; name=\"payload_json\"\r\n"
            << "Content-Type: application/json\r\n\r\n"
            << payload_json << "\r\n"
            << "--" << boundary << "\r\n"
            << "Content-Disposition: form-data; name=\"file\"; filename=\"intruder.bmp\"\r\n"
            << "Content-Type: image/bmp\r\n\r\n"
            << fileData << "\r\n"
            << "--" << boundary << "--\r\n";

        std::string bodyStr = body.str();
        if (WinHttpSendRequest(hRequest.get(), contentType.c_str(), (DWORD)-1, (LPVOID)bodyStr.data(), (DWORD)bodyStr.size(), (DWORD)bodyStr.size(), 0)) {
            WinHttpReceiveResponse(hRequest.get(), nullptr);
            g_lastWebhookTime.store(nowTicks);
        }
    }
}

static bool InitializeMediaFoundation() {
    if (g_mfInitialized.load()) return true;

    std::lock_guard<std::mutex> lock(g_captureMutex);
    if (g_mfInitialized.load()) return true;

    HRESULT hr = MFStartup(MF_VERSION, MFSTARTUP_LITE);
    if (SUCCEEDED(hr)) {
        g_mfInitialized.store(true);
        return true;
    }
    return false;
}

static void ShutdownMediaFoundation() {
    std::lock_guard<std::mutex> lock(g_captureMutex);
    if (g_mfInitialized.load()) {
        MFShutdown();
        g_mfInitialized.store(false);
    }
}

static void CaptureRoutine(std::wstring attemptedItem) {
    std::wstring savedPath;

    // Initialize COM for this thread
    HRESULT hrCo = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hrCo) && hrCo != RPC_E_CHANGED_MODE) {
        return;
    }

    // Initialize Media Foundation
    if (!InitializeMediaFoundation()) {
        CoUninitialize();
        return;
    }

    IMFAttributes* pAttributes = nullptr;
    if (SUCCEEDED(MFCreateAttributes(&pAttributes, 1))) {
        pAttributes->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);

        IMFActivate** ppDevices = nullptr;
        UINT32 count = 0;
        if (SUCCEEDED(MFEnumDeviceSources(pAttributes, &ppDevices, &count)) && count > 0) {

            IMFMediaSource* pSource = nullptr;
            if (SUCCEEDED(ppDevices[0]->ActivateObject(IID_PPV_ARGS(&pSource)))) {

                IMFAttributes* readerAttr = nullptr;
                MFCreateAttributes(&readerAttr, 1);
                readerAttr->SetUINT32(MF_SOURCE_READER_ENABLE_VIDEO_PROCESSING, TRUE);
                // Add a timeout to prevent hanging
                readerAttr->SetUINT32(MF_SOURCE_READER_DISCONNECT_MEDIASOURCE_ON_SHUTDOWN, TRUE);

                IMFSourceReader* pReader = nullptr;
                if (SUCCEEDED(MFCreateSourceReaderFromMediaSource(pSource, readerAttr, &pReader))) {
                    constexpr DWORD kVideoStreamIndex = static_cast<DWORD>(MF_SOURCE_READER_FIRST_VIDEO_STREAM);

                    IMFMediaType* pType = nullptr;
                    MFCreateMediaType(&pType);
                    pType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
                    pType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);

                    if (SUCCEEDED(pReader->SetCurrentMediaType(kVideoStreamIndex, nullptr, pType))) {

                        IMFMediaType* pNativeType = nullptr;
                        pReader->GetCurrentMediaType(kVideoStreamIndex, &pNativeType);
                        UINT32 width = 0, height = 0;
                        MFGetAttributeSize(pNativeType, MF_MT_FRAME_SIZE, &width, &height);
                        if (pNativeType) pNativeType->Release();

                        int validFrames = 0;
                        bool captured = false;
                        // Reduced frame count and added timeout mechanism
                        DWORD startTime = GetTickCount();
                        const DWORD maxCaptureTime = 5000; // 5 second timeout

                        for (int i = 0; i < 30 && !captured; ++i) { 
                            // Check for timeout
                            if (GetTickCount() - startTime > maxCaptureTime) {
                                break;
                            }

                            IMFSample* pSample = nullptr;
                            DWORD flags = 0;
                            if (SUCCEEDED(pReader->ReadSample(kVideoStreamIndex, 0, nullptr, &flags, nullptr, &pSample)) && pSample) {
                                validFrames++;
                                // Capture on 15th valid frame for better quality and to avoid black initial frames from auto-exposure
                                if (validFrames >= 15) {
                                    IMFMediaBuffer* pBuffer = nullptr;
                                    if (SUCCEEDED(pSample->ConvertToContiguousBuffer(&pBuffer))) {
                                        BYTE* pData = nullptr;
                                        DWORD cbData = 0;
                                        if (SUCCEEDED(pBuffer->Lock(&pData, nullptr, &cbData))) {
                                            // Construct APPDATA/AppLocker/Intruders path
                                            std::wstring rootDir = GetAppLockerRootDir();
                                            std::wstring dir = GetIntrudersDir();
                                            EnsureDir(rootDir);
                                            EnsureDir(dir);

                                            time_t now = time(nullptr);
                                            struct tm ti;
                                            localtime_s(&ti, &now);
                                            wchar_t fname[128];
                                            wcsftime(fname, 128, L"\\intruder_%Y%m%d_%H%M%S.bmp", &ti);

                                            std::wstring fullPath = dir + fname;

                                            if (SaveBMP(fullPath, pData, width, height)) {
                                                savedPath = fullPath;
                                                captured = true;
                                            }
                                            pBuffer->Unlock();
                                        }
                                        pBuffer->Release();
                                    }
                                    pSample->Release();
                                    break;
                                }
                                pSample->Release();
                            }
                            if (flags & MF_SOURCE_READERF_ENDOFSTREAM) break;

                            // Small delay to prevent CPU spinning
                            Sleep(50);
                        }
                    }
                    pType->Release();
                    pReader->Release();
                }
                if (readerAttr) readerAttr->Release();
                pSource->Shutdown();
                pSource->Release();
            }

            for (UINT32 i = 0; i < count; ++i) ppDevices[i]->Release();
            CoTaskMemFree(ppDevices);
        }
        pAttributes->Release();
    }

    CoUninitialize();

    if (!savedPath.empty()) {
        SendDiscordWebhook(savedPath, attemptedItem);
    }
}

static void CaptureRoutineCxxForwarder(const wchar_t* attemptedItem) {
    CaptureRoutine(std::wstring(attemptedItem));
}

static void CaptureRoutineSEHWrapped(const wchar_t* attemptedItem) {
    __try {
        CaptureRoutineCxxForwarder(attemptedItem);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Silently handle any native HW exceptions to prevent crashing
    }
}

void CaptureIntruderPhotoAsync(const std::wstring& attemptedItem) {
    // Use a proper thread with error handling
    std::thread([=]() {
        CaptureRoutineSEHWrapped(attemptedItem.c_str());
    }).detach();
}

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

        std::string embed = R"({
            "embeds": [{
                "title": "\uD83D\uDC41\uFE0F Item Opened",
                "color": 16760576,
                "fields": [
                    {"name": "\uD83D\uDD50 Time", "value": ")" + std::string(timeStr) + R"(", "inline": true},
                    {"name": "\uD83D\uDD0D Item", "value": "`)" + EscapeJsonString(W2U(nameCopy)) + R"(`", "inline": false}
                ]
            }]
        })";
        std::string payload_json = embed;

        std::wstring contentType = L"Content-Type: application/json";

        if (WinHttpSendRequest(hRequest.get(), contentType.c_str(), (DWORD)-1, (LPVOID)payload_json.data(), (DWORD)payload_json.size(), (DWORD)payload_json.size(), 0)) {
            WinHttpReceiveResponse(hRequest.get(), nullptr);
        }
    }).detach();
}
