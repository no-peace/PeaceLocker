#include "tray.h"
#include "common.h"
#include <shellapi.h>
#include <wincodec.h>
#include <vector>
#include <cstring>
#include <algorithm>
#pragma comment(lib, "shell32.lib")

static NOTIFYICONDATAW g_nid{};
static HICON g_icon{};

static std::wstring ParentDir(std::wstring path) {
    size_t p = path.find_last_of(L"\\/");
    if (p == std::wstring::npos) return L"";
    return path.substr(0, p);
}

static std::wstring FindLogoPng() {
    wchar_t exe[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring dir = ParentDir(exe);
    std::vector<std::wstring> probes;
    probes.push_back(dir + L"\\logo.png");
    std::wstring p1 = ParentDir(dir);
    if (!p1.empty()) probes.push_back(p1 + L"\\logo.png");
    std::wstring p2 = ParentDir(p1);
    if (!p2.empty()) probes.push_back(p2 + L"\\logo.png");
    for (const auto& p : probes) {
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES) return p;
    }
    return L"";
}

static HICON LoadPngIcon(const std::wstring& path, int sz) {
    IWICImagingFactory* factory = nullptr;
    IWICBitmapDecoder* decoder = nullptr;
    IWICBitmapFrameDecode* frame = nullptr;
    IWICBitmapScaler* scaler = nullptr;
    IWICFormatConverter* conv = nullptr;
    HICON icon = nullptr;
    UINT stride = 0;
    UINT bytes = 0;
    BITMAPINFO bmi{};
    HDC hdc = nullptr;
    void* dibBits = nullptr;
    HBITMAP color = nullptr;
    HBITMAP mask = nullptr;

    do {
        if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory)))) break;
        if (FAILED(factory->CreateDecoderFromFilename(path.c_str(), nullptr, GENERIC_READ, WICDecodeMetadataCacheOnLoad, &decoder))) break;
        if (FAILED(decoder->GetFrame(0, &frame))) break;
        if (FAILED(factory->CreateBitmapScaler(&scaler))) break;
        if (FAILED(scaler->Initialize(frame, (UINT)sz, (UINT)sz, WICBitmapInterpolationModeFant))) break;
        if (FAILED(factory->CreateFormatConverter(&conv))) break;
        if (FAILED(conv->Initialize(scaler, GUID_WICPixelFormat32bppBGRA, WICBitmapDitherTypeNone, nullptr, 0.f, WICBitmapPaletteTypeCustom))) break;

        stride = (UINT)(sz * 4);
        bytes = stride * (UINT)sz;
        std::vector<BYTE> pixels(bytes);
        if (FAILED(conv->CopyPixels(nullptr, stride, bytes, pixels.data()))) break;

        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = sz;
        bmi.bmiHeader.biHeight = -sz;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        hdc = GetDC(nullptr);
        color = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &dibBits, nullptr, 0);
        if (hdc) {
            ReleaseDC(nullptr, hdc);
            hdc = nullptr;
        }
        if (!color || !dibBits) break;
        std::memcpy(dibBits, pixels.data(), bytes);

        mask = CreateBitmap(sz, sz, 1, 1, nullptr);
        if (!mask) break;

        ICONINFO ii{};
        ii.fIcon = TRUE;
        ii.hbmColor = color;
        ii.hbmMask = mask;
        icon = CreateIconIndirect(&ii);
    } while (false);

    if (hdc) ReleaseDC(nullptr, hdc);
    if (color) DeleteObject(color);
    if (mask) DeleteObject(mask);
    if (conv) conv->Release();
    if (scaler) scaler->Release();
    if (frame) frame->Release();
    if (decoder) decoder->Release();
    if (factory) factory->Release();
    return icon;
}

static HICON MakeLockIcon(int sz) {
    HDC scr = GetDC(nullptr);
    HDC dc = CreateCompatibleDC(scr);
    HBITMAP col = CreateCompatibleBitmap(scr, sz, sz);
    HBITMAP msk = CreateBitmap(sz, sz, 1, 1, nullptr);
    ReleaseDC(nullptr, scr);
    HBITMAP oldCol = (HBITMAP)SelectObject(dc, col);

    RECT rc{0, 0, sz, sz};
    HBRUSH clear = CreateSolidBrush(RGB(26, 8, 8));
    FillRect(dc, &rc, clear);
    DeleteObject(clear);

    // Badge circle inspired by the "Peace" branding image.
    HPEN edge = CreatePen(PS_SOLID, 1, RGB(180, 86, 42));
    HBRUSH bg = CreateSolidBrush(RGB(106, 27, 20));
    SelectObject(dc, edge);
    SelectObject(dc, bg);
    Ellipse(dc, 1, 1, sz - 1, sz - 1);
    DeleteObject(edge);
    DeleteObject(bg);

    RECT glow{ 4, 4, sz - 4, sz - 4 };
    HBRUSH glowBr = CreateSolidBrush(RGB(150, 40, 24));
    HPEN glowPen = CreatePen(PS_SOLID, 1, RGB(202, 112, 48));
    SelectObject(dc, glowBr);
    SelectObject(dc, glowPen);
    Ellipse(dc, glow.left, glow.top, glow.right, glow.bottom);
    DeleteObject(glowBr);
    DeleteObject(glowPen);

    HFONT script = CreateFontW(-(std::max)(10, sz - 8), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_SCRIPT, L"Segoe Script");
    HGDIOBJ oldFont = SelectObject(dc, script);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 203, 77));
    RECT textRc{ 3, 0, sz, sz };
    DrawTextW(dc, L"P", 1, &textRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(dc, oldFont);
    DeleteObject(script);

    HPEN lockPen = CreatePen(PS_SOLID, 1, RGB(255, 230, 180));
    HBRUSH lockBrush = CreateSolidBrush(RGB(255, 206, 92));
    SelectObject(dc, lockPen);
    SelectObject(dc, lockBrush);
    RoundRect(dc, sz / 2 - 4, sz / 2 + 1, sz / 2 + 6, sz / 2 + 9, 3, 3);
    SelectObject(dc, GetStockObject(NULL_BRUSH));
    Arc(dc, sz / 2 - 4, sz / 2 - 5, sz / 2 + 6, sz / 2 + 4, sz / 2 + 5, sz / 2 - 1, sz / 2 - 3, sz / 2 - 1);
    DeleteObject(lockPen);
    DeleteObject(lockBrush);

    SelectObject(dc, oldCol);
    DeleteDC(dc);

    // Mask (all black = opaque)
    HDC mdc = CreateCompatibleDC(nullptr);
    HBITMAP oldMsk = (HBITMAP)SelectObject(mdc, msk);
    HBRUSH bk = CreateSolidBrush(0); FillRect(mdc, &rc, bk); DeleteObject(bk);
    SelectObject(mdc, oldMsk); DeleteDC(mdc);

    ICONINFO ii{}; ii.fIcon = TRUE; ii.hbmColor = col; ii.hbmMask = msk;
    HICON icon = CreateIconIndirect(&ii);
    DeleteObject(col); DeleteObject(msk);
    return icon;
}

void InitTray(HWND hwnd, HINSTANCE) {
    if (!g_icon) {
        std::wstring logo = FindLogoPng();
        if (!logo.empty()) {
            g_icon = LoadPngIcon(logo, 24);
        }
        if (!g_icon) {
            g_icon = MakeLockIcon(24);
        }
    }
    ZeroMemory(&g_nid, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = TRAY_UID;
    g_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_SHOWTIP;
    g_nid.uCallbackMessage = WM_APP_TRAY;
    g_nid.hIcon = g_icon ? g_icon : LoadIcon(nullptr, IDI_APPLICATION);
    wcscpy_s(g_nid.szTip, L"Peace's Vault - Active");

    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    if (!Shell_NotifyIconW(NIM_ADD, &g_nid)) {
        g_nid.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        Shell_NotifyIconW(NIM_ADD, &g_nid);
    }
    g_nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_nid);
}

void CleanupTray(HWND) {
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
    if (g_icon) { DestroyIcon(g_icon); g_icon = nullptr; }
}

void SetTrayTip(const wchar_t* tip) {
    wcscpy_s(g_nid.szTip, tip);
    g_nid.uFlags = NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    g_nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
}
