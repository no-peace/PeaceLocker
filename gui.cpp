#include "gui.h"
#include "common.h"
#include "config.h"
#include "monitor.h"
#include "capture.h"
#include "path_utils.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cmath>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "uxtheme.lib")

namespace ui {
constexpr COLORREF kBackdropTop = RGB(29, 10, 8);
constexpr COLORREF kBackdropBottom = RGB(14, 5, 5);
constexpr COLORREF kSurface = CLR_CARD;
constexpr COLORREF kSurfaceStrong = RGB(51, 19, 16);
constexpr COLORREF kSurfaceStroke = CLR_BORDER;
constexpr COLORREF kEditBg = CLR_EDIT;
constexpr COLORREF kEditStroke = RGB(110, 58, 42);
constexpr COLORREF kDangerBg = RGB(80, 20, 24);
constexpr COLORREF kDangerHover = RGB(100, 24, 31);
constexpr COLORREF kAccentBg = CLR_ACCENT;
constexpr COLORREF kAccentHover = CLR_ACCHOV;
constexpr COLORREF kText = CLR_TEXT;
constexpr COLORREF kMuted = CLR_DIM;
constexpr COLORREF kDanger = CLR_ERR;

HFONT MakeFont(int pt, int weight = FW_NORMAL, const wchar_t* face = L"Bahnschrift") {
    HDC screen = GetDC(nullptr);
    int dpi = GetDeviceCaps(screen, LOGPIXELSY);
    ReleaseDC(nullptr, screen);
    return CreateFontW(-MulDiv(pt, dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_SWISS, face);
}

void FillSolid(HDC dc, const RECT& rc, COLORREF color) {
    UniqueGDIObject br(CreateSolidBrush(color));
    FillRect(dc, &rc, (HBRUSH)br.get());
}

void FillVerticalGradient(HDC dc, const RECT& rc, COLORREF top, COLORREF bottom) {
    TRIVERTEX v[2] = {
        { rc.left, rc.top, (COLOR16)(GetRValue(top) << 8), (COLOR16)(GetGValue(top) << 8), (COLOR16)(GetBValue(top) << 8), 0xFFFF },
        { rc.right, rc.bottom, (COLOR16)(GetRValue(bottom) << 8), (COLOR16)(GetGValue(bottom) << 8), (COLOR16)(GetBValue(bottom) << 8), 0xFFFF }
    };
    GRADIENT_RECT g{ 0, 1 };
    GradientFill(dc, v, 2, &g, 1, GRADIENT_FILL_RECT_V);
}

void DrawRoundedCard(HDC dc, const RECT& rc, int radius, COLORREF fill, COLORREF stroke, int strokeWidth = 1) {
    UniqueGDIObject br(CreateSolidBrush(fill));
    UniqueGDIObject pen(CreatePen(PS_SOLID, strokeWidth, stroke));
    HGDIOBJ oldBrush = SelectObject(dc, br.get());
    HGDIOBJ oldPen = SelectObject(dc, pen.get());
    RoundRect(dc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
}

void DrawTextLine(HDC dc, const RECT& rc, const wchar_t* text, HFONT font, COLORREF color, UINT format) {
    HGDIOBJ oldFont = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    DrawTextW(dc, text, -1, const_cast<RECT*>(&rc), format);
    SelectObject(dc, oldFont);
}

RECT CenterRect(int width, int height) {
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    RECT rc{};
    rc.left = (sw - width) / 2;
    rc.top = (sh - height) / 2;
    rc.right = rc.left + width;
    rc.bottom = rc.top + height;
    return rc;
}

std::wstring Upper(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), towupper);
    return value;
}

void DrawTopAccent(HDC dc, const RECT& rc) {
    RECT bar{ rc.left + 1, rc.top + 1, rc.right - 1, rc.top + 7 };
    FillVerticalGradient(dc, bar, RGB(255, 198, 86), RGB(233, 124, 46));
}
} // namespace ui

static HBITMAP g_blurBmp = nullptr;

static std::wstring FormatLockDurationText(unsigned long long seconds) {
    unsigned long long hours = seconds / 3600ULL;
    unsigned long long mins = (seconds % 3600ULL) / 60ULL;
    wchar_t buf[96]{};
    wsprintfW(buf, L"%lluh %llum", hours, mins);
    return buf;
}

static std::wstring BuildLockMessage() {
    std::wstring msg = L"Too many wrong PIN attempts.\nPeace's Vault is locked for ";
    msg += FormatLockDurationText(GetPinLockRemainingSeconds());
    msg += L".";
    return msg;
}

static bool VerifyPinWithFeedback(HINSTANCE hInst, HWND hwndParent, const std::string& pin, const wchar_t* captureLabel) {
    if (pin.empty()) return false;

    if (IsPinLocked()) {
        std::wstring lockMsg = BuildLockMessage();
        ShowThemedAlert(hInst, hwndParent, L"Vault Locked", lockMsg.c_str(), true);
        return false;
    }

    if (VerifyPin(pin)) return true;

    CaptureIntruderPhotoAsync(captureLabel);
    if (IsPinLocked()) {
        std::wstring lockMsg = BuildLockMessage();
        ShowThemedAlert(hInst, hwndParent, L"Vault Locked", lockMsg.c_str(), true);
        return false;
    }

    wchar_t warn[120]{};
    wsprintfW(warn, L"Wrong PIN. %d attempt(s) remaining.", GetRemainingPinAttempts());
    ShowThemedAlert(hInst, hwndParent, L"Access Denied", warn, true);
    return false;
}

static void BoxBlurH(BYTE* src, BYTE* dst, int w, int h, int r) {
    float iarr = 1.0f / (r + r + 1);
    for (int y = 0; y < h; ++y) {
        int ti = y * w * 4;
        int li = ti;
        int firstB = src[ti];
        int firstG = src[ti + 1];
        int firstR = src[ti + 2];
        int lastB = src[ti + (w - 1) * 4];
        int lastG = src[ti + (w - 1) * 4 + 1];
        int lastR = src[ti + (w - 1) * 4 + 2];
        int sumB = (r + 1) * firstB;
        int sumG = (r + 1) * firstG;
        int sumR = (r + 1) * firstR;
        for (int j = 0; j < r; ++j) {
            int idx = ti + (j < w ? j : w - 1) * 4;
            sumB += src[idx];
            sumG += src[idx + 1];
            sumR += src[idx + 2];
        }
        for (int j = 0; j <= r; ++j) {
            int idx = (j + r < w ? j + r : w - 1) * 4 + y * w * 4;
            sumB += src[idx] - firstB;
            sumG += src[idx + 1] - firstG;
            sumR += src[idx + 2] - firstR;
            dst[ti] = (BYTE)(sumB * iarr);
            dst[ti + 1] = (BYTE)(sumG * iarr);
            dst[ti + 2] = (BYTE)(sumR * iarr);
            ti += 4;
        }
        for (int j = r + 1; j < w - r; ++j) {
            int ri = (j + r) * 4 + y * w * 4;
            int li2 = (j - r - 1) * 4 + y * w * 4;
            sumB += src[ri] - src[li2];
            sumG += src[ri + 1] - src[li2 + 1];
            sumR += src[ri + 2] - src[li2 + 2];
            dst[ti] = (BYTE)(sumB * iarr);
            dst[ti + 1] = (BYTE)(sumG * iarr);
            dst[ti + 2] = (BYTE)(sumR * iarr);
            ti += 4;
        }
        for (int j = w - r; j < w; ++j) {
            sumB += lastB - src[li];
            sumG += lastG - src[li + 1];
            sumR += lastR - src[li + 2];
            dst[ti] = (BYTE)(sumB * iarr);
            dst[ti + 1] = (BYTE)(sumG * iarr);
            dst[ti + 2] = (BYTE)(sumR * iarr);
            ti += 4;
            li += 4;
        }
    }
}

static void BoxBlurV(BYTE* src, BYTE* dst, int w, int h, int r) {
    float iarr = 1.0f / (r + r + 1);
    for (int x = 0; x < w; ++x) {
        int ti = x * 4;
        int firstB = src[ti];
        int firstG = src[ti + 1];
        int firstR = src[ti + 2];
        int lastB = src[(h - 1) * w * 4 + x * 4];
        int lastG = src[(h - 1) * w * 4 + x * 4 + 1];
        int lastR = src[(h - 1) * w * 4 + x * 4 + 2];
        int sumB = (r + 1) * firstB;
        int sumG = (r + 1) * firstG;
        int sumR = (r + 1) * firstR;
        for (int j = 0; j < r; ++j) {
            int idx = (j < h ? j : h - 1) * w * 4 + x * 4;
            sumB += src[idx];
            sumG += src[idx + 1];
            sumR += src[idx + 2];
        }
        for (int j = 0; j <= r; ++j) {
            int idx = (j + r < h ? j + r : h - 1) * w * 4 + x * 4;
            sumB += src[idx] - firstB;
            sumG += src[idx + 1] - firstG;
            sumR += src[idx + 2] - firstR;
            dst[ti] = (BYTE)(sumB * iarr);
            dst[ti + 1] = (BYTE)(sumG * iarr);
            dst[ti + 2] = (BYTE)(sumR * iarr);
            ti += w * 4;
        }
        for (int j = r + 1; j < h - r; ++j) {
            int ri = (j + r) * w * 4 + x * 4;
            int li = (j - r - 1) * w * 4 + x * 4;
            sumB += src[ri] - src[li];
            sumG += src[ri + 1] - src[li + 1];
            sumR += src[ri + 2] - src[li + 2];
            dst[ti] = (BYTE)(sumB * iarr);
            dst[ti + 1] = (BYTE)(sumG * iarr);
            dst[ti + 2] = (BYTE)(sumR * iarr);
            ti += w * 4;
        }
        for (int j = h - r; j < h; ++j) {
            int li = (j - r - 1 >= 0 ? j - r - 1 : 0) * w * 4 + x * 4;
            sumB += lastB - src[li];
            sumG += lastG - src[li + 1];
            sumR += lastR - src[li + 2];
            dst[ti] = (BYTE)(sumB * iarr);
            dst[ti + 1] = (BYTE)(sumG * iarr);
            dst[ti + 2] = (BYTE)(sumR * iarr);
            ti += w * 4;
        }
    }
}

static void DarkenPixels(BYTE* data, int w, int h, float factor) {
    const int total = w * h * 4;
    for (int i = 0; i < total; i += 4) {
        data[i] = (BYTE)(data[i] * factor);
        data[i + 1] = (BYTE)(data[i + 1] * factor);
        data[i + 2] = (BYTE)(data[i + 2] * factor);
    }
}

static HBITMAP CaptureAndBlurScreen(int sw, int sh) {
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    BITMAPINFO bmi{};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = sw;
    bmi.bmiHeader.biHeight = -sh;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    BYTE* bits = nullptr;
    HBITMAP bmp = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, (void**)&bits, nullptr, 0);
    SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, sw, sh, screen, 0, 0, SRCCOPY);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);

    if (!bits) return bmp;

    const int total = sw * sh * 4;
    BYTE* temp = new BYTE[total];
    for (int pass = 0; pass < 3; ++pass) {
        BoxBlurH(bits, temp, sw, sh, 20);
        BoxBlurV(temp, bits, sw, sh, 20);
    }
    delete[] temp;
    DarkenPixels(bits, sw, sh, 0.38f);
    return bmp;
}

struct PromptCtx {
    const wchar_t* prompt{};
    bool password{};
    bool done{};
    bool accepted{};
    std::wstring result;
    HWND hEdit{};
    UniqueGDIObject fTitle;
    UniqueGDIObject fBody;
    UniqueGDIObject fButton;
    UniqueGDIObject brBg;
    UniqueGDIObject brEdit;
};

static LRESULT CALLBACK PromptProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = reinterpret_cast<PromptCtx*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_CREATE: {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        ctx = reinterpret_cast<PromptCtx*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)ctx);

        ctx->fTitle.reset(ui::MakeFont(17, FW_BOLD));
        ctx->fBody.reset(ui::MakeFont(10));
        ctx->fButton.reset(ui::MakeFont(10, FW_SEMIBOLD));
        ctx->brBg.reset(CreateSolidBrush(ui::kSurface));
        ctx->brEdit.reset(CreateSolidBrush(ui::kEditBg));

        DWORD editStyle = WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | (ctx->password ? ES_PASSWORD : 0);
        ctx->hEdit = CreateWindowExW(0, L"EDIT", L"", editStyle, 30, 112, 400, 34, hwnd, (HMENU)101, cs->hInstance, nullptr);
        SendMessageW(ctx->hEdit, WM_SETFONT, (WPARAM)ctx->fBody.get(), TRUE);
        if (ctx->password) {
            SendMessageW(ctx->hEdit, EM_SETPASSWORDCHAR, L'\u25CF', 0);
        }

        HWND ok = CreateWindowExW(0, L"BUTTON", L"Confirm", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 200, 162, 110, 34, hwnd, (HMENU)IDOK, cs->hInstance, nullptr);
        HWND cancel = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE, 320, 162, 110, 34, hwnd, (HMENU)IDCANCEL, cs->hInstance, nullptr);
        SendMessageW(ok, WM_SETFONT, (WPARAM)ctx->fButton.get(), TRUE);
        SendMessageW(cancel, WM_SETFONT, (WPARAM)ctx->fButton.get(), TRUE);
        SetFocus(ctx->hEdit);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc{};
        GetClientRect(hwnd, &rc);
        ui::FillVerticalGradient(dc, rc, ui::kBackdropTop, ui::kBackdropBottom);
        RECT card{ 10, 10, rc.right - 10, rc.bottom - 10 };
        ui::DrawRoundedCard(dc, card, 14, ui::kSurface, ui::kSurfaceStroke, 1);
        ui::DrawTopAccent(dc, card);

        RECT title{ 30, 28, rc.right - 30, 56 };
        ui::DrawTextLine(dc, title, APP_NAME_L, (HFONT)ctx->fTitle.get(), ui::kText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

        RECT prompt{ 30, 66, rc.right - 30, 104 };
        ui::DrawTextLine(dc, prompt, ctx->prompt, (HFONT)ctx->fBody.get(), ui::kMuted, DT_LEFT | DT_WORDBREAK);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, ui::kMuted);
        return (LRESULT)ctx->brBg.get();
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetTextColor(dc, ui::kText);
        SetBkColor(dc, ui::kEditBg);
        return (LRESULT)ctx->brEdit.get();
    }
    case WM_CTLCOLORBTN: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkMode(dc, TRANSPARENT);
        return (LRESULT)ctx->brBg.get();
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            wchar_t buf[512]{};
            GetWindowTextW(ctx->hEdit, buf, 511);
            ctx->result = buf;
            ctx->accepted = true;
            ctx->done = true;
            DestroyWindow(hwnd);
        } else if (LOWORD(wp) == IDCANCEL) {
            ctx->done = true;
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE:
        ctx->done = true;
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        // RAII handles fTitle, fBody, fButton, brBg, brEdit cleanup
        return 0;
    case WM_NCHITTEST: {
        LRESULT hit = DefWindowProcW(hwnd, msg, wp, lp);
        if (hit == HTCLIENT) {
            POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            ScreenToClient(hwnd, &pt);
            if (pt.y <= 38) return HTCAPTION;
        }
        return hit;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

std::wstring ShowTextPromptDialog(HINSTANCE hInst, HWND hwndParent, const wchar_t* title, const wchar_t* prompt, bool password) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{ sizeof(wc) };
        wc.lpfnWndProc = PromptProc;
        wc.hInstance = hInst;
        wc.lpszClassName = L"ALPromptDialog";
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
        registered = true;
    }

    PromptCtx ctx{};
    ctx.prompt = prompt;
    ctx.password = password;

    RECT rc = ui::CenterRect(450, 215);
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, L"ALPromptDialog", title,
        WS_POPUP | WS_VISIBLE,
        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, hwndParent, nullptr, hInst, &ctx);
    if (!hwnd) return L"";

    if (hwndParent) EnableWindow(hwndParent, FALSE);

    MSG msg{};
    while (!ctx.done) {
        int ret = GetMessageW(&msg, nullptr, 0, 0);
        if (ret <= 0) {
            ctx.done = true;
            break;
        }
        if (msg.hwnd == ctx.hEdit && msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            SendMessageW(hwnd, WM_COMMAND, IDOK, 0);
        } else if (msg.hwnd == ctx.hEdit && msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) {
            SendMessageW(hwnd, WM_COMMAND, IDCANCEL, 0);
        } else {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    if (hwndParent) {
        EnableWindow(hwndParent, TRUE);
        SetForegroundWindow(hwndParent);
    }

    if (!ctx.accepted) return L"";
    return ctx.result;
}

static std::string InputBox(HINSTANCE hInst, HWND hwndParent, const wchar_t* title, const wchar_t* prompt, bool password) {
    return W2U(ShowTextPromptDialog(hInst, hwndParent, title, prompt, password));
}

struct AlertCtx {
    const wchar_t* title{};
    const wchar_t* message{};
    bool confirm{};
    bool isError{};
    bool done{};
    bool accepted{};
    BYTE alpha{ 0 };
    HWND hBtnPrimary{};
    HWND hBtnSecondary{};
    UniqueGDIObject fTitle;
    UniqueGDIObject fBody;
    UniqueGDIObject fButton;
    RECT rClose{ 0, 0, 0, 0 };
};

static LRESULT CALLBACK AlertProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = reinterpret_cast<AlertCtx*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_CREATE: {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        ctx = reinterpret_cast<AlertCtx*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)ctx);

        ctx->fTitle.reset(ui::MakeFont(16, FW_BOLD));
        ctx->fBody.reset(ui::MakeFont(10));
        ctx->fButton.reset(ui::MakeFont(10, FW_SEMIBOLD));

        if (ctx->confirm) {
            ctx->hBtnPrimary = CreateWindowExW(0, L"BUTTON", L"Confirm",
                WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 210, 172, 110, 34, hwnd, (HMENU)IDYES, cs->hInstance, nullptr);
            ctx->hBtnSecondary = CreateWindowExW(0, L"BUTTON", L"Cancel",
                WS_CHILD | WS_VISIBLE, 332, 172, 110, 34, hwnd, (HMENU)IDCANCEL, cs->hInstance, nullptr);
            SendMessageW(ctx->hBtnSecondary, WM_SETFONT, (WPARAM)ctx->fButton.get(), TRUE);
        } else {
            ctx->hBtnPrimary = CreateWindowExW(0, L"BUTTON", L"OK",
                WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 332, 172, 110, 34, hwnd, (HMENU)IDOK, cs->hInstance, nullptr);
        }
        SendMessageW(ctx->hBtnPrimary, WM_SETFONT, (WPARAM)ctx->fButton.get(), TRUE);

        SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
        SetTimer(hwnd, 10, 12, nullptr);
        return 0;
    }
    case WM_TIMER:
        if (wp == 10 && ctx) {
            if (ctx->alpha < 245) {
                BYTE next = static_cast<BYTE>(ctx->alpha + 28);
                ctx->alpha = next > 245 ? 245 : next;
                SetLayeredWindowAttributes(hwnd, 0, ctx->alpha, LWA_ALPHA);
            } else {
                KillTimer(hwnd, 10);
            }
        }
        return 0;
    case WM_NCHITTEST: {
        LRESULT hit = DefWindowProcW(hwnd, msg, wp, lp);
        if (hit == HTCLIENT) {
            POINT p{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            ScreenToClient(hwnd, &p);
            if (p.y >= 0 && p.y <= 44) return HTCAPTION;
        }
        return hit;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc{};
        GetClientRect(hwnd, &rc);
        ui::FillVerticalGradient(dc, rc, ui::kBackdropTop, ui::kBackdropBottom);
        RECT card{ 8, 8, rc.right - 8, rc.bottom - 8 };
        ui::DrawRoundedCard(dc, card, 14, ui::kSurface, ui::kSurfaceStroke, 1);
        ui::DrawTopAccent(dc, card);

        RECT header{ 18, 16, rc.right - 18, 40 };
        ui::DrawTextLine(dc, header, ctx->title, (HFONT)ctx->fTitle.get(),
            ctx->isError ? ui::kDanger : ui::kText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

        ctx->rClose = { rc.right - 36, 14, rc.right - 14, 36 };
        ui::DrawTextLine(dc, ctx->rClose, L"x", (HFONT)ctx->fTitle.get(), ui::kMuted, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        RECT divider{ 18, 48, rc.right - 18, 49 };
        ui::FillSolid(dc, divider, RGB(47, 67, 90));

        RECT body{ 22, 62, rc.right - 22, 154 };
        ui::DrawTextLine(dc, body, ctx->message, (HFONT)ctx->fBody.get(), ui::kText, DT_LEFT | DT_WORDBREAK);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_LBUTTONUP: {
        if (!ctx) return 0;
        POINT p{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        if (PtInRect(&ctx->rClose, p)) {
            SendMessageW(hwnd, WM_COMMAND, ctx->confirm ? IDCANCEL : IDOK, 0);
        }
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            ctx->accepted = true;
            ctx->done = true;
            DestroyWindow(hwnd);
        } else if (LOWORD(wp) == IDYES) {
            ctx->accepted = true;
            ctx->done = true;
            DestroyWindow(hwnd);
        } else if (LOWORD(wp) == IDCANCEL) {
            ctx->accepted = false;
            ctx->done = true;
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE:
        if (ctx) {
            ctx->done = true;
            ctx->accepted = false;
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static bool ShowThemedDialogInternal(HINSTANCE hInst, HWND hwndParent, const wchar_t* title,
    const wchar_t* message, bool confirm, bool isError) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{ sizeof(wc) };
        wc.lpfnWndProc = AlertProc;
        wc.hInstance = hInst;
        wc.lpszClassName = L"ALThemedAlert";
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
        registered = true;
    }

    AlertCtx ctx{};
    ctx.title = title;
    ctx.message = message;
    ctx.confirm = confirm;
    ctx.isError = isError;

    RECT rc = ui::CenterRect(460, 220);
    HWND hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_LAYERED, L"ALThemedAlert", L"",
        WS_POPUP | WS_VISIBLE,
        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
        hwndParent, nullptr, hInst, &ctx);
    if (!hwnd) return false;

    if (hwndParent) EnableWindow(hwndParent, FALSE);
    MSG msg{};
    while (!ctx.done) {
        int ret = GetMessageW(&msg, nullptr, 0, 0);
        if (ret <= 0) {
            ctx.done = true;
            break;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (hwndParent) {
        EnableWindow(hwndParent, TRUE);
        SetForegroundWindow(hwndParent);
    }
    return ctx.accepted;
}

void ShowThemedAlert(HINSTANCE hInst, HWND hwndParent, const wchar_t* title, const wchar_t* message, bool isError) {
    ShowThemedDialogInternal(hInst, hwndParent, title, message, false, isError);
}

bool ShowThemedConfirm(HINSTANCE hInst, HWND hwndParent, const wchar_t* title, const wchar_t* message) {
    return ShowThemedDialogInternal(hInst, hwndParent, title, message, true, false);
}

struct SetupCtx {
    HWND hPin1{};
    HWND hPin2{};
    HWND hError{};
    UniqueGDIObject fTitle;
    UniqueGDIObject fBody;
    UniqueGDIObject fButton;
    UniqueGDIObject brBg;
    UniqueGDIObject brEdit;
    std::string result;
    bool done{};
    bool accepted{};
};

static LRESULT CALLBACK SetupProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = reinterpret_cast<SetupCtx*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_CREATE: {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        ctx = reinterpret_cast<SetupCtx*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)ctx);

        ctx->fTitle.reset(ui::MakeFont(20, FW_BOLD));
        ctx->fBody.reset(ui::MakeFont(10));
        ctx->fButton.reset(ui::MakeFont(10, FW_SEMIBOLD));
        ctx->brBg.reset(CreateSolidBrush(ui::kSurface));
        ctx->brEdit.reset(CreateSolidBrush(ui::kEditBg));

        auto makeLabel = [&](const wchar_t* text, int x, int y, int w, int h) {
            HWND label = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
                x, y, w, h, hwnd, nullptr, cs->hInstance, nullptr);
            SendMessageW(label, WM_SETFONT, (WPARAM)ctx->fBody.get(), TRUE);
        };

        auto makeEdit = [&](int id, int x, int y, int w, int h) -> HWND {
            HWND edit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL,
                x, y, w, h, hwnd, (HMENU)(INT_PTR)id, cs->hInstance, nullptr);
            SendMessageW(edit, WM_SETFONT, (WPARAM)ctx->fBody.get(), TRUE);
            SendMessageW(edit, EM_SETPASSWORDCHAR, L'\u25CF', 0);
            return edit;
        };

        makeLabel(L"Create your security PIN (minimum 4 characters)", 28, 96, 360, 20);
        ctx->hPin1 = makeEdit(301, 28, 120, 360, 34);

        makeLabel(L"Confirm PIN", 28, 166, 360, 20);
        ctx->hPin2 = makeEdit(302, 28, 190, 360, 34);

        ctx->hError = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            28, 232, 360, 20, hwnd, nullptr, cs->hInstance, nullptr);
        SendMessageW(ctx->hError, WM_SETFONT, (WPARAM)ctx->fBody.get(), TRUE);

        HWND button = CreateWindowExW(0, L"BUTTON", L"Set PIN", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            140, 262, 140, 36, hwnd, (HMENU)IDOK, cs->hInstance, nullptr);
        SendMessageW(button, WM_SETFONT, (WPARAM)ctx->fButton.get(), TRUE);

        SetFocus(ctx->hPin1);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc{};
        GetClientRect(hwnd, &rc);
        ui::FillVerticalGradient(dc, rc, ui::kBackdropTop, ui::kBackdropBottom);
        RECT card{ 12, 12, rc.right - 12, rc.bottom - 12 };
        ui::DrawRoundedCard(dc, card, 14, ui::kSurface, ui::kSurfaceStroke, 1);
        ui::DrawTopAccent(dc, card);

        RECT title{ 28, 30, rc.right - 28, 62 };
        ui::DrawTextLine(dc, title, L"Welcome to Peace's Vault", (HFONT)ctx->fTitle.get(), ui::kText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

        RECT subtitle{ 28, 64, rc.right - 28, 90 };
        ui::DrawTextLine(dc, subtitle, L"One-time setup to protect your blocked content", (HFONT)ctx->fBody.get(), ui::kMuted, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, (reinterpret_cast<HWND>(lp) == ctx->hError) ? ui::kDanger : ui::kMuted);
        return (LRESULT)ctx->brBg.get();
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkColor(dc, ui::kEditBg);
        SetTextColor(dc, ui::kText);
        return (LRESULT)ctx->brEdit.get();
    }
    case WM_CTLCOLORBTN: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkMode(dc, TRANSPARENT);
        return (LRESULT)ctx->brBg.get();
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            wchar_t p1[128]{};
            wchar_t p2[128]{};
            GetWindowTextW(ctx->hPin1, p1, 127);
            GetWindowTextW(ctx->hPin2, p2, 127);

            if (wcslen(p1) < 4) {
                SetWindowTextW(ctx->hError, L"PIN must be at least 4 characters.");
                return 0;
            }
            if (wcscmp(p1, p2) != 0) {
                SetWindowTextW(ctx->hError, L"PINs do not match.");
                return 0;
            }

            ctx->result = W2U(p1);
            ctx->accepted = true;
            ctx->done = true;
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE:
        ctx->done = true;
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        // RAII handles fTitle, fBody, fButton, brBg, brEdit cleanup
        return 0;
    case WM_NCHITTEST: {
        LRESULT hit = DefWindowProcW(hwnd, msg, wp, lp);
        if (hit == HTCLIENT) {
            POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            ScreenToClient(hwnd, &pt);
            if (pt.y <= 42) return HTCAPTION;
        }
        return hit;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

std::string ShowSetupDialog(HINSTANCE hInst, HWND hwndParent) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{ sizeof(wc) };
        wc.lpfnWndProc = SetupProc;
        wc.hInstance = hInst;
        wc.lpszClassName = L"ALSetupDialog";
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
        registered = true;
    }

    SetupCtx ctx{};
    RECT rc = ui::CenterRect(420, 330);
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, L"ALSetupDialog", L"Peace's Vault Setup",
        WS_POPUP | WS_VISIBLE,
        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, hwndParent, nullptr, hInst, &ctx);
    if (!hwnd) return "";

    if (hwndParent) EnableWindow(hwndParent, FALSE);

    MSG msg{};
    while (!ctx.done) {
        int ret = GetMessageW(&msg, nullptr, 0, 0);
        if (ret <= 0) {
            ctx.done = true;
            break;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (hwndParent) {
        EnableWindow(hwndParent, TRUE);
        SetForegroundWindow(hwndParent);
    }

    if (!ctx.accepted) return "";
    return ctx.result;
}

#define IDC_PIN_EDIT 3001

struct OverlayCtx {
    QueuedBlock item;
    HWND hEdit{};
    UniqueGDIObject fTitle;
    UniqueGDIObject fSub;
    UniqueGDIObject fBody;
    UniqueGDIObject fHint;
    UniqueGDIObject fPin;
    UniqueGDIObject brEdit;
    int attempts{};
    bool overlayVisible{};
    RECT rUnlock{};
    RECT rDeny{};
    bool unlockHover{};
    bool denyHover{};
    float animPhase{};
};

static HWND g_hOverlay = nullptr;
static OverlayCtx* g_overlay = nullptr;
static WNDPROC g_originalEditProc = nullptr;

static void ShowNextOrHide(HWND hwnd);
static void TryUnlock(HWND hwnd);

static void DrawLockGlyph(HDC dc, int x, int y, int size) {
    HBRUSH fill = CreateSolidBrush(RGB(245, 251, 255));
    HPEN pen = CreatePen(PS_SOLID, 2, RGB(245, 251, 255));
    HGDIOBJ oldBrush = SelectObject(dc, fill);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    RoundRect(dc, x - size / 4, y, x + size / 4, y + size / 2, 6, 6);
    SelectObject(dc, GetStockObject(NULL_BRUSH));
    Arc(dc, x - size / 4 + 2, y - size / 3, x + size / 4 - 2, y + 8,
        x + size / 4 - 3, y - size / 8, x - size / 4 + 3, y - size / 8);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(fill);
    DeleteObject(pen);
}

static void PaintOverlay(HWND hwnd) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);

    if (g_blurBmp) {
        HDC mem = CreateCompatibleDC(dc);
        SelectObject(mem, g_blurBmp);
        BitBlt(dc, 0, 0, sw, sh, mem, 0, 0, SRCCOPY);
        DeleteDC(mem);
    } else {
        RECT full{ 0, 0, sw, sh };
        ui::FillVerticalGradient(dc, full, ui::kBackdropTop, ui::kBackdropBottom);
    }

    RECT overlayTint{ 0, 0, sw, sh };
    HBRUSH tint = CreateSolidBrush(RGB(5, 9, 15));
    FillRect(dc, &overlayTint, tint);
    DeleteObject(tint);

    const int cardW = 560;
    const int cardH = 470;
    int cx = (sw - cardW) / 2;
    int cy = (sh - cardH) / 2;
    RECT card{ cx, cy, cx + cardW, cy + cardH };

    ui::DrawRoundedCard(dc, card, 18, ui::kSurface, ui::kSurfaceStroke, 2);
    ui::DrawTopAccent(dc, card);

    const float pulse = 0.5f + 0.5f * std::sin(g_overlay->animPhase);
    BYTE glow = static_cast<BYTE>(80 + pulse * 120.0f);
    HPEN pulsePen = CreatePen(PS_SOLID, 2, RGB(255, glow, 72));
    HGDIOBJ oldPenPulse = SelectObject(dc, pulsePen);
    HGDIOBJ oldBrushPulse = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, cx + 4, cy + 4, cx + cardW - 4, cy + cardH - 4, 18, 18);
    SelectObject(dc, oldPenPulse);
    SelectObject(dc, oldBrushPulse);
    DeleteObject(pulsePen);

    RECT iconCircle{ cx + 40, cy + 40, cx + 116, cy + 116 };
    HBRUSH iconBrush = CreateSolidBrush(ui::kAccentBg);
    HPEN iconPen = CreatePen(PS_SOLID, 1, RGB(255, 225, 140));
    HGDIOBJ oldBrush = SelectObject(dc, iconBrush);
    HGDIOBJ oldPen = SelectObject(dc, iconPen);
    Ellipse(dc, iconCircle.left, iconCircle.top, iconCircle.right, iconCircle.bottom);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(iconBrush);
    DeleteObject(iconPen);
    DrawLockGlyph(dc, cx + 78, cy + 67, 52);

    RECT title{ cx + 134, cy + 52, cx + cardW - 30, cy + 88 };
    ui::DrawTextLine(dc, title, L"Peace's Vault Security Check", (HFONT)g_overlay->fTitle.get(), ui::kText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    RECT subtitle{ cx + 134, cy + 88, cx + cardW - 30, cy + 114 };
    ui::DrawTextLine(dc, subtitle, L"This app or content is protected.", (HFONT)g_overlay->fSub.get(), ui::kMuted, DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    std::wstring itemText = g_overlay->item.label;
    if (itemText.size() > 64) itemText = itemText.substr(0, 64) + L"...";
    RECT itemLabel{ cx + 40, cy + 140, cx + cardW - 40, cy + 168 };
    ui::DrawTextLine(dc, itemLabel, itemText.c_str(), (HFONT)g_overlay->fBody.get(), ui::kText, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

    std::wstring typeTag = L"TYPE: " + ui::Upper(g_overlay->item.type);
    RECT typeRc{ cx + 40, cy + 170, cx + cardW - 40, cy + 194 };
    ui::DrawTextLine(dc, typeRc, typeTag.c_str(), (HFONT)g_overlay->fHint.get(), ui::kMuted, DT_LEFT | DT_SINGLELINE);

    RECT sep{ cx + 40, cy + 206, cx + cardW - 40, cy + 207 };
    ui::FillSolid(dc, sep, RGB(88, 44, 34));

    RECT prompt{ cx + 40, cy + 226, cx + cardW - 40, cy + 252 };
    ui::DrawTextLine(dc, prompt, L"Enter your PIN to allow this session.", (HFONT)g_overlay->fBody.get(), ui::kText, DT_LEFT | DT_SINGLELINE);

    RECT editFrame{ cx + 40, cy + 264, cx + cardW - 40, cy + 312 };
    ui::DrawRoundedCard(dc, editFrame, 10, ui::kEditBg, ui::kEditStroke, 2);

    if (IsPinLocked()) {
        std::wstring lockWarn = BuildLockMessage();
        RECT warnRc{ cx + 40, cy + 320, cx + cardW - 40, cy + 346 };
        ui::DrawTextLine(dc, warnRc, lockWarn.c_str(), (HFONT)g_overlay->fHint.get(), ui::kDanger, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
    } else if (g_overlay->attempts > 0) {
        wchar_t warn[96]{};
        wsprintfW(warn, L"Wrong PIN. %d attempt(s) remaining.", GetRemainingPinAttempts());
        RECT warnRc{ cx + 40, cy + 320, cx + cardW - 40, cy + 346 };
        ui::DrawTextLine(dc, warnRc, warn, (HFONT)g_overlay->fHint.get(), ui::kDanger, DT_LEFT | DT_SINGLELINE);
    }

    const int btnW = 224;
    const int btnH = 46;
    g_overlay->rUnlock = { cx + 40, cy + 356, cx + 40 + btnW, cy + 356 + btnH };
    g_overlay->rDeny = { cx + cardW - 40 - btnW, cy + 356, cx + cardW - 40, cy + 356 + btnH };

    ui::DrawRoundedCard(dc, g_overlay->rUnlock, 10, g_overlay->unlockHover ? ui::kAccentHover : ui::kAccentBg,
        g_overlay->unlockHover ? RGB(255, 230, 155) : RGB(214, 150, 64), 1);
    ui::DrawTextLine(dc, g_overlay->rUnlock, L"Unlock", (HFONT)g_overlay->fBody.get(), RGB(36, 16, 7), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    ui::DrawRoundedCard(dc, g_overlay->rDeny, 10, g_overlay->denyHover ? ui::kDangerHover : ui::kDangerBg,
        RGB(142, 57, 72), 1);
    ui::DrawTextLine(dc, g_overlay->rDeny, L"Deny and Kill", (HFONT)g_overlay->fBody.get(), ui::kDanger, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    RECT hint{ cx + 40, cy + 416, cx + cardW - 40, cy + 440 };
    ui::DrawTextLine(dc, hint, L"Tip: press Enter to unlock quickly.", (HFONT)g_overlay->fHint.get(), ui::kMuted, DT_LEFT | DT_SINGLELINE);

    EndPaint(hwnd, &ps);
}

static void DenyAndKill(HWND hwnd) {
    if (!g_overlay) return;
    MonitorKillPid(g_overlay->item.pid);
    if (g_overlay->item.hProc) {
        g_overlay->item.hProc.reset();
    }
    g_overlay->attempts = 0;
    ShowNextOrHide(hwnd);
}

static void TryUnlock(HWND hwnd) {
    if (!g_overlay) return;
    wchar_t pin[64]{};
    GetWindowTextW(g_overlay->hEdit, pin, 63);
    if (!pin[0]) return;

    if (IsPinLocked()) {
        std::wstring msg = BuildLockMessage();
        ShowThemedAlert(GetModuleHandleW(nullptr), hwnd, L"Vault Locked", msg.c_str(), true);

        MonitorKillPid(g_overlay->item.pid);
        if (g_overlay->item.hProc) {
            g_overlay->item.hProc.reset();
        }
        LockWorkStation();
        g_overlay->attempts = 0;
        ShowNextOrHide(hwnd);
        return;
    }

    if (VerifyPin(W2U(pin))) {
        g_overlay->attempts = 0;
        SetWindowTextW(g_overlay->hEdit, L"");
        MonitorAllow(g_overlay->item);
        if (g_overlay->item.hProc) {
            g_overlay->item.hProc.reset();
        }
        ShowNextOrHide(hwnd);
        return;
    }

    SetWindowTextW(g_overlay->hEdit, L"");
    CaptureIntruderPhotoAsync(g_overlay->item.label);
    g_overlay->attempts = 3 - GetRemainingPinAttempts();
    InvalidateRect(hwnd, nullptr, TRUE);

    if (IsPinLocked()) {
        std::wstring msg = BuildLockMessage();
        ShowThemedAlert(GetModuleHandleW(nullptr), hwnd, L"Vault Locked", msg.c_str(), true);

        MonitorKillPid(g_overlay->item.pid);
        if (g_overlay->item.hProc) {
            g_overlay->item.hProc.reset();
        }
        LockWorkStation();
        g_overlay->attempts = 0;
        ShowNextOrHide(hwnd);
    } else {
        SetFocus(g_overlay->hEdit);
    }
}

static LRESULT CALLBACK OverlayEditProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_KEYDOWN && wp == VK_RETURN) {
        TryUnlock(GetParent(hwnd));
        return 0;
    }
    return CallWindowProcW(g_originalEditProc, hwnd, msg, wp, lp);
}

static void ShowNextOrHide(HWND hwnd) {
    if (!g_overlay) return;
    QueuedBlock next{};
    if (PopBlock(next)) {
        g_overlay->item = std::move(next);
        g_overlay->attempts = 0;
        g_overlay->unlockHover = false;
        g_overlay->denyHover = false;
        SetWindowTextW(g_overlay->hEdit, L"");
        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        int cx = (sw - 560) / 2;
        int cy = (sh - 470) / 2;
        SetWindowPos(g_overlay->hEdit, nullptr, cx + 52, cy + 274, 560 - 104, 28, SWP_NOZORDER);
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, sw, sh, SWP_SHOWWINDOW);
        SetForegroundWindow(hwnd);
        SetFocus(g_overlay->hEdit);
        InvalidateRect(hwnd, nullptr, TRUE);
        return;
    }

    g_overlay->overlayVisible = false;
    ShowWindow(hwnd, SW_HIDE);
    KillTimer(hwnd, 2);
    if (g_blurBmp) {
        DeleteObject(g_blurBmp);
        g_blurBmp = nullptr;
    }
}

static LRESULT CALLBACK OverlayProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT:
        PaintOverlay(hwnd);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_CLOSE:
        return 0;
    case WM_LBUTTONDOWN: {
        if (!g_overlay) return 0;
        POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        if (PtInRect(&g_overlay->rUnlock, pt)) TryUnlock(hwnd);
        else if (PtInRect(&g_overlay->rDeny, pt)) DenyAndKill(hwnd);
        else SetFocus(g_overlay->hEdit);
        return 0;
    }
    case WM_MOUSEMOVE: {
        if (!g_overlay) return 0;
        POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        bool unlockHover = PtInRect(&g_overlay->rUnlock, pt) != 0;
        bool denyHover = PtInRect(&g_overlay->rDeny, pt) != 0;
        if (unlockHover != g_overlay->unlockHover || denyHover != g_overlay->denyHover) {
            g_overlay->unlockHover = unlockHover;
            g_overlay->denyHover = denyHover;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    }
    case WM_SETCURSOR: {
        if (!g_overlay) break;
        POINT pt{};
        GetCursorPos(&pt);
        ScreenToClient(hwnd, &pt);
        bool overBtn = PtInRect(&g_overlay->rUnlock, pt) || PtInRect(&g_overlay->rDeny, pt);
        SetCursor(LoadCursor(nullptr, overBtn ? IDC_HAND : IDC_ARROW));
        return TRUE;
    }
    case WM_ACTIVATE:
        if (LOWORD(wp) == WA_INACTIVE && g_overlay && g_overlay->overlayVisible) {
            SetTimer(hwnd, 1, 120, nullptr);
        }
        return 0;
    case WM_TIMER:
        if (wp == 1) {
            KillTimer(hwnd, (UINT_PTR)wp);
            if (g_overlay && g_overlay->overlayVisible) {
                SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
                SetForegroundWindow(hwnd);
                SetFocus(g_overlay->hEdit);
            }
            return 0;
        }
        if (wp == 2 && g_overlay && g_overlay->overlayVisible) {
            g_overlay->animPhase += 0.1f;
            if (g_overlay->animPhase > 6.283f) g_overlay->animPhase = 0.0f;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        return 0;
    case WM_CTLCOLOREDIT:
        if (g_overlay) {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetTextColor(dc, ui::kText);
            SetBkColor(dc, ui::kEditBg);
            return (LRESULT)g_overlay->brEdit.get();
        }
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void ShowPinOverlay(HINSTANCE hInst, HWND);
void CleanupOverlay();

void ShowPinOverlay(HINSTANCE hInst, HWND) {
    if (!g_hOverlay) {
        WNDCLASSEXW wc{ sizeof(wc) };
        wc.lpfnWndProc = OverlayProc;
        wc.hInstance = hInst;
        wc.lpszClassName = L"ALOverlay";
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);

        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        g_hOverlay = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"ALOverlay", APP_NAME_L,
            WS_POPUP, 0, 0, sw, sh, nullptr, nullptr, hInst, nullptr);

        static OverlayCtx overlay{};
        overlay.fTitle.reset(ui::MakeFont(24, FW_BOLD));
        overlay.fSub.reset(ui::MakeFont(11));
        overlay.fBody.reset(ui::MakeFont(12, FW_SEMIBOLD));
        overlay.fHint.reset(ui::MakeFont(9));
        overlay.fPin.reset(ui::MakeFont(17, FW_SEMIBOLD, L"Consolas"));
        overlay.brEdit.reset(CreateSolidBrush(ui::kEditBg));
        g_overlay = &overlay;

        g_overlay->hEdit = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | ES_PASSWORD | ES_CENTER | ES_AUTOHSCROLL,
            0, 0, 1, 1, g_hOverlay, (HMENU)IDC_PIN_EDIT, hInst, nullptr);
        SendMessageW(g_overlay->hEdit, WM_SETFONT, (WPARAM)g_overlay->fPin.get(), TRUE);
        SendMessageW(g_overlay->hEdit, EM_SETPASSWORDCHAR, L'\u25CF', 0);
        g_originalEditProc = (WNDPROC)SetWindowLongPtrW(g_overlay->hEdit, GWLP_WNDPROC, (LONG_PTR)OverlayEditProc);
    }

    QueuedBlock item{};
    if (!PopBlock(item)) return;

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    if (g_blurBmp) {
        DeleteObject(g_blurBmp);
        g_blurBmp = nullptr;
    }
    g_blurBmp = CaptureAndBlurScreen(sw, sh);

    g_overlay->item = std::move(item);
        g_overlay->attempts = 0;
        g_overlay->overlayVisible = true;
        g_overlay->unlockHover = false;
        g_overlay->denyHover = false;
        g_overlay->animPhase = 0.0f;
        SetWindowTextW(g_overlay->hEdit, L"");

    int cx = (sw - 560) / 2;
    int cy = (sh - 470) / 2;
    SetWindowPos(g_overlay->hEdit, nullptr, cx + 52, cy + 274, 560 - 104, 28, SWP_NOZORDER);
    ShowWindow(g_overlay->hEdit, SW_SHOW);
    SetWindowPos(g_hOverlay, HWND_TOPMOST, 0, 0, sw, sh, SWP_SHOWWINDOW);
    SetTimer(g_hOverlay, 2, 16, nullptr);
    SetForegroundWindow(g_hOverlay);
    SetFocus(g_overlay->hEdit);
    InvalidateRect(g_hOverlay, nullptr, TRUE);
}

void CleanupOverlay() {
    if (g_hOverlay) {
        DestroyWindow(g_hOverlay);
        g_hOverlay = nullptr;
    }
}

bool ShowExitPinDialog(HINSTANCE hInst, HWND hwndParent) {
    std::string pin = InputBox(hInst, hwndParent, L"Exit Peace's Vault", L"Enter your PIN to exit:", true);
    if (pin.empty()) return false;
    return VerifyPinWithFeedback(hInst, hwndParent, pin, L"Exit Application");
}

void ShowChangePinDialog(HINSTANCE hInst, HWND hwndParent) {
    std::string current = InputBox(hInst, hwndParent, L"Change PIN", L"Enter current PIN:", true);
    if (current.empty()) return;
    if (!VerifyPinWithFeedback(hInst, hwndParent, current, L"Change PIN")) {
        return;
    }

    std::string next = ShowSetupDialog(hInst, hwndParent);
    if (!next.empty()) {
        SetPin(next);
        ShowThemedAlert(hInst, hwndParent, L"PIN Updated", L"PIN updated successfully.", false);
    }
}

void ShowResetPinDialog(HINSTANCE hInst, HWND hwndParent) {
    std::wstring code = ShowTextPromptDialog(hInst, hwndParent, L"Reset PIN",
        L"Enter your recovery code:");
    if (code.empty()) return;

    std::string next = ShowSetupDialog(hInst, hwndParent);
    if (next.empty()) return;

    if (ResetPinWithRecoveryCode(W2U(code), next)) {
        ShowThemedAlert(hInst, hwndParent, L"PIN Reset", L"PIN reset successfully.", false);
    } else {
        CaptureIntruderPhotoAsync(L"Reset PIN");
        ShowThemedAlert(hInst, hwndParent, L"Reset Failed",
            L"Recovery code did not match. PIN was not changed.", true);
    }
}

void ShowWebhookDialog(HINSTANCE hInst, HWND hwndParent) {
    const bool hasWebhook = !GetWebhookUrl().empty();
    const wchar_t* pinPrompt = hasWebhook ? L"Enter PIN to change Webhook:" : L"Enter PIN to set Webhook:";
    std::string pin = InputBox(hInst, hwndParent, L"Discord Webhook", pinPrompt, true);
    if (pin.empty()) return;
    if (!VerifyPinWithFeedback(hInst, hwndParent, pin, hasWebhook ? L"Change Webhook" : L"Set Webhook")) {
        return;
    }

    std::string webhook = InputBox(hInst, hwndParent, L"Discord Webhook",
        L"Paste webhook URL (leave blank to disable):", false);
    SetWebhookUrl(webhook);

    if (!webhook.empty()) {
        ShowThemedAlert(hInst, hwndParent, L"Webhook Updated", L"Webhook saved.", false);
    } else {
        ShowThemedAlert(hInst, hwndParent, L"Webhook Updated", L"Webhook disabled.", false);
    }
}

struct ManageCtx {
    HWND hList{};
    HWND hStatus{};
    UniqueGDIObject fTitle;
    UniqueGDIObject fBody;
    bool done{};
};

static void RefreshManageList(ManageCtx* ctx) {
    ListView_DeleteAllItems(ctx->hList);
    auto items = GetBlocked();
    for (int i = 0; i < (int)items.size(); ++i) {
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = i;
        item.pszText = const_cast<wchar_t*>(items[i].type.c_str());
        ListView_InsertItem(ctx->hList, &item);
        ListView_SetItemText(ctx->hList, i, 1, const_cast<wchar_t*>(items[i].label.c_str()));
        ListView_SetItemText(ctx->hList, i, 2, const_cast<wchar_t*>(items[i].value.c_str()));
    }

    wchar_t status[64]{};
    wsprintfW(status, L"%d item(s) blocked", (int)items.size());
    SetWindowTextW(ctx->hStatus, status);
}

static LRESULT CALLBACK ManageProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = reinterpret_cast<ManageCtx*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_CREATE: {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        ctx = reinterpret_cast<ManageCtx*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)ctx);

        ctx->fTitle.reset(ui::MakeFont(14, FW_BOLD));
        ctx->fBody.reset(ui::MakeFont(10));

        HWND title = CreateWindowExW(0, L"STATIC", L"Blocked Items", WS_CHILD | WS_VISIBLE,
            16, 14, 220, 24, hwnd, nullptr, cs->hInstance, nullptr);
        SendMessageW(title, WM_SETFONT, (WPARAM)ctx->fTitle.get(), TRUE);

        ctx->hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            16, 46, 688, 318, hwnd, (HMENU)500, cs->hInstance, nullptr);
        SendMessageW(ctx->hList, WM_SETFONT, (WPARAM)ctx->fBody.get(), TRUE);
        ListView_SetExtendedListViewStyle(ctx->hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        ListView_SetBkColor(ctx->hList, ui::kSurfaceStrong);
        ListView_SetTextBkColor(ctx->hList, ui::kSurfaceStrong);
        ListView_SetTextColor(ctx->hList, ui::kText);

        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = 90;
        col.pszText = (LPWSTR)L"Type";
        ListView_InsertColumn(ctx->hList, 0, &col);
        col.cx = 190;
        col.pszText = (LPWSTR)L"Label";
        ListView_InsertColumn(ctx->hList, 1, &col);
        col.cx = 380;
        col.pszText = (LPWSTR)L"Path / Value";
        ListView_InsertColumn(ctx->hList, 2, &col);

        ctx->hStatus = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            16, 372, 280, 22, hwnd, nullptr, cs->hInstance, nullptr);
        SendMessageW(ctx->hStatus, WM_SETFONT, (WPARAM)ctx->fBody.get(), TRUE);

        HWND removeBtn = CreateWindowExW(0, L"BUTTON", L"Remove Selected", WS_CHILD | WS_VISIBLE,
            16, 402, 160, 34, hwnd, (HMENU)501, cs->hInstance, nullptr);
        SendMessageW(removeBtn, WM_SETFONT, (WPARAM)ctx->fBody.get(), TRUE);

        HWND closeBtn = CreateWindowExW(0, L"BUTTON", L"Close", WS_CHILD | WS_VISIBLE,
            596, 402, 108, 34, hwnd, (HMENU)IDCANCEL, cs->hInstance, nullptr);
        SendMessageW(closeBtn, WM_SETFONT, (WPARAM)ctx->fBody.get(), TRUE);

        RefreshManageList(ctx);
        return 0;
    }
    case WM_NOTIFY:
        if (((LPNMHDR)lp)->idFrom == 500 && ((LPNMHDR)lp)->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lp);
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                bool odd = (cd->nmcd.dwItemSpec % 2) != 0;
                cd->clrText = ui::kText;
                cd->clrTextBk = odd ? RGB(23, 35, 50) : ui::kSurfaceStrong;
                return CDRF_NEWFONT;
            }
        }
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == 501) {
            int selected = ListView_GetNextItem(ctx->hList, -1, LVNI_SELECTED);
            if (selected < 0) {
                ShowThemedAlert((HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE), hwnd,
                    L"Selection Required", L"Select an item first.", true);
                return 0;
            }

            auto items = GetBlocked();
            std::wstring label = (selected >= 0 && selected < (int)items.size()) ? items[selected].label : L"item";
            RemoveBlocked(selected);
            RefreshManageList(ctx);

            std::wstring messageText = L"Removed: " + label;
            ShowThemedAlert((HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE), hwnd,
                L"Rule Removed", messageText.c_str(), false);
        } else if (LOWORD(wp) == IDCANCEL) {
            ctx->done = true;
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, ui::kMuted);
        static HBRUSH br = CreateSolidBrush(ui::kSurface);
        return (LRESULT)br;
    }
    case WM_CTLCOLORBTN: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetBkMode(dc, TRANSPARENT);
        static HBRUSH br = CreateSolidBrush(ui::kSurface);
        return (LRESULT)br;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc{};
        GetClientRect(hwnd, &rc);
        ui::FillVerticalGradient(dc, rc, ui::kBackdropTop, ui::kBackdropBottom);
        RECT card{ 8, 8, rc.right - 8, rc.bottom - 8 };
        ui::DrawRoundedCard(dc, card, 14, ui::kSurface, ui::kSurfaceStroke, 1);
        ui::DrawTopAccent(dc, card);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CLOSE:
        ctx->done = true;
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        return 0;
    case WM_NCHITTEST: {
        LRESULT hit = DefWindowProcW(hwnd, msg, wp, lp);
        if (hit == HTCLIENT) {
            POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            ScreenToClient(hwnd, &pt);
            if (pt.y <= 42) return HTCAPTION;
        }
        return hit;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

void ShowManageDialog(HINSTANCE hInst, HWND hwndParent) {
    std::string pin = InputBox(hInst, hwndParent, L"Manage Blocked Items", L"Enter PIN to continue:", true);
    if (pin.empty()) return;
    if (!VerifyPinWithFeedback(hInst, hwndParent, pin, L"Manage Blocked Items")) {
        return;
    }

    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{ sizeof(wc) };
        wc.lpfnWndProc = ManageProc;
        wc.hInstance = hInst;
        wc.lpszClassName = L"ALManageDialog";
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
        registered = true;
    }

    ManageCtx ctx{};
    RECT rc = ui::CenterRect(720, 450);
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, L"ALManageDialog", L"Manage Blocked Items",
        WS_POPUP | WS_VISIBLE,
        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, hwndParent, nullptr, hInst, &ctx);
    if (!hwnd) return;

    if (hwndParent) EnableWindow(hwndParent, FALSE);
    MSG msg{};
    while (!ctx.done) {
        int ret = GetMessageW(&msg, nullptr, 0, 0);
        if (ret <= 0) {
            ctx.done = true;
            break;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (hwndParent) {
        EnableWindow(hwndParent, TRUE);
        SetForegroundWindow(hwndParent);
    }
}

namespace {
constexpr int IDC_DASH_LIST = 7100;
constexpr int IDC_DASH_STATUS = 7101;
constexpr int IDC_DASH_ADD_ITEM = 7102;
constexpr int IDC_DASH_ADD_APP = 7103;
constexpr int IDC_DASH_ADD_FOLDER = 7104;
constexpr int IDC_DASH_ADD_SITE = 7105;
constexpr int IDC_DASH_MANAGE = 7106;
constexpr int IDC_DASH_CHANGE_PIN = 7107;
constexpr int IDC_DASH_RESET_PIN = 7108;
constexpr int IDC_DASH_WEBHOOK = 7109;
constexpr int IDC_DASH_INTRUDERS = 7110;
constexpr int IDC_DASH_AUTOSTART = 7111;
constexpr int IDC_DASH_SHELL = 7112;
constexpr int IDC_DASH_CLOSE = 7113;
constexpr int IDC_DASH_EXIT = 7114;
constexpr int IDC_DASH_LOGALL = 7115;

struct DashboardCtx {
    HWND hwnd{};
    HWND hwndHost{};
    HWND hList{};
    HWND hAutoStart{};
    HWND hShell{};
    HWND hLogAll{};
    HWND hButtons[16]{};
    int buttonCount{};
    UniqueGDIObject fTitle;
    UniqueGDIObject fBody;
    UniqueGDIObject fButton;
    std::wstring statusText;
    std::wstring listSignature;
    RECT panelList{};
    RECT panelActions{};
    RECT statusRect{};
};

DashboardCtx g_dashboard{};

void DashboardPostHostCommand(DashboardCtx* ctx, UINT cmd) {
    if (!ctx || !ctx->hwndHost) return;
    PostMessageW(ctx->hwndHost, WM_COMMAND, MAKEWPARAM(cmd, 0), 0);
}

std::wstring BuildListSignature(const std::vector<BlockEntry>& items) {
    std::wstring sig;
    sig.reserve(items.size() * 24);
    for (const auto& it : items) {
        sig += it.type;
        sig += L"|";
        sig += it.label;
        sig += L"|";
        sig += it.value;
        sig += L"\n";
    }
    return sig;
}

void RefreshDashboardList(DashboardCtx* ctx) {
    if (!ctx || !ctx->hList) return;

    auto items = GetBlocked();
    std::wstring signature = BuildListSignature(items);
    if (signature != ctx->listSignature) {
        ctx->listSignature = signature;
        SendMessageW(ctx->hList, WM_SETREDRAW, FALSE, 0);
        ListView_DeleteAllItems(ctx->hList);
        for (int i = 0; i < (int)items.size(); ++i) {
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = i;
            item.pszText = const_cast<wchar_t*>(items[i].type.c_str());
            ListView_InsertItem(ctx->hList, &item);
            ListView_SetItemText(ctx->hList, i, 1, const_cast<wchar_t*>(items[i].label.c_str()));
            ListView_SetItemText(ctx->hList, i, 2, const_cast<wchar_t*>(items[i].value.c_str()));
        }
        SendMessageW(ctx->hList, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(ctx->hList, nullptr, FALSE);
        UpdateWindow(ctx->hList);
    }

    std::wstring status = L"Protected rules: ";
    wchar_t num[24]{};
    wsprintfW(num, L"%d", (int)items.size());
    status += num;

    if (IsPinLocked()) {
        status += L" | Vault locked: ";
        status += FormatLockDurationText(GetPinLockRemainingSeconds());
    } else {
        wchar_t remaining[64]{};
        wsprintfW(remaining, L" | Attempts before lock: %d", GetRemainingPinAttempts());
        status += remaining;
    }

    status += L" | Standalone mode | Close=Tray | Kill App button asks for PIN";
    if (status != ctx->statusText) {
        ctx->statusText = status;
        InvalidateRect(ctx->hwnd, &ctx->statusRect, FALSE);
    }

    std::wstring autoLabel = IsAutoStartEnabled() ? L"Startup: ON" : L"Startup: OFF";
    SetWindowTextW(ctx->hAutoStart, autoLabel.c_str());

    std::wstring shellLabel = IsShellIntegrationEnabled() ? L"Explorer Protect: ON" : L"Explorer Protect: OFF";
    SetWindowTextW(ctx->hShell, shellLabel.c_str());

    std::wstring logAllLabel = IsLogAllEnabled() ? L"Log Opened Items: ON" : L"Log Opened Items: OFF";
    if (ctx->hLogAll) SetWindowTextW(ctx->hLogAll, logAllLabel.c_str());
}

void LayoutDashboard(HWND hwnd, DashboardCtx* ctx) {
    if (!ctx) return;
    RECT rc{};
    GetClientRect(hwnd, &rc);

    const int pad = 24;
    const int gap = 18;
    const int headerH = 80;
    int innerW = rc.right - rc.left - pad * 2;
    int innerH = rc.bottom - rc.top - pad * 2;
    if (innerW < 760) innerW = 760;
    if (innerH < 480) innerH = 480;

    int rightW = (std::min)(320, (std::max)(250, innerW / 3));
    int leftW = innerW - rightW - gap;
    if (leftW < 420) {
        leftW = 420;
        rightW = innerW - leftW - gap;
    }

    int top = pad + headerH;
    int mainH = innerH - headerH - 20;
    if (mainH < 300) mainH = 300;

    ctx->panelList = { pad, top, pad + leftW, top + mainH };
    ctx->panelActions = { ctx->panelList.right + gap, top, ctx->panelList.right + gap + rightW, top + mainH };

    const int listInset = 14;
    int listX = ctx->panelList.left + listInset;
    int listY = ctx->panelList.top + listInset;
    int listW = (ctx->panelList.right - ctx->panelList.left) - listInset * 2;
    int listH = (ctx->panelList.bottom - ctx->panelList.top) - listInset * 2 - 34;
    if (listH < 120) listH = 120;
    MoveWindow(ctx->hList, listX, listY, listW, listH, TRUE);
    ctx->statusRect = { listX, ctx->panelList.bottom - 34, listX + listW, ctx->panelList.bottom - 12 };

    int bx = ctx->panelActions.left + 12;
    int by = ctx->panelActions.top + 14;
    int bw = (ctx->panelActions.right - ctx->panelActions.left) - 24;
    for (int i = 0; i < ctx->buttonCount; ++i) {
        MoveWindow(ctx->hButtons[i], bx, by, bw, 34, TRUE);
        by += 40;
    }

    int c1 = 110;
    int c2 = (std::max)(180, listW / 3);
    int c3 = (std::max)(200, listW - c1 - c2 - 24);
    ListView_SetColumnWidth(ctx->hList, 0, c1);
    ListView_SetColumnWidth(ctx->hList, 1, c2);
    ListView_SetColumnWidth(ctx->hList, 2, c3);
}

void DrawDashboardButton(const DRAWITEMSTRUCT* dis) {
    if (!dis || dis->CtlType != ODT_BUTTON) return;
    HDC dc = dis->hDC;
    RECT rc = dis->rcItem;

    const bool pressed = (dis->itemState & ODS_SELECTED) != 0;
    const bool focused = (dis->itemState & ODS_FOCUS) != 0;
    bool danger = (dis->CtlID == IDC_DASH_EXIT);
    COLORREF fill = danger
        ? (pressed ? RGB(96, 26, 24) : RGB(78, 21, 20))
        : (pressed ? RGB(74, 32, 22) : RGB(52, 21, 18));
    COLORREF stroke = danger
        ? (pressed ? RGB(255, 124, 110) : RGB(181, 62, 57))
        : (pressed ? RGB(255, 193, 98) : RGB(145, 73, 50));
    ui::DrawRoundedCard(dc, rc, 10, fill, stroke, 1);

    wchar_t text[160]{};
    GetWindowTextW(reinterpret_cast<HWND>(dis->hwndItem), text, _countof(text));
    HFONT font = reinterpret_cast<HFONT>(SendMessageW(reinterpret_cast<HWND>(dis->hwndItem), WM_GETFONT, 0, 0));
    HGDIOBJ oldFont = font ? SelectObject(dc, font) : nullptr;
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, danger ? RGB(255, 210, 204) : ui::kText);
    RECT tx = rc;
    DrawTextW(dc, text, -1, &tx, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    if (oldFont) SelectObject(dc, oldFont);

    if (focused) {
        RECT fr = rc;
        InflateRect(&fr, -5, -5);
        DrawFocusRect(dc, &fr);
    }
}

void PaintDashboard(HWND hwnd, DashboardCtx* ctx) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc{};
    GetClientRect(hwnd, &rc);

    ui::FillVerticalGradient(dc, rc, ui::kBackdropTop, ui::kBackdropBottom);

    RECT card{ 16, 16, rc.right - 16, rc.bottom - 16 };
    ui::DrawRoundedCard(dc, card, 16, ui::kSurface, ui::kSurfaceStroke, 1);
    ui::DrawTopAccent(dc, card);

    if (ctx) {
        ui::DrawRoundedCard(dc, ctx->panelList, 14, RGB(30, 11, 11), RGB(97, 44, 32), 1);
        ui::DrawRoundedCard(dc, ctx->panelActions, 14, RGB(28, 10, 10), RGB(97, 44, 32), 1);

        RECT title{ 34, 22, rc.right - 40, 72 };
        ui::DrawTextLine(dc, title, APP_NAME_L, (HFONT)ctx->fTitle.get(), ui::kText, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        RECT sub{ 36, 64, rc.right - 40, 88 };
        ui::DrawTextLine(dc, sub, L"Dashboard", (HFONT)ctx->fBody.get(), ui::kMuted, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        RECT status = ctx->statusRect;
        ui::DrawTextLine(dc, status, ctx->statusText.c_str(), (HFONT)ctx->fBody.get(), ui::kMuted, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
    }

    EndPaint(hwnd, &ps);
}

LRESULT CALLBACK DashboardProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = reinterpret_cast<DashboardCtx*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_CREATE: {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        ctx = reinterpret_cast<DashboardCtx*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)ctx);
        ctx->hwnd = hwnd;

        ctx->fTitle.reset(ui::MakeFont(30, FW_BOLD, L"Segoe Script"));
        ctx->fBody.reset(ui::MakeFont(10, FW_NORMAL, L"Bahnschrift"));
        ctx->fButton.reset(ui::MakeFont(10, FW_SEMIBOLD, L"Bahnschrift"));

        ctx->hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            28, 110, 640, 430, hwnd, (HMENU)(INT_PTR)IDC_DASH_LIST, cs->hInstance, nullptr);
        SendMessageW(ctx->hList, WM_SETFONT, (WPARAM)ctx->fBody.get(), TRUE);
        SetWindowTheme(ctx->hList, L"", L"");
        ListView_SetExtendedListViewStyle(ctx->hList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_INFOTIP);
        ListView_SetBkColor(ctx->hList, ui::kSurfaceStrong);
        ListView_SetTextBkColor(ctx->hList, ui::kSurfaceStrong);
        ListView_SetTextColor(ctx->hList, ui::kText);

        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.cx = 110;
        col.pszText = (LPWSTR)L"Type";
        ListView_InsertColumn(ctx->hList, 0, &col);
        col.cx = 210;
        col.pszText = (LPWSTR)L"Label";
        ListView_InsertColumn(ctx->hList, 1, &col);
        col.cx = 300;
        col.pszText = (LPWSTR)L"Path / Value";
        ListView_InsertColumn(ctx->hList, 2, &col);

        ctx->statusText = L"Loading...";

        auto makeBtn = [&](int id, const wchar_t* text, int x, int y, int w = 230) {
            HWND b = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                x, y, w, 34, hwnd, (HMENU)(INT_PTR)id, cs->hInstance, nullptr);
            SendMessageW(b, WM_SETFONT, (WPARAM)ctx->fButton.get(), TRUE);
            if (ctx->buttonCount < (int)_countof(ctx->hButtons)) {
                ctx->hButtons[ctx->buttonCount++] = b;
            }
            return b;
        };

        int bx = 700;
        int by = 110;
        makeBtn(IDC_DASH_ADD_ITEM, L"Add Item...", bx, by); by += 40;
        makeBtn(IDC_DASH_ADD_APP, L"Block App By Name...", bx, by); by += 40;
        makeBtn(IDC_DASH_ADD_FOLDER, L"Block Folder...", bx, by); by += 40;
        makeBtn(IDC_DASH_ADD_SITE, L"Block Website...", bx, by); by += 40;
        makeBtn(IDC_DASH_MANAGE, L"Manage Blocked Items...", bx, by); by += 40;
        makeBtn(IDC_DASH_CHANGE_PIN, L"Change PIN...", bx, by); by += 40;
        makeBtn(IDC_DASH_RESET_PIN, L"Reset PIN (Recovery)...", bx, by); by += 40;
        makeBtn(IDC_DASH_WEBHOOK, L"Discord Webhook...", bx, by); by += 40;
        makeBtn(IDC_DASH_INTRUDERS, L"Open Intruders Folder...", bx, by); by += 40;
        ctx->hAutoStart = makeBtn(IDC_DASH_AUTOSTART, L"Startup: ON", bx, by); by += 40;
        ctx->hShell = makeBtn(IDC_DASH_SHELL, L"Explorer Protect: ON", bx, by); by += 40;
        ctx->hLogAll = makeBtn(IDC_DASH_LOGALL, L"Log Opened Items: OFF", bx, by); by += 40;
        makeBtn(IDC_DASH_CLOSE, L"Close To Tray", bx, by); by += 40;
        makeBtn(IDC_DASH_EXIT, L"Kill App (PIN)...", bx, by);

        LayoutDashboard(hwnd, ctx);
        SetTimer(hwnd, 2, 1300, nullptr);
        RefreshDashboardList(ctx);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_TIMER:
        if (wp == 2) {
            RefreshDashboardList(ctx);
        }
        return 0;
    case WM_DRAWITEM:
        DrawDashboardButton(reinterpret_cast<DRAWITEMSTRUCT*>(lp));
        return TRUE;
    case WM_SIZE:
        if (wp == SIZE_MINIMIZED) {
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        }
        if (ctx) {
            LayoutDashboard(hwnd, ctx);
        }
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_DASH_ADD_ITEM: DashboardPostHostCommand(ctx, IDM_ADD_FILE); break;
        case IDC_DASH_ADD_APP: DashboardPostHostCommand(ctx, IDM_ADD_APP); break;
        case IDC_DASH_ADD_FOLDER: DashboardPostHostCommand(ctx, IDM_ADD_FOLDER); break;
        case IDC_DASH_ADD_SITE: DashboardPostHostCommand(ctx, IDM_ADD_URL); break;
        case IDC_DASH_MANAGE: DashboardPostHostCommand(ctx, IDM_MANAGE); break;
        case IDC_DASH_CHANGE_PIN: DashboardPostHostCommand(ctx, IDM_CHANGE_PIN); break;
        case IDC_DASH_RESET_PIN: DashboardPostHostCommand(ctx, IDM_RESET_PIN); break;
        case IDC_DASH_WEBHOOK: DashboardPostHostCommand(ctx, IDM_SET_WEBHOOK); break;
        case IDC_DASH_INTRUDERS: DashboardPostHostCommand(ctx, IDM_OPEN_INTRUDERS); break;
        case IDC_DASH_AUTOSTART:
            SetAutoStart(!IsAutoStartEnabled());
            RefreshDashboardList(ctx);
            break;
        case IDC_DASH_SHELL:
            SetShellIntegrationEnabled(!IsShellIntegrationEnabled());
            RefreshDashboardList(ctx);
            break;
        case IDC_DASH_LOGALL:
            SetLogAllEnabled(!IsLogAllEnabled());
            RefreshDashboardList(ctx);
            break;
        case IDC_DASH_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        case IDC_DASH_EXIT:
            DashboardPostHostCommand(ctx, IDM_EXIT);
            return 0;
        default:
            break;
        }
        return 0;
    case WM_PAINT:
        PaintDashboard(hwnd, ctx);
        return 0;
    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, 2);
        ctx->hwnd = nullptr;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
} // namespace

void ShowDashboard(HINSTANCE hInst, HWND hwndParent) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{ sizeof(wc) };
        wc.lpfnWndProc = DashboardProc;
        wc.hInstance = hInst;
        wc.lpszClassName = L"PeaceVaultDashboard";
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
        registered = true;
    }

    g_dashboard.hwndHost = hwndParent;
    if (!g_dashboard.hwnd) {
        RECT rc = ui::CenterRect(1180, 720);
        g_dashboard.hwnd = CreateWindowExW(WS_EX_TOPMOST, L"PeaceVaultDashboard", APP_NAME_L,
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN,
            rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
            hwndParent, nullptr, hInst, &g_dashboard);
        if (!g_dashboard.hwnd) return;
    }

    RefreshDashboardList(&g_dashboard);
    ShowWindow(g_dashboard.hwnd, SW_SHOW);
    SetForegroundWindow(g_dashboard.hwnd);
}

void FocusDashboard() {
    if (!g_dashboard.hwnd) return;
    ShowWindow(g_dashboard.hwnd, SW_SHOW);
    SetForegroundWindow(g_dashboard.hwnd);
}

static std::wstring FormatRemainingTime(unsigned long long seconds) {
    unsigned long long hours = seconds / 3600ULL;
    unsigned long long mins = (seconds % 3600ULL) / 60ULL;
    wchar_t buf[96]{};
    wsprintfW(buf, L"%lluh %llum", hours, mins);
    return buf;
}

bool PromptForLaunchPin(HINSTANCE hInst, HWND hwndParent) {
    for (;;) {
        if (IsPinLocked()) {
            std::wstring msg = L"Too many wrong PIN attempts.\nVault is locked for ";
            msg += FormatRemainingTime(GetPinLockRemainingSeconds());
            msg += L".";
            ShowThemedAlert(hInst, hwndParent, L"Vault Locked", msg.c_str(), true);
            return false;
        }

        std::wstring pin = ShowTextPromptDialog(hInst, hwndParent, APP_NAME_L, L"Enter your PIN to open the dashboard:", true);
        if (pin.empty()) return false;
        if (VerifyPin(W2U(pin))) return true;

        if (IsPinLocked()) {
            std::wstring msg = L"Too many wrong PIN attempts.\nVault is locked for ";
            msg += FormatRemainingTime(GetPinLockRemainingSeconds());
            msg += L".";
            ShowThemedAlert(hInst, hwndParent, L"Vault Locked", msg.c_str(), true);
            return false;
        }

        wchar_t warn[128]{};
        wsprintfW(warn, L"Wrong PIN. %d attempt(s) remaining.", GetRemainingPinAttempts());
        ShowThemedAlert(hInst, hwndParent, L"Access Denied", warn, true);
    }
}
