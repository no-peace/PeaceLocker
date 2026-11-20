#include "splash.h"
#include "common.h"
#include <windows.h>
#include <string>
#include <vector>

#pragma comment(lib, "msimg32.lib")

namespace {
constexpr wchar_t kSplashClass[] = L"ALStartupSplash";

struct SplashCtx {
    HINSTANCE hInst{};
    UniqueGDIObject fBrand;
    UniqueGDIObject fTitle;
    UniqueGDIObject fSub;
    UniqueGDIObject fStage;
    std::vector<std::wstring> stages;
    std::wstring status;
    float progress{};
    float targetProgress{};
    int stageIndex{};
    DWORD startedAt{};
    bool done{};
};

HFONT MakeFont(int pt, int weight, const wchar_t* face) {
    HDC screen = GetDC(nullptr);
    int dpi = GetDeviceCaps(screen, LOGPIXELSY);
    ReleaseDC(nullptr, screen);
    return CreateFontW(
        -MulDiv(pt, dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, face);
}

void FillGradient(HDC dc, const RECT& rc, COLORREF top, COLORREF bottom) {
    TRIVERTEX v[2] = {
        { rc.left, rc.top, (COLOR16)(GetRValue(top) << 8), (COLOR16)(GetGValue(top) << 8), (COLOR16)(GetBValue(top) << 8), 0xFFFF },
        { rc.right, rc.bottom, (COLOR16)(GetRValue(bottom) << 8), (COLOR16)(GetGValue(bottom) << 8), (COLOR16)(GetBValue(bottom) << 8), 0xFFFF }
    };
    GRADIENT_RECT g{ 0, 1 };
    GradientFill(dc, v, 2, &g, 1, GRADIENT_FILL_RECT_V);
}

void DrawRoundedRect(HDC dc, const RECT& rc, int radius, COLORREF fill, COLORREF stroke) {
    HBRUSH br = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, stroke);
    HGDIOBJ oldBr = SelectObject(dc, br);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    RoundRect(dc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);
    SelectObject(dc, oldBr);
    SelectObject(dc, oldPen);
    DeleteObject(br);
    DeleteObject(pen);
}

void DrawTextLine(HDC dc, const RECT& rc, const wchar_t* text, HFONT font, COLORREF color, UINT flags) {
    HGDIOBJ oldFont = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    DrawTextW(dc, text, -1, const_cast<RECT*>(&rc), flags);
    SelectObject(dc, oldFont);
}

void PaintSplash(HWND hwnd, SplashCtx* ctx) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc{};
    GetClientRect(hwnd, &rc);

    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right - rc.left, rc.bottom - rc.top);
    HGDIOBJ oldBmp = SelectObject(mem, bmp);

    FillGradient(mem, rc, RGB(34, 11, 9), RGB(13, 5, 5));

    RECT glowA{ rc.right - 280, -140, rc.right + 210, 220 };
    HBRUSH glowBrA = CreateSolidBrush(RGB(86, 24, 18));
    HPEN glowPenA = CreatePen(PS_SOLID, 1, RGB(128, 44, 32));
    HGDIOBJ oldBr = SelectObject(mem, glowBrA);
    HGDIOBJ oldPen = SelectObject(mem, glowPenA);
    Ellipse(mem, glowA.left, glowA.top, glowA.right, glowA.bottom);
    SelectObject(mem, oldBr);
    SelectObject(mem, oldPen);
    DeleteObject(glowBrA);
    DeleteObject(glowPenA);

    RECT glowB{ -240, rc.bottom - 260, 220, rc.bottom + 120 };
    HBRUSH glowBrB = CreateSolidBrush(RGB(64, 17, 15));
    HPEN glowPenB = CreatePen(PS_SOLID, 1, RGB(108, 34, 28));
    oldBr = SelectObject(mem, glowBrB);
    oldPen = SelectObject(mem, glowPenB);
    Ellipse(mem, glowB.left, glowB.top, glowB.right, glowB.bottom);
    SelectObject(mem, oldBr);
    SelectObject(mem, oldPen);
    DeleteObject(glowBrB);
    DeleteObject(glowPenB);

    RECT card{ 24, 24, rc.right - 24, rc.bottom - 24 };
    DrawRoundedRect(mem, card, 18, RGB(33, 11, 11), RGB(96, 38, 30));
    RECT accent{ card.left + 1, card.top + 1, card.right - 1, card.top + 7 };
    FillGradient(mem, accent, RGB(255, 200, 86), RGB(233, 116, 41));

    RECT brand{ card.left + 30, card.top + 22, card.right - 30, card.top + 96 };
    DrawTextLine(mem, brand, APP_NAME_L, (HFONT)ctx->fBrand.get(), RGB(255, 204, 92), DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    RECT title{ card.left + 34, card.top + 92, card.right - 34, card.top + 118 };
    DrawTextLine(mem, title, L"Secure Startup", (HFONT)ctx->fTitle.get(), RGB(236, 170, 123), DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    RECT sub{ card.left + 34, card.top + 124, card.right - 34, card.top + 148 };
    DrawTextLine(mem, sub, L"Preparing layers and vault controls...", (HFONT)ctx->fSub.get(), RGB(204, 154, 126), DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    RECT stageRc{ card.left + 34, card.top + 182, card.right - 34, card.top + 210 };
    DrawTextLine(mem, stageRc, ctx->status.c_str(), (HFONT)ctx->fStage.get(), RGB(255, 232, 206), DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    RECT track{ card.left + 34, card.bottom - 52, card.right - 34, card.bottom - 30 };
    DrawRoundedRect(mem, track, 8, RGB(18, 8, 8), RGB(85, 38, 30));
    int width = track.right - track.left - 2;
    int filled = static_cast<int>(width * ctx->progress);
    if (filled > 0) {
        RECT fill{ track.left + 1, track.top + 1, track.left + 1 + filled, track.bottom - 1 };
        FillGradient(mem, fill, RGB(255, 202, 102), RGB(232, 112, 44));
    }

    RECT pct{ track.right - 96, track.top - 30, track.right, track.top - 6 };
    wchar_t pctText[32]{};
    wsprintfW(pctText, L"%d%%", (int)(ctx->progress * 100.0f));
    DrawTextLine(mem, pct, pctText, (HFONT)ctx->fStage.get(), RGB(247, 202, 168), DT_RIGHT | DT_SINGLELINE | DT_VCENTER);

    BitBlt(dc, 0, 0, rc.right - rc.left, rc.bottom - rc.top, mem, 0, 0, SRCCOPY);

    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

LRESULT CALLBACK SplashProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = reinterpret_cast<SplashCtx*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_CREATE: {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
        ctx = reinterpret_cast<SplashCtx*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)ctx);

        ctx->fBrand.reset(MakeFont(42, FW_BOLD, L"Segoe Script"));
        ctx->fTitle.reset(MakeFont(12, FW_SEMIBOLD, L"Bahnschrift"));
        ctx->fSub.reset(MakeFont(10, FW_NORMAL, L"Bahnschrift"));
        ctx->fStage.reset(MakeFont(11, FW_SEMIBOLD, L"Bahnschrift"));
        ctx->startedAt = GetTickCount();
        ctx->stages = {
            L"Initializing secure vault core...",
            L"Validating PIN lock policy...",
            L"Preparing process guard and monitor...",
            L"Applying startup and explorer protection...",
            L"Launching Peace's Vault dashboard..."
        };
        ctx->status = ctx->stages.front();
        ctx->targetProgress = 0.18f;

        SetTimer(hwnd, 1, 33, nullptr);
        SetTimer(hwnd, 2, 650, nullptr);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_TIMER:
        if (!ctx) return 0;
        if (wp == 1) {
            ctx->progress += (ctx->targetProgress - ctx->progress) * 0.16f;
            if (ctx->progress > 1.0f) ctx->progress = 1.0f;
            InvalidateRect(hwnd, nullptr, FALSE);
        } else if (wp == 2) {
            if (ctx->stageIndex + 1 < static_cast<int>(ctx->stages.size())) {
                ctx->stageIndex++;
                ctx->status = ctx->stages[ctx->stageIndex];
                ctx->targetProgress = 0.2f + (0.73f * (ctx->stageIndex + 1) / static_cast<float>(ctx->stages.size()));
                InvalidateRect(hwnd, nullptr, FALSE);
            } else {
                ctx->targetProgress = 1.0f;
                DWORD elapsed = GetTickCount() - ctx->startedAt;
                if (elapsed > 2400 && ctx->progress > 0.985f) {
                    ctx->done = true;
                    DestroyWindow(hwnd);
                }
            }
        }
        return 0;
    case WM_NCHITTEST:
        return HTCAPTION;
    case WM_PAINT:
        if (ctx) PaintSplash(hwnd, ctx);
        return 0;
    case WM_CLOSE:
        if (ctx) ctx->done = true;
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (ctx) {
            KillTimer(hwnd, 1);
            KillTimer(hwnd, 2);
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
} // namespace

void ShowStartupSplash(HINSTANCE hInst) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{ sizeof(wc) };
        wc.lpfnWndProc = SplashProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.lpszClassName = kSplashClass;
        RegisterClassExW(&wc);
        registered = true;
    }

    SplashCtx ctx{};
    ctx.hInst = hInst;

    const int width = 940;
    const int height = 560;
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        kSplashClass,
        L"",
        WS_POPUP | WS_VISIBLE,
        (sw - width) / 2, (sh - height) / 2,
        width, height,
        nullptr, nullptr, hInst, &ctx);
    if (!hwnd) return;

    MSG msg{};
    while (!ctx.done) {
        int ret = GetMessageW(&msg, nullptr, 0, 0);
        if (ret <= 0) break;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}
