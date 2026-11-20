#pragma once
#include <windows.h>

void InitTray(HWND hwnd, HINSTANCE hInst);
void CleanupTray(HWND hwnd);
void SetTrayTip(const wchar_t* tip);
