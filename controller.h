#pragma once

#include <windows.h>

void ShowTrayMenu(HWND hwnd);

bool HandleTrayCommand(HWND hwnd, HINSTANCE hInst, UINT commandId, bool& isExiting, const wchar_t* exitEventName);
