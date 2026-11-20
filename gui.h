#pragma once
#include <windows.h>
#include <string>

// Full-screen PIN overlay
void ShowPinOverlay(HINSTANCE hInst, HWND hwndParent);
void CleanupOverlay();

// Setup dialog (first run)
std::string ShowSetupDialog(HINSTANCE hInst, HWND hwndParent);

// Other dialogs
bool ShowExitPinDialog(HINSTANCE hInst, HWND hwndParent);
void ShowChangePinDialog(HINSTANCE hInst, HWND hwndParent);
void ShowResetPinDialog(HINSTANCE hInst, HWND hwndParent);
void ShowWebhookDialog(HINSTANCE hInst, HWND hwndParent);
void ShowManageDialog(HINSTANCE hInst, HWND hwndParent);
void ShowDashboard(HINSTANCE hInst, HWND hwndParent);
void FocusDashboard();
bool PromptForLaunchPin(HINSTANCE hInst, HWND hwndParent);

// Shared text prompt used by tray/menu actions.
std::wstring ShowTextPromptDialog(HINSTANCE hInst, HWND hwndParent, const wchar_t* title,
                                  const wchar_t* prompt, bool password = false);

// Custom themed alerts (replaces default MessageBox style usage).
void ShowThemedAlert(HINSTANCE hInst, HWND hwndParent, const wchar_t* title, const wchar_t* message, bool isError = false);
bool ShowThemedConfirm(HINSTANCE hInst, HWND hwndParent, const wchar_t* title, const wchar_t* message);
