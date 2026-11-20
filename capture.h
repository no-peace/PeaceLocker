#pragma once
#include <string>

void CaptureIntruderPhotoAsync(const std::wstring& attemptedItem = L"Unknown");
void SendDiscordWebhookTextLogAsync(const std::wstring& itemName);
