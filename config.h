#pragma once
#include <string>
#include <vector>

struct BlockEntry {
    std::wstring type;
    std::wstring value;
    std::wstring label; 
};

void InitConfig();

bool IsFirstRun();
void SetPin(const std::string& pin);
bool VerifyPin(const std::string& pin);
bool IsPinLocked();
unsigned long long GetPinLockRemainingSeconds();
int GetRemainingPinAttempts();
void ResetPinLockState();

// Recovery-code helpers (used for PIN reset flows).
std::string EnsureRecoveryCode();
bool ResetPinWithRecoveryCode(const std::string& code, const std::string& newPin);

std::vector<BlockEntry> GetBlocked();
void AddBlocked(const BlockEntry& entry);
void RemoveBlocked(int index);

bool IsAutoStartEnabled();
void SetAutoStart(bool enabled);
bool IsShellIntegrationEnabled();
bool IsLogAllEnabled();
void SetLogAllEnabled(bool enabled);
void SetShellIntegrationEnabled(bool enabled);

std::string GetWebhookUrl();
void SetWebhookUrl(const std::string& url);

void ClearAllData();
