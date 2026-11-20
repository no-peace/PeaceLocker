#include "config.h"
#include "common.h"
#include "path_utils.h"
#include "security.h"
#include <windows.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <fstream>
#include <vector>
#include <mutex>
#include <algorithm>
#include <cstdlib>
#include <chrono>
#include <cctype>
#include <sstream>
#include <cstdint>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

namespace {
constexpr int kPinLockThreshold = 3;
constexpr unsigned long long kPinLockDurationSeconds = 6ULL * 60ULL * 60ULL;
constexpr int kRecoveryIterations = 120000;
constexpr wchar_t kRunValueName[] = L"PeaceVault";
constexpr wchar_t kRunLegacyValueName[] = L"AppLocker";
constexpr wchar_t kShellRoot[] = L"Software\\Classes";
constexpr wchar_t kShellVerbName[] = L"PeaceVault.Protect";
constexpr wchar_t kShellVerbTitle[] = L"Protect with Peace's Vault";
constexpr char kConfigMagic[] = "PVBIN01";
constexpr uint32_t kConfigMaxBlobBytes = 1024 * 1024;
}

static std::string g_pinHash;
static std::string g_pinSaltHex;
static int g_pinIterations = 150000;
static int g_pinVersion = 1;
static std::string g_pinPepperBlob;
static std::string g_pinPepperPlain;
static int g_failedPinAttempts = 0;
static unsigned long long g_pinLockUntilEpoch = 0;
static std::string g_recoverySaltHex;
static std::string g_recoveryHash;

static bool g_autoStart = true;
static bool g_shellIntegration = true;
static bool g_logAll = false;
static std::vector<BlockEntry> g_blocked;
static std::string g_webhookUrl;
static std::wstring g_cfgPath;
static std::wstring g_legacyCfgPath;
static std::mutex g_mtx;

static std::string HexEncode(const BYTE* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = digits[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = digits[data[i] & 0xF];
    }
    return out;
}

static bool HexDecode(const std::string& hex, std::vector<BYTE>& out) {
    if (hex.size() % 2 != 0) return false;
    auto hexVal = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hexVal(hex[i]);
        int lo = hexVal(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<BYTE>((hi << 4) | lo));
    }
    return true;
}

static std::vector<BYTE> RandomBytes(size_t count) {
    std::vector<BYTE> data(count);
    if (count == 0) return data;
    if (BCryptGenRandom(nullptr, data.data(), static_cast<ULONG>(count), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        data.assign(count, 0);
    }
    return data;
}

inline std::string Sha256Hex(const std::string& input) {
    UniqueBCryptAlg alg;
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return "";
    alg.reset(hAlg);

    UniqueBCryptHash hash;
    BCRYPT_HASH_HANDLE hHash;
    if (BCryptCreateHash(alg.get(), &hHash, nullptr, 0, nullptr, 0, 0) < 0) return "";
    hash.reset(hHash);

    BYTE digest[32]{};
    BCryptHashData(hash.get(), reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())), static_cast<ULONG>(input.size()), 0);
    BCryptFinishHash(hash.get(), digest, sizeof(digest), 0);
    return HexEncode(digest, sizeof(digest));
}

static std::string CalculateHMAC(const std::string& data) {
    UniqueBCryptAlg alg;
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) return "";
    alg.reset(hAlg);

    const char hmacKey[] = "PeaceVaultInternalKey";
    UniqueBCryptHash hash;
    BCRYPT_HASH_HANDLE hHash;
    if (BCryptCreateHash(alg.get(), &hHash, nullptr, 0, (PUCHAR)hmacKey, (ULONG)strlen(hmacKey), 0) < 0) return "";
    hash.reset(hHash);

    BCryptHashData(hash.get(), (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BYTE digest[32];
    BCryptFinishHash(hash.get(), digest, sizeof(digest), 0);
    return HexEncode(digest, sizeof(digest));
}

static bool TimingSafeEqual(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

static bool LoadPepperFromBlob() {
    g_pinPepperPlain.clear();
    if (g_pinPepperBlob.empty()) return false;

    if (g_pinPepperBlob.rfind("PLAIN:", 0) == 0) {
        std::vector<BYTE> raw;
        if (!HexDecode(g_pinPepperBlob.substr(6), raw) || raw.empty()) return false;
        g_pinPepperPlain.assign(reinterpret_cast<const char*>(raw.data()), raw.size());
        return true;
    }

    return SecurityUnprotectSecret(g_pinPepperBlob, g_pinPepperPlain) && !g_pinPepperPlain.empty();
}

static bool EnsurePepperReady() {
    if (!g_pinPepperPlain.empty()) return false;
    if (LoadPepperFromBlob()) return false;

    std::vector<BYTE> pepper = RandomBytes(32);
    if (pepper.empty()) return false;
    g_pinPepperPlain.assign(reinterpret_cast<const char*>(pepper.data()), pepper.size());

    g_pinPepperBlob = SecurityProtectSecret(g_pinPepperPlain);
    if (g_pinPepperBlob.empty()) {
        g_pinPepperBlob = "PLAIN:" + HexEncode(pepper.data(), pepper.size());
    }
    return true;
}

static std::string DerivePinHashV2(const std::string& pin, const std::string& saltHex, int iterations, const std::string& pepperPlain) {
    if (saltHex.empty() || pepperPlain.empty() || iterations <= 0) return "";

    std::vector<BYTE> salt;
    if (!HexDecode(saltHex, salt) || salt.empty()) return "";

    std::string pinMaterial = pin;
    pinMaterial.append(":");
    pinMaterial.append(pepperPlain);

    UniqueBCryptAlg alg;
    BCRYPT_ALG_HANDLE hAlg;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) {
        return "";
    }
    alg.reset(hAlg);

    BYTE out[32]{};
    NTSTATUS st = BCryptDeriveKeyPBKDF2(
        alg.get(),
        reinterpret_cast<PUCHAR>(const_cast<char*>(pinMaterial.data())),
        static_cast<ULONG>(pinMaterial.size()),
        salt.data(),
        static_cast<ULONG>(salt.size()),
        static_cast<ULONGLONG>(iterations),
        out,
        sizeof(out),
        0);
    if (st < 0) return "";

    return HexEncode(out, sizeof(out));
}

static unsigned long long NowEpochSeconds() {
    using namespace std::chrono;
    return static_cast<unsigned long long>(duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

static bool IsPinLockedNoSync() {
    if (g_pinLockUntilEpoch == 0) return false;
    unsigned long long now = NowEpochSeconds();
    return now < g_pinLockUntilEpoch;
}

static void ClearPinLockNoSync() {
    g_failedPinAttempts = 0;
    g_pinLockUntilEpoch = 0;
}

static std::string NormalizeRecoveryCode(std::string code) {
    std::string out;
    out.reserve(code.size());
    for (char c : code) {
        if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        out.push_back(static_cast<char>(toupper(static_cast<unsigned char>(c))));
    }
    return out;
}

static std::string DeriveRecoveryHash(const std::string& codeNormalized, const std::string& saltHex, int iterations, const std::string& pepperPlain) {
    return DerivePinHashV2(codeNormalized, saltHex, iterations, pepperPlain);
}

static std::string MakeRecoveryCode() {
    std::vector<BYTE> raw = RandomBytes(10);
    if (raw.empty()) return "";
    std::string hex = HexEncode(raw.data(), raw.size());
    for (char& c : hex) c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    if (hex.size() < 20) return hex;
    return hex.substr(0, 5) + "-" + hex.substr(5, 5) + "-" + hex.substr(10, 5) + "-" + hex.substr(15, 5);
}

static bool VerifyPinHashNoSync(const std::string& pin) {
    if (g_pinHash.empty()) return false;

    if (g_pinVersion >= 2 && !g_pinSaltHex.empty()) {
        EnsurePepperReady();
        std::string candidate = DerivePinHashV2(pin, g_pinSaltHex, g_pinIterations, g_pinPepperPlain);
        return TimingSafeEqual(candidate, g_pinHash);
    }

    const bool legacyMatch = TimingSafeEqual(Sha256Hex(pin), g_pinHash);
    if (legacyMatch) {
        EnsurePepperReady();
        std::vector<BYTE> salt = RandomBytes(16);
        g_pinSaltHex = HexEncode(salt.data(), salt.size());
        g_pinIterations = 150000;
        g_pinVersion = 2;
        g_pinHash = DerivePinHashV2(pin, g_pinSaltHex, g_pinIterations, g_pinPepperPlain);
    }
    return legacyMatch;
}

// Helper function to verify auto-start registry entry is correctly set
static bool VerifyAutoStartRegistry() {
    HKEY hk{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        return false;
    }
    wchar_t exe[MAX_PATH]{};
    DWORD len = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        RegCloseKey(hk);
        return false;
    }
    std::wstring expectedCmd = L"\"" + std::wstring(exe) + L"\"";

    wchar_t valueData[MAX_PATH + 10]{};
    DWORD valueLen = sizeof(valueData);
    DWORD type = 0;

    LONG result = RegQueryValueExW(hk, kRunValueName, nullptr, &type, 
        reinterpret_cast<LPBYTE>(valueData), &valueLen);
    RegCloseKey(hk);

    if (result != ERROR_SUCCESS || type != REG_SZ) {
        return false;
    }

    return expectedCmd == valueData;
}

static void ApplyAutoStartNoSync(bool enabled) {
    HKEY hk{};
    // Use KEY_WRITE instead of KEY_ALL_ACCESS for better compatibility
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hk);
    if (result != ERROR_SUCCESS) {
        // Try with read/write access if write-only fails
        result = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ | KEY_WRITE, &hk);
    }
    if (result == ERROR_SUCCESS) {
        if (enabled) {
            wchar_t exe[MAX_PATH]{};
            DWORD len = GetModuleFileNameW(nullptr, exe, MAX_PATH);
            if (len > 0 && len < MAX_PATH) {
                // Properly quote the path and ensure it's valid
                std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --silent";
                // Also add a working directory parameter to ensure the app starts correctly
                result = RegSetValueExW(hk, kRunValueName, 0, REG_SZ, 
                    reinterpret_cast<const BYTE*>(cmd.c_str()), 
                    static_cast<DWORD>((cmd.length() + 1) * sizeof(wchar_t)));
                if (result == ERROR_SUCCESS) {
                    RegDeleteValueW(hk, kRunLegacyValueName);
                }
            }
        } else {
            RegDeleteValueW(hk, kRunValueName);
            RegDeleteValueW(hk, kRunLegacyValueName);
        }
        RegCloseKey(hk);
    }
}

static void SetRegString(HKEY root, const std::wstring& subkey, const wchar_t* valueName, const std::wstring& value) {
    HKEY hk{};
    if (RegCreateKeyExW(root, subkey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hk, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(hk, valueName, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(value.c_str()),
            static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hk);
    }
}

static void DeleteRegTreeIfExists(HKEY root, const std::wstring& subkey) {
    RegDeleteTreeW(root, subkey.c_str());
}

static void ApplyShellIntegrationNoSync(bool enabled) {
    const std::wstring shellRoot = kShellRoot;
    const std::wstring fileVerb = shellRoot + L"\\*\\shell\\" + kShellVerbName;
    const std::wstring dirVerb = shellRoot + L"\\Directory\\shell\\" + kShellVerbName;
    const std::wstring dirBgVerb = shellRoot + L"\\Directory\\Background\\shell\\" + kShellVerbName;
    const std::wstring driveVerb = shellRoot + L"\\Drive\\shell\\" + kShellVerbName;

    if (!enabled) {
        DeleteRegTreeIfExists(HKEY_CURRENT_USER, fileVerb);
        DeleteRegTreeIfExists(HKEY_CURRENT_USER, dirVerb);
        DeleteRegTreeIfExists(HKEY_CURRENT_USER, dirBgVerb);
        DeleteRegTreeIfExists(HKEY_CURRENT_USER, driveVerb);
        return;
    }

    wchar_t exe[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring command = L"\"" + std::wstring(exe) + L"\" --protect \"%1\"";
    std::wstring commandBg = L"\"" + std::wstring(exe) + L"\" --protect \"%V\"";
    std::wstring icon = std::wstring(exe) + L",0";

    SetRegString(HKEY_CURRENT_USER, fileVerb, nullptr, kShellVerbTitle);
    SetRegString(HKEY_CURRENT_USER, fileVerb, L"Icon", icon);
    SetRegString(HKEY_CURRENT_USER, fileVerb + L"\\command", nullptr, command);

    SetRegString(HKEY_CURRENT_USER, dirVerb, nullptr, kShellVerbTitle);
    SetRegString(HKEY_CURRENT_USER, dirVerb, L"Icon", icon);
    SetRegString(HKEY_CURRENT_USER, dirVerb + L"\\command", nullptr, command);

    SetRegString(HKEY_CURRENT_USER, dirBgVerb, nullptr, kShellVerbTitle);
    SetRegString(HKEY_CURRENT_USER, dirBgVerb, L"Icon", icon);
    SetRegString(HKEY_CURRENT_USER, dirBgVerb + L"\\command", nullptr, commandBg);

    SetRegString(HKEY_CURRENT_USER, driveVerb, nullptr, kShellVerbTitle);
    SetRegString(HKEY_CURRENT_USER, driveVerb, L"Icon", icon);
    SetRegString(HKEY_CURRENT_USER, driveVerb + L"\\command", nullptr, command);
}

static void ResetConfigState() {
    g_pinHash.clear();
    g_pinSaltHex.clear();
    g_pinIterations = 150000;
    g_pinVersion = 1;
    g_pinPepperBlob.clear();
    g_pinPepperPlain.clear();
    g_failedPinAttempts = 0;
    g_pinLockUntilEpoch = 0;
    g_recoverySaltHex.clear();
    g_recoveryHash.clear();
    g_blocked.clear();
    g_autoStart = true;
    g_shellIntegration = true;
    g_logAll = false;
    g_webhookUrl.clear();
}

static void ParseConfigStream(std::istream& in) {
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        if (key == "pin") g_pinHash = value;
        else if (key == "pinsalt") g_pinSaltHex = value;
        else if (key == "piniter") g_pinIterations = value.empty() ? 150000 : (std::max)(10000, atoi(value.c_str()));
        else if (key == "pinv") g_pinVersion = value.empty() ? 1 : (std::max)(1, atoi(value.c_str()));
        else if (key == "pepper") g_pinPepperBlob = value;
        else if (key == "pinfail") g_failedPinAttempts = value.empty() ? 0 : (std::max)(0, atoi(value.c_str()));
        else if (key == "pinlock") g_pinLockUntilEpoch = value.empty() ? 0 : _strtoui64(value.c_str(), nullptr, 10);
        else if (key == "recsalt") g_recoverySaltHex = value;
        else if (key == "rechash") g_recoveryHash = value;
        else if (key == "auto") g_autoStart = (value == "1");
        else if (key == "shell") g_shellIntegration = (value != "0");
        else if (key == "logall") g_logAll = (value == "1");
        else if (key == "webhook") g_webhookUrl = value;
        else if (key == "b") {
            auto p1 = value.find('|');
            auto p2 = value.rfind('|');
            if (p1 != p2 && p1 != std::string::npos) {
                BlockEntry e;
                e.type = U2W(value.substr(0, p1));
                e.value = U2W(value.substr(p1 + 1, p2 - p1 - 1));
                e.label = U2W(value.substr(p2 + 1));
                g_blocked.push_back(e);
            }
        }
    }
}

static std::string BuildConfigPlainText() {
    std::ostringstream out;
    out << "pin=" << g_pinHash << "\n";
    out << "pinsalt=" << g_pinSaltHex << "\n";
    out << "piniter=" << g_pinIterations << "\n";
    out << "pinv=" << g_pinVersion << "\n";
    out << "pepper=" << g_pinPepperBlob << "\n";
    out << "pinfail=" << g_failedPinAttempts << "\n";
    out << "pinlock=" << g_pinLockUntilEpoch << "\n";
    out << "recsalt=" << g_recoverySaltHex << "\n";
    out << "rechash=" << g_recoveryHash << "\n";
    out << "auto=" << (g_autoStart ? "1" : "0") << "\n";
    out << "shell=" << (g_shellIntegration ? "1" : "0") << "\n";
    out << "logall=" << (g_logAll ? "1" : "0") << "\n";
    out << "webhook=" << g_webhookUrl << "\n";
    for (const auto& b : g_blocked) {
        out << "b=" << W2U(b.type) << "|" << W2U(b.value) << "|" << W2U(b.label) << "\n";
    }
    std::string content = out.str();
    return content + "hmac=" + CalculateHMAC(content) + "\n";
}

static bool LoadBinaryConfig() {
    std::ifstream f(W2U(g_cfgPath), std::ios::binary);
    if (!f) return false;

    char magic[7]{};
    f.read(magic, sizeof(magic));
    if (!f || std::string(magic, sizeof(magic)) != std::string(kConfigMagic)) return false;

    uint32_t blobSize = 0;
    f.read(reinterpret_cast<char*>(&blobSize), sizeof(blobSize));
    if (!f || blobSize == 0 || blobSize > kConfigMaxBlobBytes) return false;

    std::string sealed(blobSize, '\0');
    f.read(&sealed[0], blobSize);
    if (!f) return false;

    std::string plain;
    if (sealed.rfind("RAW:", 0) == 0) {
        Log(L"Warning: loading unencrypted config fallback");
        plain = sealed.substr(4);
    } else if (!SecurityUnprotectSecret(sealed, plain)) {
        Log(L"Error: failed to decrypt config");
        return false;
    }

    size_t hmacPos = plain.rfind("hmac=");
    if (hmacPos != std::string::npos) {
        std::string content = plain.substr(0, hmacPos);
        std::string expected = plain.substr(hmacPos + 5);
        while (!expected.empty() && (expected.back() == '\n' || expected.back() == '\r')) expected.pop_back();
        if (!TimingSafeEqual(CalculateHMAC(content), expected)) {
            Log(L"Error: config HMAC mismatch (tampered)");
            return false;
        }
    }

    std::istringstream in(plain);
    ParseConfigStream(in);
    return true;
}

static bool LoadLegacyTextConfig() {
    std::ifstream f(W2U(g_legacyCfgPath));
    if (!f) return false;
    ParseConfigStream(f);
    return true;
}

static void Save() {
    std::string plain = BuildConfigPlainText();
    std::string sealed = SecurityProtectSecret(plain);
    if (sealed.empty()) {
        Log(L"Error: encryption failed, refusing to save plain-text config");
        return;
    }

    std::ofstream f(W2U(g_cfgPath), std::ios::binary | std::ios::trunc);
    if (!f) return;

    const uint32_t blobSize = static_cast<uint32_t>(sealed.size());
    f.write(kConfigMagic, 7);
    f.write(reinterpret_cast<const char*>(&blobSize), sizeof(blobSize));
    f.write(sealed.data(), sealed.size());
}

static void Load() {
    ResetConfigState();
    if (LoadBinaryConfig()) return;

    if (LoadLegacyTextConfig()) {
        Save();
        DeleteFileW(g_legacyCfgPath.c_str());
    }
}

void InitConfig() {
    std::wstring dir = GetAppLockerRootDir();
    EnsureDir(dir);
    g_cfgPath = dir + L"\\vault_data.bin";
    g_legacyCfgPath = dir + L"\\config.txt";
    SecurityInit();
    Load();
    bool dirty = EnsurePepperReady();
    if (g_autoStart) {
        ApplyAutoStartNoSync(true);
        // Verify the registry entry was set correctly
        if (!VerifyAutoStartRegistry()) {
            // Retry with elevated permissions might be needed
            ApplyAutoStartNoSync(true);
        }
    } else {
        ApplyAutoStartNoSync(false);
    }
    if (g_shellIntegration) {
        ApplyShellIntegrationNoSync(true);
    }
    if (dirty) Save();
}

bool IsFirstRun() {
    std::lock_guard<std::mutex> lock(g_mtx);
    return g_pinHash.empty();
}

void SetPin(const std::string& pin) {
    std::lock_guard<std::mutex> lock(g_mtx);

    EnsurePepperReady();
    std::vector<BYTE> salt = RandomBytes(16);
    g_pinSaltHex = HexEncode(salt.data(), salt.size());
    g_pinIterations = 150000;
    g_pinVersion = 2;
    g_pinHash = DerivePinHashV2(pin, g_pinSaltHex, g_pinIterations, g_pinPepperPlain);
    ClearPinLockNoSync();
    Save();
}

bool VerifyPin(const std::string& pin) {
    std::lock_guard<std::mutex> lock(g_mtx);
    if (g_pinHash.empty()) return false;
    if (IsPinLockedNoSync()) return false;

    if (VerifyPinHashNoSync(pin)) {
        ClearPinLockNoSync();
        Save();
        return true;
    }

    g_failedPinAttempts++;
    if (g_failedPinAttempts >= kPinLockThreshold) {
        g_pinLockUntilEpoch = NowEpochSeconds() + kPinLockDurationSeconds;
        g_failedPinAttempts = 0;
    }
    Save();
    return false;
}

bool IsPinLocked() {
    std::lock_guard<std::mutex> lock(g_mtx);
    if (!IsPinLockedNoSync() && g_pinLockUntilEpoch != 0) {
        g_pinLockUntilEpoch = 0;
        Save();
        return false;
    }
    return IsPinLockedNoSync();
}

unsigned long long GetPinLockRemainingSeconds() {
    std::lock_guard<std::mutex> lock(g_mtx);
    if (!IsPinLockedNoSync()) return 0;
    unsigned long long now = NowEpochSeconds();
    return g_pinLockUntilEpoch > now ? (g_pinLockUntilEpoch - now) : 0;
}

int GetRemainingPinAttempts() {
    std::lock_guard<std::mutex> lock(g_mtx);
    if (IsPinLockedNoSync()) return 0;
    int remaining = kPinLockThreshold - g_failedPinAttempts;
    return (std::max)(0, remaining);
}

void ResetPinLockState() {
    std::lock_guard<std::mutex> lock(g_mtx);
    ClearPinLockNoSync();
    Save();
}

std::string EnsureRecoveryCode() {
    std::lock_guard<std::mutex> lock(g_mtx);
    EnsurePepperReady();
    if (!g_recoveryHash.empty() && !g_recoverySaltHex.empty()) {
        return "";
    }

    std::string code = MakeRecoveryCode();
    if (code.empty()) return "";

    std::vector<BYTE> salt = RandomBytes(16);
    g_recoverySaltHex = HexEncode(salt.data(), salt.size());
    g_recoveryHash = DeriveRecoveryHash(NormalizeRecoveryCode(code), g_recoverySaltHex, kRecoveryIterations, g_pinPepperPlain);
    Save();
    return code;
}

bool ResetPinWithRecoveryCode(const std::string& code, const std::string& newPin) {
    std::lock_guard<std::mutex> lock(g_mtx);
    if (newPin.size() < 4) return false;

    EnsurePepperReady();
    if (g_recoveryHash.empty() || g_recoverySaltHex.empty()) return false;

    std::string candidate = DeriveRecoveryHash(NormalizeRecoveryCode(code), g_recoverySaltHex, kRecoveryIterations, g_pinPepperPlain);
    if (!TimingSafeEqual(candidate, g_recoveryHash)) return false;

    std::vector<BYTE> salt = RandomBytes(16);
    g_pinSaltHex = HexEncode(salt.data(), salt.size());
    g_pinIterations = 150000;
    g_pinVersion = 2;
    g_pinHash = DerivePinHashV2(newPin, g_pinSaltHex, g_pinIterations, g_pinPepperPlain);
    ClearPinLockNoSync();
    Save();
    return true;
}

std::vector<BlockEntry> GetBlocked() {
    std::lock_guard<std::mutex> lock(g_mtx);
    return g_blocked;
}

void AddBlocked(const BlockEntry& entry) {
    std::lock_guard<std::mutex> lock(g_mtx);
    g_blocked.push_back(entry);
    Save();
}

void RemoveBlocked(int index) {
    std::lock_guard<std::mutex> lock(g_mtx);
    if (index >= 0 && index < static_cast<int>(g_blocked.size())) {
        g_blocked.erase(g_blocked.begin() + index);
        Save();
    }
}

bool IsAutoStartEnabled() {
    std::lock_guard<std::mutex> lock(g_mtx);
    return g_autoStart;
}

void SetAutoStart(bool enabled) {
    std::lock_guard<std::mutex> lock(g_mtx);
    g_autoStart = enabled;
    ApplyAutoStartNoSync(enabled);
    // Verify and retry if needed
    if (enabled && !VerifyAutoStartRegistry()) {
        ApplyAutoStartNoSync(true);
    }
    Save();
}

bool IsShellIntegrationEnabled() {
    std::lock_guard<std::mutex> lock(g_mtx);
    return g_shellIntegration;
}

void SetShellIntegrationEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(g_mtx);
    g_shellIntegration = enabled;
    ApplyShellIntegrationNoSync(enabled);
    Save();
}


bool IsLogAllEnabled() {
    std::lock_guard<std::mutex> lock(g_mtx);
    return g_logAll;
}

void SetLogAllEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(g_mtx);
    g_logAll = enabled;
    Save();
}

std::string GetWebhookUrl() {
    std::lock_guard<std::mutex> lock(g_mtx);
    return g_webhookUrl;
}

void SetWebhookUrl(const std::string& url) {
    std::lock_guard<std::mutex> lock(g_mtx);
    g_webhookUrl = url;
    Save();
}

void ClearAllData() {
    std::lock_guard<std::mutex> lock(g_mtx);

    g_pinHash.clear();
    g_pinSaltHex.clear();
    g_pinIterations = 150000;
    g_pinVersion = 1;
    g_pinPepperBlob.clear();
    g_pinPepperPlain.clear();
    g_failedPinAttempts = 0;
    g_pinLockUntilEpoch = 0;
    g_recoverySaltHex.clear();
    g_recoveryHash.clear();
    g_blocked.clear();
    g_autoStart = false;
    g_shellIntegration = true;
    g_logAll = false;
    g_webhookUrl.clear();

    ApplyAutoStartNoSync(false);
    ApplyShellIntegrationNoSync(false);

    std::wstring dir = GetAppLockerRootDir();
    wchar_t dirDb[MAX_PATH + 2] = {};
    wcsncpy_s(dirDb, _countof(dirDb), dir.c_str(), _TRUNCATE);
    size_t len = wcsnlen_s(dirDb, MAX_PATH + 1);
    if (len + 1 < MAX_PATH + 2) dirDb[len + 1] = L'\0';

    SHFILEOPSTRUCTW op{};
    op.wFunc = FO_DELETE;
    op.pFrom = dirDb;
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    SHFileOperationW(&op);
}
