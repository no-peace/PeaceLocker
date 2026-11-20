#include "security.h"
#include <windows.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <mutex>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace {
constexpr wchar_t kTpmKeyName[] = L"WindowsLocker_TPM_Key";
constexpr size_t kPrefixTpmLen = 4;    // "TPM:"
constexpr size_t kPrefixDpapiLen = 6;  // "DPAPI:"

std::mutex g_securityMtx;
bool g_initialized = false;
bool g_tpmReady = false;
NCRYPT_PROV_HANDLE g_tpmProvider = 0;
NCRYPT_KEY_HANDLE g_tpmKey = 0;

std::string Base64Encode(const BYTE* data, DWORD dataLen) {
    DWORD chars = 0;
    if (!CryptBinaryToStringA(data, dataLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &chars)) {
        return "";
    }
    std::string out(chars, '\0');
    if (!CryptBinaryToStringA(data, dataLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &chars)) {
        return "";
    }
    if (!out.empty() && out.back() == '\0') {
        out.pop_back();
    }
    return out;
}

bool Base64Decode(const std::string& input, std::vector<BYTE>& out) {
    DWORD bytes = 0;
    if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &bytes, nullptr, nullptr)) {
        return false;
    }
    out.resize(bytes);
    return CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &bytes, nullptr, nullptr) == TRUE;
}

void EnsureTpmStateLocked() {
    if (g_initialized) return;
    g_initialized = true;

    SECURITY_STATUS st = NCryptOpenStorageProvider(&g_tpmProvider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (st != ERROR_SUCCESS) {
        g_tpmReady = false;
        return;
    }

    st = NCryptOpenKey(g_tpmProvider, &g_tpmKey, kTpmKeyName, 0, 0);
    if (st == NTE_BAD_KEYSET) {
        st = NCryptCreatePersistedKey(g_tpmProvider, &g_tpmKey, BCRYPT_RSA_ALGORITHM, kTpmKeyName, 0, 0);
        if (st == ERROR_SUCCESS) {
            DWORD keyBits = 2048;
            st = NCryptSetProperty(g_tpmKey, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&keyBits), sizeof(keyBits), 0);
            if (st == ERROR_SUCCESS) {
                st = NCryptFinalizeKey(g_tpmKey, 0);
            }
        }
    }

    g_tpmReady = (st == ERROR_SUCCESS && g_tpmKey != 0);
    if (!g_tpmReady) {
        if (g_tpmKey) {
            NCryptFreeObject(g_tpmKey);
            g_tpmKey = 0;
        }
        if (g_tpmProvider) {
            NCryptFreeObject(g_tpmProvider);
            g_tpmProvider = 0;
        }
    }
}

bool TpmEncryptLocked(const std::string& plain, std::vector<BYTE>& encryptedOut) {
    EnsureTpmStateLocked();
    if (!g_tpmReady) return false;

    BCRYPT_OAEP_PADDING_INFO oaep{};
    oaep.pszAlgId = const_cast<wchar_t*>(BCRYPT_SHA256_ALGORITHM);

    DWORD required = 0;
    SECURITY_STATUS st = NCryptEncrypt(
        g_tpmKey,
        reinterpret_cast<PBYTE>(const_cast<char*>(plain.data())),
        static_cast<DWORD>(plain.size()),
        &oaep,
        nullptr,
        0,
        &required,
        NCRYPT_PAD_OAEP_FLAG);

    if (st != ERROR_SUCCESS || required == 0) return false;
    encryptedOut.resize(required);
    st = NCryptEncrypt(
        g_tpmKey,
        reinterpret_cast<PBYTE>(const_cast<char*>(plain.data())),
        static_cast<DWORD>(plain.size()),
        &oaep,
        encryptedOut.data(),
        required,
        &required,
        NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS) return false;
    encryptedOut.resize(required);
    return true;
}

bool TpmDecryptLocked(const std::vector<BYTE>& encrypted, std::string& plainOut) {
    EnsureTpmStateLocked();
    if (!g_tpmReady) return false;

    BCRYPT_OAEP_PADDING_INFO oaep{};
    oaep.pszAlgId = const_cast<wchar_t*>(BCRYPT_SHA256_ALGORITHM);

    DWORD required = 0;
    SECURITY_STATUS st = NCryptDecrypt(
        g_tpmKey,
        const_cast<PBYTE>(encrypted.data()),
        static_cast<DWORD>(encrypted.size()),
        &oaep,
        nullptr,
        0,
        &required,
        NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS || required == 0) return false;

    std::vector<BYTE> plain(required);
    st = NCryptDecrypt(
        g_tpmKey,
        const_cast<PBYTE>(encrypted.data()),
        static_cast<DWORD>(encrypted.size()),
        &oaep,
        plain.data(),
        required,
        &required,
        NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS) return false;

    plainOut.assign(reinterpret_cast<const char*>(plain.data()), required);
    return true;
}

std::string DpapiProtect(const std::string& plain) {
    DATA_BLOB input{};
    input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()));
    input.cbData = static_cast<DWORD>(plain.size());
    DATA_BLOB output{};

    if (!CryptProtectData(&input, L"WindowsLocker Secret", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        return "";
    }

    std::string encoded = Base64Encode(output.pbData, output.cbData);
    LocalFree(output.pbData);
    if (encoded.empty()) return "";
    return "DPAPI:" + encoded;
}

bool DpapiUnprotect(const std::string& sealed, std::string& plainOut) {
    std::vector<BYTE> data;
    if (!Base64Decode(sealed, data)) return false;

    DATA_BLOB input{};
    input.pbData = data.data();
    input.cbData = static_cast<DWORD>(data.size());
    DATA_BLOB output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        return false;
    }

    plainOut.assign(reinterpret_cast<const char*>(output.pbData), output.cbData);
    LocalFree(output.pbData);
    return true;
}
} // namespace

bool SecurityInit() {
    std::lock_guard<std::mutex> lock(g_securityMtx);
    EnsureTpmStateLocked();
    return true;
}

bool SecurityIsTpmAvailable() {
    std::lock_guard<std::mutex> lock(g_securityMtx);
    EnsureTpmStateLocked();
    return g_tpmReady;
}

std::string SecurityProtectSecret(const std::string& plain) {
    std::lock_guard<std::mutex> lock(g_securityMtx);

    std::vector<BYTE> encrypted;
    if (TpmEncryptLocked(plain, encrypted)) {
        std::string encoded = Base64Encode(encrypted.data(), static_cast<DWORD>(encrypted.size()));
        if (!encoded.empty()) {
            return "TPM:" + encoded;
        }
    }

    return DpapiProtect(plain);
}

bool SecurityUnprotectSecret(const std::string& sealedBlob, std::string& plainOut) {
    std::lock_guard<std::mutex> lock(g_securityMtx);
    plainOut.clear();

    if (sealedBlob.rfind("TPM:", 0) == 0 && sealedBlob.size() > kPrefixTpmLen) {
        std::vector<BYTE> encrypted;
        if (Base64Decode(sealedBlob.substr(kPrefixTpmLen), encrypted) && TpmDecryptLocked(encrypted, plainOut)) {
            return true;
        }
        return false;
    }

    if (sealedBlob.rfind("DPAPI:", 0) == 0 && sealedBlob.size() > kPrefixDpapiLen) {
        return DpapiUnprotect(sealedBlob.substr(kPrefixDpapiLen), plainOut);
    }

    return false;
}
