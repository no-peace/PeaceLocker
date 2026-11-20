#pragma once

#include <string>

// Initializes TPM/DPAPI protection backend.
bool SecurityInit();

// Returns true when TPM-backed key protection is available.
bool SecurityIsTpmAvailable();

// Protects secret data with TPM if available, otherwise DPAPI.
// Returns a serialized blob with a backend prefix (e.g. "TPM:"/"DPAPI:").
std::string SecurityProtectSecret(const std::string& plain);

// Unprotects a serialized secret blob created by SecurityProtectSecret.
bool SecurityUnprotectSecret(const std::string& sealedBlob, std::string& plainOut);
