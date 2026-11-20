# Peace's Vault

## Build (MSVC, no `build.bat`)

Use the Visual Studio solution directly:

1. Open `WindowsLocker.sln` in Visual Studio 2022.
2. Select `Release | x64`.
3. Build the `WindowsLocker` project.

Or build from terminal with PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Configuration Release
```

Output binary:

- `build\Release\WindowsLocker.exe`

Notes:

- Standalone mode is enabled: only `WindowsLocker.exe` is required.
- Config storage is persisted as encrypted binary (`%APPDATA%\PeaceVault\vault_data.bin`).
