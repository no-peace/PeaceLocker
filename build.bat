@echo off
setlocal EnableDelayedExpansion
echo.
echo  AppLocker V7 Build Script
echo  ==========================
echo.

set MISSING=
for %%f in (main.cpp config.cpp monitor.cpp gui.cpp tray.cpp capture.cpp controller.cpp security.cpp splash.cpp) do (
    if not exist "%%f" set MISSING=!MISSING! %%f
)
if not "!MISSING!"=="" (
    echo  [MISSING] Source files:!MISSING!
    pause & exit /b 1
)
echo  [OK] All source files present

set "VSWHERE="
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if "!VSWHERE!"=="" (
    echo  [ERROR] Visual Studio not found.
    pause & exit /b 1
)

set "VSDIR="
for /f "usebackq delims=" %%i in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do set "VSDIR=%%i"
if "!VSDIR!"=="" for /f "usebackq delims=" %%i in (`"!VSWHERE!" -latest -products * -property installationPath 2^>nul`) do set "VSDIR=%%i"
if "!VSDIR!"=="" (
    for %%v in (2022 2025 2019) do (
        for %%e in (Community Professional Enterprise BuildTools Preview) do (
            if exist "%ProgramFiles%\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvars64.bat" (
                if "!VSDIR!"=="" set "VSDIR=%ProgramFiles%\Microsoft Visual Studio\%%v\%%e"
            )
        )
    )
)
if "!VSDIR!"=="" (
    echo  [ERROR] Could not find Visual Studio.
    pause & exit /b 1
)
echo  [OK] Visual Studio: !VSDIR!

set "VCVARS=!VSDIR!\VC\Auxiliary\Build\vcvars64.bat"
if not exist "!VCVARS!" (
    echo  [ERROR] vcvars64.bat not found.
    pause & exit /b 1
)

call "!VCVARS!" >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Failed to activate MSVC environment.
    pause & exit /b 1
)
echo  [OK] MSVC x64 environment active

where cl.exe >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] cl.exe not found.
    pause & exit /b 1
)
echo  [OK] cl.exe found
echo.

echo  Compiling AppLocker V7...
echo.

cl.exe /nologo /W3 /WX- /O2 /std:c++17 /EHsc ^
    /DUNICODE /D_UNICODE /DWIN32 /D_WIN32_WINNT=0x0A00 ^
    config.cpp monitor.cpp gui.cpp tray.cpp main.cpp capture.cpp controller.cpp security.cpp splash.cpp ^
    /Fe:WindowsLocker_V7.exe ^
    /link ^
    /SUBSYSTEM:WINDOWS ^
    bcrypt.lib shell32.lib comdlg32.lib ole32.lib oleaut32.lib ^
    user32.lib gdi32.lib advapi32.lib shlwapi.lib ^
    comctl32.lib ntdll.lib msimg32.lib ^
    mfplat.lib mfreadwrite.lib mfuuid.lib windowscodecs.lib winhttp.lib wininet.lib gdiplus.lib version.lib Wtsapi32.lib dwmapi.lib uiautomationcore.lib

if %errorlevel% neq 0 (
    echo.
    echo  BUILD FAILED - see errors above.
    pause
    exit /b %errorlevel%
)

del /q *.obj 2>nul

echo.
echo  BUILD SUCCEEDED  -  WindowsLocker_V7.exe
echo.
echo  Right-click WindowsLocker_V7.exe and Run as administrator.
echo.
pause
