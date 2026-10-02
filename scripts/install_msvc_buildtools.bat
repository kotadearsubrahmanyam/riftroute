@echo off
echo ========================================================================
echo RiftRoute: Visual Studio 2022 C++ Build Tools Installer
echo ========================================================================
echo This script installs Microsoft Visual Studio C++ Build Tools (MSVC compiler,
echo link.exe linker, C++ tools, and Windows development libraries).
echo.
echo Please run this script as Administrator (Right click -^> Run as administrator).
echo.

set INSTALLER_PATH=%LOCALAPPDATA%\Temp\WinGet\Microsoft.VisualStudio.2022.BuildTools.17.14.41\vs_BuildTools.exe

if not exist "%INSTALLER_PATH%" (
    echo [ERROR] Installer not found at: %INSTALLER_PATH%
    echo Downloading installer via winget...
    winget download --id Microsoft.VisualStudio.2022.BuildTools -d "%LOCALAPPDATA%\Temp\WinGet\Microsoft.VisualStudio.2022.BuildTools.17.14.41"
)

echo Starting Visual Studio Build Tools installation with C++ Workload...
"%INSTALLER_PATH%" --passive --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended

echo.
echo Installation process initiated. Please allow the installer to complete.
pause
