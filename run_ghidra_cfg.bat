@echo off
REM Batch file wrapper for Ghidra CFG generation
REM Usage: run_ghidra_cfg.bat <binary_path> [output_path]

if "%~1"=="" (
    echo Usage: %~nx0 ^<binary_path^> [output_path]
    echo Example: %~nx0 C:\malware\sample.exe C:\output\cfg.json
    exit /b 1
)

set BINARY_PATH=%~1
set BINARY_NAME=%~n1

REM Set output path
if "%~2"=="" (
    set OUTPUT_PATH=%TEMP%\%BINARY_NAME%_cfg.json
) else (
    set OUTPUT_PATH=%~2
)

REM Check if binary exists
if not exist "%BINARY_PATH%" (
    echo [!] Error: Binary not found: %BINARY_PATH%
    exit /b 1
)

REM Set Ghidra path - ADJUST THIS TO YOUR INSTALLATION
set GHIDRA_PATH=C:\ghidra
set ANALYZE_HEADLESS=%GHIDRA_PATH%\support\analyzeHeadless.bat

REM Try to find Ghidra if not at default location
if not exist "%ANALYZE_HEADLESS%" (
    if exist "C:\ghidra_10.4\support\analyzeHeadless.bat" (
        set ANALYZE_HEADLESS=C:\ghidra_10.4\support\analyzeHeadless.bat
    ) else if exist "C:\ghidra_11.0\support\analyzeHeadless.bat" (
        set ANALYZE_HEADLESS=C:\ghidra_11.0\support\analyzeHeadless.bat
    ) else (
        echo [!] Error: Could not find analyzeHeadless.bat
        echo [!] Please edit this script and set GHIDRA_PATH correctly
        exit /b 1
    )
)

REM Get script directory
set SCRIPT_DIR=%~dp0

REM Create temp project directory
set TEMP_PROJECT_DIR=%TEMP%\ghidra_projects
if not exist "%TEMP_PROJECT_DIR%" mkdir "%TEMP_PROJECT_DIR%"

set PROJECT_NAME=%BINARY_NAME%_project

echo [*] Starting Ghidra headless analysis...
echo [*] Binary: %BINARY_PATH%
echo [*] Output: %OUTPUT_PATH%
echo [*] Ghidra: %ANALYZE_HEADLESS%
echo.

REM Run Ghidra headless
call "%ANALYZE_HEADLESS%" ^
    "%TEMP_PROJECT_DIR%" ^
    "%PROJECT_NAME%" ^
    -import "%BINARY_PATH%" ^
    -scriptPath "%SCRIPT_DIR%" ^
    -postScript headless_cfg_generator.py "%OUTPUT_PATH%" ^
    -deleteProject

echo.

REM Check if output was created
if exist "%OUTPUT_PATH%" (
    echo [+] Success! CFG saved to: %OUTPUT_PATH%
    for %%A in ("%OUTPUT_PATH%") do echo [+] File size: %%~zA bytes
    exit /b 0
) else (
    echo [!] Error: Output file not created
    exit /b 1
)
