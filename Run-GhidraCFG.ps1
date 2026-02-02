# PowerShell script for headless Ghidra CFG generation on Windows
# Usage: .\Run-GhidraCFG.ps1 -BinaryPath "C:\path\to\malware.exe" -OutputPath "C:\output\cfg.json"

param(
    [Parameter(Mandatory=$true)]
    [string]$BinaryPath,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$GhidraPath = "C:\ghidra"
)

# Validate binary exists
if (-not (Test-Path $BinaryPath)) {
    Write-Host "[!] Error: Binary not found: $BinaryPath" -ForegroundColor Red
    exit 1
}

$BinaryName = [System.IO.Path]::GetFileNameWithoutExtension($BinaryPath)
$ProjectName = "${BinaryName}_project"

# Set output path if not provided
if ([string]::IsNullOrEmpty($OutputPath)) {
    $OutputPath = "$env:TEMP\${BinaryName}_cfg.json"
}

# Ensure output directory exists
$OutputDir = [System.IO.Path]::GetDirectoryName($OutputPath)
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Find analyzeHeadless.bat
$AnalyzeHeadless = "$GhidraPath\support\analyzeHeadless.bat"

if (-not (Test-Path $AnalyzeHeadless)) {
    # Try common locations
    $CommonPaths = @(
        "C:\ghidra\support\analyzeHeadless.bat",
        "C:\ghidra_10.4\support\analyzeHeadless.bat",
        "C:\ghidra_11.0\support\analyzeHeadless.bat",
        "$env:ProgramFiles\ghidra\support\analyzeHeadless.bat",
        "D:\ghidra\support\analyzeHeadless.bat"
    )
    
    foreach ($path in $CommonPaths) {
        if (Test-Path $path) {
            $AnalyzeHeadless = $path
            break
        }
    }
    
    if (-not (Test-Path $AnalyzeHeadless)) {
        Write-Host "[!] Error: Could not find analyzeHeadless.bat" -ForegroundColor Red
        Write-Host "[!] Please specify -GhidraPath parameter" -ForegroundColor Red
        exit 1
    }
}

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Create temporary project directory
$TempProjectDir = "$env:TEMP\ghidra_projects"
if (-not (Test-Path $TempProjectDir)) {
    New-Item -ItemType Directory -Path $TempProjectDir -Force | Out-Null
}

Write-Host "[*] Starting Ghidra headless analysis..." -ForegroundColor Cyan
Write-Host "[*] Binary: $BinaryPath" -ForegroundColor Gray
Write-Host "[*] Output: $OutputPath" -ForegroundColor Gray
Write-Host "[*] Ghidra: $AnalyzeHeadless" -ForegroundColor Gray
Write-Host ""

# Measure execution time
$StartTime = Get-Date

# Run Ghidra headless analysis
$Arguments = @(
    "`"$TempProjectDir`"",
    "`"$ProjectName`"",
    "-import", "`"$BinaryPath`"",
    "-scriptPath", "`"$ScriptDir`"",
    "-postScript", "headless_cfg_generator.py", "`"$OutputPath`"",
    "-deleteProject"
)

$ProcessInfo = Start-Process -FilePath $AnalyzeHeadless -ArgumentList $Arguments -NoNewWindow -Wait -PassThru

$EndTime = Get-Date
$Duration = ($EndTime - $StartTime).TotalSeconds

Write-Host ""

# Check if output was created
if (Test-Path $OutputPath) {
    $FileSize = (Get-Item $OutputPath).Length
    $FileSizeKB = [math]::Round($FileSize / 1KB, 2)
    $FileSizeMB = [math]::Round($FileSize / 1MB, 2)
    
    Write-Host "[+] Success! CFG saved to: $OutputPath" -ForegroundColor Green
    
    if ($FileSizeMB -gt 1) {
        Write-Host "[+] File size: $FileSizeMB MB" -ForegroundColor Green
    } else {
        Write-Host "[+] File size: $FileSizeKB KB" -ForegroundColor Green
    }
    
    Write-Host "[+] Total execution time: $([math]::Round($Duration, 2)) seconds" -ForegroundColor Green
    
    exit 0
} else {
    Write-Host "[!] Error: Output file not created" -ForegroundColor Red
    Write-Host "[!] Ghidra exit code: $($ProcessInfo.ExitCode)" -ForegroundColor Red
    exit 1
}
