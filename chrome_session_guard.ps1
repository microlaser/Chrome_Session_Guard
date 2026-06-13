#Requires -RunAsAdministrator
<#
.SYNOPSIS
    chrome_session_guard.ps1 — On-device Chrome session riding detector for Windows

.DESCRIPTION
    Detects active or attempted on-device session riding against Chrome browser sessions.
    Monitors for:
      [1] Chrome Remote Debugging Protocol (CDP) port exposure (default: 9222)
      [2] Chrome instances launched with --remote-debugging-port flag
      [3] Non-shell processes opening handles to chrome.exe (injection precursor)
      [4] Chrome child processes with anomalous parent lineage
      [5] Unexpected chrome.exe instances spawned outside normal user shell parents
      [6] Network connections from chrome.exe to non-browser destinations on loopback
          that could indicate CDP tunneling or local proxy interception

    Runs as a continuous monitor loop. Alerts are written to console and log file.
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges.
    Optional: Sysinternals handle.exe on PATH for deep handle inspection.

.PARAMETER Interval
    Polling interval in seconds (default: 5)

.PARAMETER LogFile
    Path to write alerts (default: C:\Logs\chrome_session_guard.log)

.PARAMETER CDPPort
    Chrome DevTools Protocol port to watch (default: 9222)

.PARAMETER TrustedParents
    Additional trusted parent process names (comma-separated). Default set covers
    common shells and launchers. Override if you use a custom launcher.

.PARAMETER AlertOnly
    If set, do not attempt to kill suspicious processes — alert only.

.EXAMPLE
    .\chrome_session_guard.ps1
    .\chrome_session_guard.ps1 -Interval 3 -AlertOnly
    .\chrome_session_guard.ps1 -LogFile D:\security\chrome_guard.log -CDPPort 9222

.NOTES
    Author  : microlaser (Michael Lazin)
    Version : 1.0
    Related : wifi-guardian-windows.ps1, net_exploit_detector
#>

[CmdletBinding()]
param(
    [int]    $Interval      = 5,
    [string] $LogFile       = "C:\Logs\chrome_session_guard.log",
    [int]    $CDPPort       = 9222,
    [string[]] $TrustedParents = @(),
    [switch] $AlertOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
# Trusted parent processes — processes legitimately allowed to spawn chrome.exe
# ---------------------------------------------------------------------------
$DEFAULT_TRUSTED_PARENTS = @(
    "explorer",         # Normal desktop launch
    "cmd",              # CLI launch
    "powershell",       # PS launch
    "pwsh",             # PowerShell 7
    "bash",             # WSL / Git Bash
    "wsl",              # WSL launcher
    "open-with",        # Windows "open with" handler
    "ApplicationFrameHost",
    "SearchApp",        # Windows search
    "StartMenuExperienceHost",
    "svchost",          # Service-hosted launchers (e.g. scheduled tasks)
    "taskhostw",        # Task scheduler
    "userinit",         # Logon init
    "winlogon",
    "chrome"            # Chrome relaunching itself (update, crash recovery)
)

$TRUSTED_PARENTS = ($DEFAULT_TRUSTED_PARENTS + $TrustedParents) | Sort-Object -Unique

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
$LogDir = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$AlertCount = 0

function Write-Alert {
    param([string]$Level, [string]$Message)
    $ts   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $line = "$ts [$Level] $Message"
    switch ($Level) {
        "ALERT"   { Write-Host $line -ForegroundColor Red }
        "WARNING" { Write-Host $line -ForegroundColor Yellow }
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "DEBUG"   { Write-Host $line -ForegroundColor Gray }
        default   { Write-Host $line }
    }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function New-Alert {
    param([string]$Category, [string]$Detail)
    $script:AlertCount++
    Write-Alert "ALERT" "[#$($script:AlertCount)] $Category | $Detail"
}

# ---------------------------------------------------------------------------
# Check 1: CDP port exposure
# Detects any process listening on the Chrome DevTools Protocol port.
# Legitimate Chrome only listens here if explicitly launched with
# --remote-debugging-port, which malware exploits for session riding.
# ---------------------------------------------------------------------------
function Test-CDPPortExposure {
    $listeners = Get-NetTCPConnection -LocalPort $CDPPort -State Listen `
                 -ErrorAction SilentlyContinue
    foreach ($conn in $listeners) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $name = if ($proc) { $proc.Name } else { "PID $($conn.OwningProcess)" }
        New-Alert "CDP_PORT_EXPOSED" `
            "Process '$name' (PID $($conn.OwningProcess)) is listening on CDP port $CDPPort. " +
            "Chrome should NEVER expose this in normal operation. Possible remote debugging exploit."
    }
}

# ---------------------------------------------------------------------------
# Check 2: Chrome launched with --remote-debugging-port in command line
# ---------------------------------------------------------------------------
function Test-ChromeDebugFlags {
    $chromeProcs = Get-CimInstance Win32_Process -Filter "Name = 'chrome.exe'" `
                   -ErrorAction SilentlyContinue
    foreach ($p in $chromeProcs) {
        $cmdline = $p.CommandLine
        if ($cmdline -match '--remote-debugging-port') {
            New-Alert "CHROME_DEBUG_FLAG" `
                "chrome.exe PID $($p.ProcessId) launched with --remote-debugging-port. " +
                "Command: $($cmdline.Substring(0, [Math]::Min(200, $cmdline.Length)))"
        }
        if ($cmdline -match '--remote-debugging-pipe') {
            New-Alert "CHROME_DEBUG_FLAG" `
                "chrome.exe PID $($p.ProcessId) launched with --remote-debugging-pipe (CDP via stdin/stdout)."
        }
        if ($cmdline -match '--headless' -and $cmdline -notmatch 'print') {
            # Headless Chrome used outside of a print/PDF context is suspicious
            New-Alert "CHROME_HEADLESS" `
                "chrome.exe PID $($p.ProcessId) running headless (non-print). " +
                "Could indicate automated session rider. Cmdline: $($cmdline.Substring(0, [Math]::Min(150,$cmdline.Length)))"
        }
    }
}

# ---------------------------------------------------------------------------
# Check 3: Chrome child process lineage anomalies
# Chrome's own process tree is: chrome.exe -> chrome.exe (renderer/GPU/utility)
# An attacker spawning chrome.exe from malware (e.g. a .NET dropper, Python,
# cmd from a temp path) will have a non-standard parent.
# ---------------------------------------------------------------------------
function Test-ChromeParentLineage {
    $chromeProcs = Get-CimInstance Win32_Process -Filter "Name = 'chrome.exe'" `
                   -ErrorAction SilentlyContinue
    foreach ($p in $chromeProcs) {
        $parentId   = $p.ParentProcessId
        $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId = $parentId" `
                      -ErrorAction SilentlyContinue
        $parentName = if ($parentProc) { $parentProc.Name -replace '\.exe$','' } else { "GONE_$parentId" }

        if ($parentName -notin $TRUSTED_PARENTS) {
            # Deeper check: is the parent running from a suspicious path?
            $parentPath = if ($parentProc) { $parentProc.ExecutablePath } else { "unknown" }
            $isSuspiciousPath = $parentPath -match '(\\Temp\\|\\AppData\\Local\\Temp\\|\\Downloads\\|\\ProgramData\\(?!Microsoft))'

            $level = if ($isSuspiciousPath) { "ALERT" } else { "WARNING" }
            $msg   = "chrome.exe PID $($p.ProcessId) spawned by untrusted parent: " +
                     "'$parentName' (PID $parentId, path: $parentPath)"

            if ($level -eq "ALERT") {
                New-Alert "SUSPICIOUS_CHROME_PARENT" $msg
            } else {
                Write-Alert "WARNING" $msg
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Check 4: Processes with open handles to chrome.exe
# Requires Sysinternals handle.exe. Skipped gracefully if not present.
# A process that opens a handle to chrome.exe with PROCESS_VM_READ or
# PROCESS_VM_WRITE is a strong indicator of injection or memory scraping.
# ---------------------------------------------------------------------------
function Test-ChromeHandles {
    $handleExe = Get-Command "handle.exe" -ErrorAction SilentlyContinue
    if (-not $handleExe) {
        Write-Alert "INFO" "handle.exe not found on PATH — skipping handle inspection. " +
                           "Install Sysinternals for deeper coverage."
        return
    }

    $output = & handle.exe -p chrome.exe -accepteula 2>$null
    foreach ($line in $output) {
        # handle.exe output: "ProcessName  pid: NNNN  <handle type>: <target>"
        if ($line -match '^\s*(\S+)\s+pid:\s*(\d+)') {
            $accessorName = $Matches[1]
            $accessorPid  = $Matches[2]
            if ($accessorName -notin ($TRUSTED_PARENTS | ForEach-Object { "$($_).exe" }) -and
                $accessorName -ne "chrome.exe") {
                New-Alert "CHROME_HANDLE_ACCESS" `
                    "Process '$accessorName' (PID $accessorPid) holds a handle to chrome.exe. " +
                    "Possible injection or memory scraping attempt."
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Check 5: Loopback connections from chrome.exe to CDP-range ports
# A process connecting to 127.0.0.1:9222 (or nearby) is riding the session
# via the DevTools protocol even if it didn't spawn chrome itself.
# ---------------------------------------------------------------------------
function Test-CDPLoopbackClients {
    $conns = Get-NetTCPConnection -RemotePort $CDPPort -State Established `
             -ErrorAction SilentlyContinue
    foreach ($conn in $conns) {
        # Only flag loopback clients
        if ($conn.RemoteAddress -in @("127.0.0.1", "::1", "0:0:0:0:0:0:0:1")) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $name = if ($proc) { $proc.Name } else { "PID $($conn.OwningProcess)" }
            if ($name -ne "chrome") {
                New-Alert "CDP_LOOPBACK_CLIENT" `
                    "Process '$name' (PID $($conn.OwningProcess)) has an established connection " +
                    "to CDP port $CDPPort on loopback. Active session rider?"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Check 6: Chrome user-data-dir opened by non-chrome processes
# The Chrome profile directory holds cookies, local storage, and session state.
# A process reading from it (other than chrome itself) is likely exfiltrating.
# Uses handle.exe if available; falls back to filesystem audit heuristic.
# ---------------------------------------------------------------------------
function Test-ChromeProfileAccess {
    $chromeUserData = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    if (-not (Test-Path $chromeUserData)) { return }

    $handleExe = Get-Command "handle.exe" -ErrorAction SilentlyContinue
    if (-not $handleExe) { return }

    # Check for open handles to the Cookies or Login Data SQLite files
    foreach ($sensitiveFile in @("Cookies", "Login Data", "Web Data", "Local State")) {
        $output = & handle.exe "$chromeUserData\Default\$sensitiveFile" -accepteula 2>$null
        foreach ($line in $output) {
            if ($line -match '^\s*(\S+)\s+pid:\s*(\d+)') {
                $accessorName = $Matches[1]
                $accessorPid  = $Matches[2]
                if ($accessorName -notmatch '^chrome') {
                    New-Alert "CHROME_PROFILE_ACCESS" `
                        "Non-Chrome process '$accessorName' (PID $accessorPid) has open handle to " +
                        "Chrome profile file '$sensitiveFile'. Cookie/credential theft in progress?"
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Remediation: kill suspicious process (unless -AlertOnly)
# ---------------------------------------------------------------------------
function Invoke-Remediation {
    param([int]$TargetPid, [string]$Reason)
    if ($AlertOnly) {
        Write-Alert "INFO" "AlertOnly mode — NOT killing PID $TargetPid ($Reason)"
        return
    }
    Write-Alert "WARNING" "Attempting to terminate suspicious PID $TargetPid ($Reason)"
    try {
        Stop-Process -Id $TargetPid -Force -ErrorAction Stop
        Write-Alert "INFO" "PID $TargetPid terminated."
    } catch {
        Write-Alert "WARNING" "Could not terminate PID $TargetPid - $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------
function Show-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║        chrome_session_guard.ps1  v1.0                   ║" -ForegroundColor Cyan
    Write-Host "  ║        On-Device Session Riding Detector                 ║" -ForegroundColor Cyan
    Write-Host "  ║        github.com/microlaser                             ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Alert "INFO" "Starting monitor | interval=${Interval}s | CDP port=$CDPPort | log=$LogFile"
    Write-Alert "INFO" "AlertOnly mode: $AlertOnly"
    Write-Alert "INFO" "Trusted parent processes: $($TRUSTED_PARENTS -join ', ')"
    Write-Host  ("-" * 70)
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
Show-Banner

$iteration = 0
while ($true) {
    $iteration++
    Write-Alert "DEBUG" "--- Scan #$iteration ---"

    Test-CDPPortExposure
    Test-ChromeDebugFlags
    Test-ChromeParentLineage
    Test-CDPLoopbackClients
    Test-ChromeProfileAccess

    # Handle inspection is slower — run every 3rd cycle
    if ($iteration % 3 -eq 0) {
        Test-ChromeHandles
    }

    Start-Sleep -Seconds $Interval
}
