# Chrome Session Guard 🛡️

**chrome_session_guard.ps1** is a PowerShell-based runtime monitor that detects on-device Chrome session riding on Windows — the class of attack that remains fully effective even when Google's new Device Bound Session Credentials (DBSC) protection is active.

---

## The Problem: DBSC Doesn't Cover Everything

Google's Device Bound Session Credentials (DBSC), which shipped as enabled-by-default in Chrome 150 and reached General Availability for Windows in Chrome 146 (Spring 2026), represents a meaningful step forward in browser security. By binding session cookies to a hardware-backed key in the device's TPM, DBSC neutralizes the classic "steal once, replay anywhere" infostealer attack. A stolen session cookie becomes cryptographically useless on any other machine.

**But DBSC has a documented blind spot.**

From Google's own threat model: if malware achieves code execution on the local machine, it doesn't need to export the cookie at all. It can simply use the already-authenticated browser in place — issuing requests through the live session, driving Chrome via its DevTools Protocol, or injecting into the browser process directly. The private key never leaves the TPM. The protection is entirely bypassed. This is on-device session riding.

DBSC is also currently Windows-only. Linux Chrome users receive no hardware-backed session protection and remain vulnerable to the traditional cookie theft path as well.

---

## The Attack Surface

On-device session riding takes several concrete forms:

**Chrome DevTools Protocol (CDP) abuse** — Chrome exposes a full programmatic control API on a local TCP port (default: 9222) when launched with `--remote-debugging-port`. Malware can respawn Chrome with this flag, then connect to the port and issue arbitrary authenticated requests, navigate to pages, extract cookies, or exfiltrate session state — all through the legitimately authenticated browser, invisible to the server.

**Headless Chrome session riding** — An attacker spawns a hidden `chrome.exe` instance reusing the existing user profile directory, which contains the live session cookies. Since the cookies are read locally (not exported over the network), DBSC's TPM binding offers no protection.

**Chrome profile file theft** — The Chrome profile directory contains `Cookies`, `Login Data`, and `Local State` as SQLite files. A process with filesystem access can open these files directly while Chrome is running and extract raw session material.

**Process injection** — A process with `PROCESS_VM_READ` or `PROCESS_VM_WRITE` access to `chrome.exe` can read session memory or inject code that issues authenticated requests from within the browser's own process context.

**Anomalous parent spawning** — Legitimate Chrome is launched by `explorer.exe`, a shell, or relaunches itself. Malware spawning `chrome.exe` from a temp directory, a Python runtime, or a .NET dropper produces a detectable parent lineage anomaly.

---

## What Chrome Session Guard Does

Chrome Session Guard runs as a continuous polling monitor and detects all of the above in real time:

| Module | What It Detects |
|---|---|
| `Test-CDPPortExposure` | Any process listening on the CDP port (9222). Chrome should never expose this in normal operation. |
| `Test-ChromeDebugFlags` | Chrome instances launched with `--remote-debugging-port`, `--remote-debugging-pipe`, or `--headless` outside of print contexts. |
| `Test-ChromeParentLineage` | Chrome spawned by untrusted parent processes, escalating to ALERT when the parent runs from a temp or downloads path. |
| `Test-CDPLoopbackClients` | Non-Chrome processes with an established connection to the CDP port on loopback — the active session riding moment. |
| `Test-ChromeHandles` | Non-Chrome processes holding open handles to `chrome.exe` (requires Sysinternals `handle.exe`). Injection and memory scraping precursor. |
| `Test-ChromeProfileAccess` | Non-Chrome processes with open handles to `Cookies`, `Login Data`, or `Local State` profile files. |

All alerts are written to console with color-coded severity and to a structured log file in ISO 8601 format.

---

## Why Windows, and Why Now

DBSC's Windows-first rollout means Windows users currently have the strongest cookie theft protection of any platform. macOS support is announced but not yet shipped. Linux support has no committed timeline due to fragmented TPM availability and inconsistent hardware security APIs across distributions.

This creates an interesting asymmetry: Windows is now the hardest platform for remote session replay attacks, which increases the relative value of on-device techniques. As DBSC closes the remote theft path, attackers who have already achieved local execution have stronger incentive to pivot to local session riding rather than exfiltrating cookies for remote replay.

Chrome Session Guard is designed for exactly this environment — a Windows machine where DBSC is active and the remaining meaningful threat is local.

---

## Requirements

- Windows 10 or 11
- PowerShell 5.1+ (built into Windows)
- Administrator privileges (raw TCP and process inspection)
- Optional: [Sysinternals handle.exe](https://learn.microsoft.com/en-us/sysinternals/downloads/handle) on your PATH for handle-level inspection (Checks 5 and 6). All other modules work natively without it.

---

## Usage

```powershell
# Alert-only mode — no process termination, safe for monitoring
.\chrome_session_guard.ps1 -AlertOnly

# Active mode — terminates suspicious processes on detection
.\chrome_session_guard.ps1

# Custom polling interval and log path
.\chrome_session_guard.ps1 -Interval 3 -LogFile D:\security\chrome_guard.log -AlertOnly

# Add a trusted parent process (e.g. a custom launcher)
.\chrome_session_guard.ps1 -TrustedParents "mycompany_launcher" -AlertOnly
```

**Full parameters:**

| Parameter | Default | Description |
|---|---|---|
| `-Interval` | `5` | Polling interval in seconds |
| `-LogFile` | `C:\Logs\chrome_session_guard.log` | Alert log path |
| `-CDPPort` | `9222` | Chrome DevTools Protocol port to watch |
| `-TrustedParents` | *(see source)* | Additional trusted Chrome parent process names |
| `-AlertOnly` | off | Alert without killing processes |

---

## Sample Output

```
2026-06-11T14:22:01Z [INFO] Starting monitor | interval=5s | CDP port=9222
----------------------------------------------------------------------
2026-06-11T14:23:44Z [ALERT] [#1] CDP_PORT_EXPOSED | Process 'python' (PID 9142) is
  listening on CDP port 9222. Chrome should NEVER expose this in normal operation.
2026-06-11T14:23:49Z [ALERT] [#2] SUSPICIOUS_CHROME_PARENT | chrome.exe PID 10881
  spawned by untrusted parent: 'python' (PID 9142, path: C:\Users\user\AppData\Local\
  Temp\mal.exe)
2026-06-11T14:23:49Z [WARNING] Attempting to terminate suspicious PID 10881
```

---

## Limitations

Chrome Session Guard detects and alerts — it is not a replacement for endpoint detection and response (EDR) tooling, and it operates at the process/network layer rather than kernel level. A sufficiently privileged attacker who has already subverted the OS can evade userspace monitors. This tool is most effective as an early-warning layer on a hardened system where the attacker has not yet achieved kernel access.

The handle inspection modules (Checks 5 and 6) require Sysinternals `handle.exe`. The remaining four modules work natively on any Windows 10/11 system without additional dependencies.

---

## Related Tools

| Repo | Description |
|---|---|
| [wifi-guardian-windows](https://github.com/microlaser/wifi-guardian-windows) | Evil Twin and rogue AP detection for Windows (PowerShell) |
| [net_exploit_detector](https://github.com/microlaser/net_exploit_detector) | 16-module behavioral network anomaly detector |
| [apt_detector_improved](https://github.com/microlaser/apt_detector_improved) | APT detection via Mach VM APIs and process forensics (macOS) |
| [ndp_hunter](https://github.com/microlaser/ndp_hunter) | IPv6 rogue RA and RDNSS DNS hijack detector |
| [pff2](https://github.com/microlaser/pff2) | Hardened macOS pf firewall ruleset |

---

## License

MIT
