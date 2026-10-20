# DFIR Workstation

One PowerShell script that turns a fresh Windows machine into a DFIR analysis box. I use it to set up the machines I do SOC and DFIR work on: event logs, memory images, Windows artifacts and malware triage.

## Before you start

- Run it on a **dedicated analysis machine or VM**, not your daily computer and never on a machine you are investigating. It installs software and changes system settings (see [What it changes](#what-it-changes)).
- Windows 10 or 11, x64, with internet access and an administrator account.
- Tested on Windows 10 IoT Enterprise LTSC 21H2 and Windows 11 IoT Enterprise LTSC 2024 (24H2), PowerShell 5.1.

## Install

1. Download this repo (Code > Download ZIP) and extract it.
2. Open PowerShell **as administrator** (right click > Run as administrator).
3. Go to the extracted folder and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-DfirWorkstation.ps1
```

Run it from a normal PowerShell window, not over SSH or a scheduled task. It takes a while: each step prints a line, and a failed step does not stop the others. Failures are listed at the end.

On a dedicated machine, add `-AddDefenderExclusion` so Defender stops quarantining detection rules and malware samples in `C:\DFIR`.

## After install

1. Sign out and back in once (font and keyboard shortcut).
2. Open a new terminal. Every tool runs by name from any folder:

```powershell
hayabusa help
chainsaw --help
vol -h
EvtxECmd
```

3. Put each investigation in its own folder under `C:\DFIR\Cases`.

## What's installed

| Tool | Use it for |
|---|---|
| Eric Zimmerman tools | Parsing Windows artifacts (registry, MFT, prefetch, event logs, LNK...). Timeline Explorer opens their CSV output. |
| Hayabusa | Fast event log timelines and detections with Sigma rules |
| Chainsaw | Searching and hunting through event logs |
| Volatility 3 | Analyzing memory images |
| MemProcFS | Browsing a memory image as files and folders |
| YARA-X | Scanning files with YARA rules (`yr`) |
| capa | Finding what an executable can do |
| FLOSS | Extracting hidden and obfuscated strings from malware |
| CyberChef | Decoding and transforming data, offline in the browser |
| Velociraptor | Collecting artifacts from endpoints |
| Sysinternals Suite | Live system inspection (Procmon, Autoruns, Process Explorer...) |
| Wireshark | Analyzing network captures |
| DB Browser for SQLite | Opening SQLite databases (browser history, app data) |
| 7-Zip, Python 3.12 | Archives and scripting |
| Windows Terminal, winget, Brave | Day to day use |

Tools live in `C:\DFIR\Tools`. `C:\DFIR\Tools\manifest.csv` records the version, source URL and SHA256 of every download, handy for reports.

## What it changes

All of this is for the user who runs the script:

- Explorer shows hidden files, protected OS files and file extensions, then restarts (open Explorer windows close).
- "Open in Terminal" in the folder right click menu (under "Show more options" on Windows 11).
- `Ctrl+Alt+T` opens an admin terminal.
- JetBrains Mono as the console and terminal font.
- Bash-like keys in the PowerShell profile (Ctrl+A, Ctrl+E, Ctrl+D, prefix history search), inside a marked block that is replaced on each run.
- PowerShell execution policy set to `RemoteSigned` if none was set.

## Update

Run the script again. Tools already at the latest version are skipped.
