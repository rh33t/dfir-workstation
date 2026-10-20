#Requires -RunAsAdministrator
param(
    # Dedicated analysis machines only: rule sets and case evidence get quarantined otherwise
    [switch]$AddDefenderExclusion
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root       = 'C:\DFIR'
$Tools      = Join-Path $Root 'Tools'
$Installers = Join-Path $Tools '_installers'
$Manifest   = Join-Path $Tools 'manifest.csv'
$NetVersion = 9
$PyVersion  = '3.12.10'

# Desktop Runtime also ships Microsoft.NETCore.App, needed by the EZ CLI tools
$DotnetSetup = @{
    Name = 'DotNetDesktopRuntime'; Version = 'latest'; Arguments = '/install /quiet /norestart'
    Url  = "https://aka.ms/dotnet/$NetVersion.0/windowsdesktop-runtime-win-x64.exe"
}

$Setups = @(
    @{ Name = '7-Zip';     Repo = 'ip7z/7zip';                   Pattern = '^7z\d+-x64\.msi$' }
    @{ Name = 'DBBrowser'; Repo = 'sqlitebrowser/sqlitebrowser'; Pattern = 'win64\.msi$' }
    @{ Name = 'Wireshark'; Url = 'https://2.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe'; Version = 'latest'; Arguments = '/S' }
    @{
        Name = 'Python'; Version = $PyVersion; Arguments = '/quiet InstallAllUsers=1 PrependPath=1'
        Url  = "https://www.python.org/ftp/python/$PyVersion/python-$PyVersion-amd64.exe"
    }
)

# Extra apps from the winget repository, by exact ID (find IDs with `winget search <name>`)
$WingetPackages = @(
    'Brave.Brave'
)

# Managed block of the current user's PowerShell profile, replaced on every run
$ProfileBlock = @'
# beginning/end of line like bash
Set-PSReadLineKeyHandler -Key Ctrl+a -Function BeginningOfLine
Set-PSReadLineKeyHandler -Key Ctrl+e -Function EndOfLine

# menu completion with tab
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete

# search history with up/down arrows
Set-PSReadLineKeyHandler -Key UpArrow   -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward

# keep cursor at end when searching history
Set-PSReadLineOption -HistorySearchCursorMovesToEnd

# exit like unix
Set-PSReadLineKeyHandler -Key Ctrl+d -Function DeleteCharOrExit
'@

# Command: PATH name for tools whose exe name carries a version or platform
$Portables = @(
    @{ Name = 'Sysinternals'; Url = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'; Version = 'latest' }
    @{ Name = 'Hayabusa';     Repo = 'Yamato-Security/hayabusa';      Pattern = '-win-x64\.zip$';                       Command = 'hayabusa' }
    @{ Name = 'Chainsaw';     Repo = 'WithSecureOpenSource/chainsaw'; Pattern = '^chainsaw_all_platforms\+rules\.zip$'; Command = 'chainsaw' }
    @{ Name = 'Velociraptor'; Repo = 'Velocidex/velociraptor';        Pattern = '-windows-amd64\.exe\.gz$';             Command = 'velociraptor' }
    @{ Name = 'MemProcFS';    Repo = 'ufrisk/MemProcFS';              Pattern = '_v[\d.]+-win_x64-\d+\.zip$' }
    @{ Name = 'YARA-X';       Repo = 'VirusTotal/yara-x';             Pattern = '^yara-x-v.*-x86_64-pc-windows-msvc\.zip$' }
    @{ Name = 'capa';         Repo = 'mandiant/capa';                 Pattern = 'windows\.zip$' }
    @{ Name = 'FLOSS';        Repo = 'mandiant/flare-floss';          Pattern = 'windows\.zip$' }
    @{ Name = 'CyberChef';    Repo = 'gchq/CyberChef';                Pattern = '^CyberChef_.*\.zip$' }
    # Unpackaged build: no Store or Appx dependencies, works on LTSC and Server
    @{ Name = 'WindowsTerminal'; Repo = 'microsoft/terminal';        Pattern = '^Microsoft\.WindowsTerminal_[\d.]+_x64\.zip$' }
)

function Add-Manifest($Name, $Version, $Url, $Path) {
    [pscustomobject]@{
        Date    = Get-Date -Format s
        Name    = $Name
        Version = $Version
        Url     = $Url
        SHA256  = (Get-FileHash $Path -Algorithm SHA256).Hash
    } | Export-Csv $Manifest -Append -NoTypeInformation
}

function Resolve-Source($Tool) {
    if (-not $Tool.Repo) {
        $version = $Tool.Version
        # Unversioned URLs: the server's Last-Modified date stands in for a version
        if ($version -eq 'latest') {
            $modified = (Invoke-WebRequest -UseBasicParsing -Method Head -Uri $Tool.Url).Headers['Last-Modified']
            if ($modified) { $version = $modified }
        }
        return $Tool.Url, $version
    }
    $rel = Invoke-RestMethod "https://api.github.com/repos/$($Tool.Repo)/releases/latest"
    $asset = $rel.assets | Where-Object name -Match $Tool.Pattern | Select-Object -First 1
    if (-not $asset) { throw "no asset matching '$($Tool.Pattern)' in $($rel.tag_name)" }
    return $asset.browser_download_url, $rel.tag_name
}

function Save-File($Name, $Url, $Version, $Dir) {
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    $file = Join-Path $Dir ([IO.Path]::GetFileName(([uri]$Url).AbsolutePath))
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $file
    Add-Manifest $Name $Version $Url $file
    return $file
}

function Expand-GZip($Path) {
    $in  = [IO.File]::OpenRead($Path)
    $out = [IO.File]::Create(($Path -replace '\.gz$'))
    try { (New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)).CopyTo($out) }
    finally { $out.Dispose(); $in.Dispose() }
    Remove-Item $Path
}

function Test-Recorded($Name, $Version) {
    (Test-Path $Manifest) -and [bool](Import-Csv $Manifest | Where-Object { $_.Name -eq $Name -and $_.Version -eq $Version })
}

function Install-Portable($Tool) {
    $url, $version = Resolve-Source $Tool
    $dest = Join-Path $Tools $Tool.Name
    # Skipping known versions also avoids overwriting files of a tool that is currently running
    if ($version -ne 'latest' -and (Test-Path $dest) -and (Test-Recorded $Tool.Name $version)) {
        Write-Host "    $version already installed"
        return
    }
    $file = Save-File $Tool.Name $url $version $dest
    if ($file -like '*.zip') {
        Expand-Archive $file -DestinationPath $dest -Force
        Remove-Item $file
    } elseif ($file -like '*.gz') {
        Expand-GZip $file
    }
}

# -Force reinstalls even when this version is already in the manifest
function Install-Setup($Tool, [switch]$Force) {
    $url, $version = Resolve-Source $Tool
    if (-not $Force -and $version -ne 'latest' -and (Test-Recorded $Tool.Name $version)) {
        Write-Host "    $version already installed"
        return
    }
    $file = Save-File $Tool.Name $url $version $Installers
    if ($file -like '*.msi') {
        $p = Start-Process msiexec.exe -ArgumentList "/i `"$file`" /qn /norestart" -Wait -PassThru
    } else {
        $p = Start-Process $file -ArgumentList $Tool.Arguments -Wait -PassThru
    }
    # 3010 means success with a pending reboot
    if ($p.ExitCode -notin 0, 3010) { throw "installer exit code $($p.ExitCode)" }
}

# Repair-WinGetPackageManager can report success without a working winget, so check the binary itself
function Test-Winget {
    $exe = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
    if (-not (Test-Path $exe)) { return $false }
    try { & $exe --version *> $null; return $LASTEXITCODE -eq 0 } catch { return $false }
}

# Official sideload for editions without the Store, provisioned for every user
function Install-WingetManual {
    $repo = 'microsoft/winget-cli'
    $dir  = Join-Path $Installers 'winget'
    $url, $version = Resolve-Source @{ Repo = $repo; Pattern = '\.msixbundle$' }
    $bundle = Save-File 'winget' $url $version $dir
    $url, $version = Resolve-Source @{ Repo = $repo; Pattern = '_License1\.xml$' }
    $license = Save-File 'winget-license' $url $version $dir
    $url, $version = Resolve-Source @{ Repo = $repo; Pattern = '^DesktopAppInstaller_Dependencies\.zip$' }
    $depsZip = Save-File 'winget-dependencies' $url $version $dir
    $depsDir = Join-Path $dir 'dependencies'
    Expand-Archive $depsZip -DestinationPath $depsDir -Force
    $deps = Get-ChildItem (Join-Path $depsDir 'x64') -Filter *.appx | Select-Object -Expand FullName
    Add-AppxProvisionedPackage -Online -PackagePath $bundle -LicensePath $license -DependencyPackagePath $deps | Out-Null
    # Provisioning only applies at next logon, register it for the current user now
    Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
}

# Installs, updates or skips a package through the Microsoft.WinGet.Client module
function Sync-WingetPackage($Id) {
    $installed = Get-WinGetPackage -Id $Id -MatchOption Equals
    if ($installed -and -not $installed.IsUpdateAvailable) {
        Write-Host "    $($installed.InstalledVersion) already installed"
        return
    }
    $result = if ($installed) {
        Update-WinGetPackage -Id $Id -MatchOption Equals -Source winget -Mode Silent
    } else {
        Install-WinGetPackage -Id $Id -MatchOption Equals -Source winget -Mode Silent
    }
    if (-not $result.Succeeded()) { throw $result.ErrorMessage() }
}

$Failed = New-Object System.Collections.Generic.List[string]

# A failed step is reported and recorded, the following steps still run
function Invoke-Step($Name, [scriptblock]$Action) {
    Write-Host "[$(Get-Date -Format HH:mm:ss)] $Name"
    try { & $Action } catch { Write-Warning "${Name}: $_"; $Failed.Add($Name) }
}

# A click in a classic console starts a QuickEdit selection that freezes the script until Enter
Add-Type -Namespace Native -Name ConsoleMode -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
'@
$StdIn = [Native.ConsoleMode]::GetStdHandle(-10)
$SavedMode = [uint32]0
$HasConsole = [Native.ConsoleMode]::GetConsoleMode($StdIn, [ref]$SavedMode)
if ($HasConsole) {
    # Clear ENABLE_QUICK_EDIT_MODE (0x40); ENABLE_EXTENDED_FLAGS (0x80) must be set for the change to apply
    [void][Native.ConsoleMode]::SetConsoleMode($StdIn, [uint32](($SavedMode -band (-bnot 0x40)) -bor 0x80))
}

# The console mode belongs to the window, not this process, so restore it on every exit path
function Restore-ConsoleMode {
    if ($HasConsole) { [void][Native.ConsoleMode]::SetConsoleMode($StdIn, $SavedMode) }
}
trap { Restore-ConsoleMode; break }

foreach ($d in $Tools, (Join-Path $Root 'Cases')) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}

if ($AddDefenderExclusion) {
    Invoke-Step 'Defender exclusion' {
        Add-MpPreference -ExclusionPath $Root
        Write-Warning "Defender no longer scans $Root"
    }
}

# winget: missing on LTSC and Server, and without the Store nothing updates it, so every run repairs to latest
Invoke-Step 'winget' {
    try {
        if (-not (Get-Module -ListAvailable Microsoft.WinGet.Client)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
            Install-Module Microsoft.WinGet.Client -Scope AllUsers -Repository PSGallery -Force
        }
        Repair-WinGetPackageManager -AllUsers -Latest
    } catch { Write-Warning "Repair-WinGetPackageManager failed, trying manual install: $_" }
    if (-not (Test-Winget)) { Install-WingetManual }
    if (-not (Test-Winget)) { throw 'winget still not available, tools below do not need it' }
}

Invoke-Step ".NET Desktop Runtime $NetVersion" {
    $runtimes = if (Get-Command dotnet -ErrorAction SilentlyContinue) { dotnet --list-runtimes } else { @() }
    if (-not (@($runtimes) -match "^Microsoft\.WindowsDesktop\.App $NetVersion\.")) { Install-Setup $DotnetSetup -Force }
}

foreach ($t in $Setups) {
    Invoke-Step $t.Name { Install-Setup $t }
}

foreach ($id in $WingetPackages) {
    Invoke-Step "winget $id" { Sync-WingetPackage $id }
}

Invoke-Step 'Eric Zimmerman tools' {
    $ezScript = Join-Path $Tools 'Get-ZimmermanTools.ps1'
    # Pinned: since 64e81a1 (2026-10-17) master only fetches .NET 10 (/net/) builds, which the tool index does not list yet
    # To unpin: once https://ericzimmerman.github.io links /net/ zips, set $EzCommit = 'master' and $NetVersion = 10
    $EzCommit = 'd808d1dfe6446faf884576a8a1c11b6875197a19'
    $ezUrl = "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/$EzCommit/Get-ZimmermanTools.ps1"
    Invoke-WebRequest -UseBasicParsing -Uri $ezUrl -OutFile $ezScript
    Unblock-File $ezScript
    Add-Manifest 'Get-ZimmermanTools' $EzCommit $ezUrl $ezScript
    & $ezScript -Dest (Join-Path $Tools 'EZ') -NetVersion $NetVersion
}

foreach ($t in $Portables) {
    Invoke-Step $t.Name { Install-Portable $t }
}

# Volatility 3 in its own venv to keep the system Python clean
Invoke-Step 'Volatility 3' {
    $vol = Join-Path $Tools 'Volatility3'
    $py  = Join-Path $env:ProgramFiles ('Python' + ($PyVersion -replace '^(\d+)\.(\d+).*', '$1$2') + '\python.exe')
    if (-not (Test-Path $vol)) { & $py -m venv $vol }
    & (Join-Path $vol 'Scripts\python.exe') -m pip install --upgrade volatility3
}

$FontFace = 'JetBrains Mono'
Invoke-Step 'JetBrains Mono font' {
    $url, $version = Resolve-Source @{ Repo = 'JetBrains/JetBrainsMono'; Pattern = '^JetBrainsMono-[\d.]+\.zip$' }
    $zip = Save-File 'JetBrainsMono' $url $version $Installers
    $tmp = Join-Path $env:TEMP 'JetBrainsMono'
    Expand-Archive $zip -DestinationPath $tmp -Force
    $FontKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'
    foreach ($ttf in Get-ChildItem (Join-Path $tmp 'fonts\ttf') -Filter 'JetBrainsMono-*.ttf') {
        # A loaded font file cannot be overwritten, so existing files are kept
        $target = Join-Path $env:windir "Fonts\$($ttf.Name)"
        if (-not (Test-Path $target)) { Copy-Item $ttf.FullName $target }
        Set-ItemProperty $FontKey "$($ttf.BaseName) (TrueType)" $ttf.Name
    }
    Remove-Item $tmp -Recurse -Force
}

Invoke-Step 'Console font (cmd, PowerShell windows, current user)' {
    $ConsoleFonts = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Console\TrueTypeFont'
    $registered = Get-ItemProperty $ConsoleFonts
    if ($registered.PSObject.Properties.Value -notcontains $FontFace) {
        # Value names must be unique strings of zeros
        $slot = '0'
        while ($registered.PSObject.Properties.Name -contains $slot) { $slot += '0' }
        New-ItemProperty $ConsoleFonts -Name $slot -Value $FontFace -PropertyType String | Out-Null
    }
    # Per-app subkeys override the HKCU:\Console defaults
    foreach ($key in @(Get-Item 'HKCU:\Console') + @(Get-ChildItem 'HKCU:\Console')) {
        Set-ItemProperty $key.PSPath FaceName $FontFace
        Set-ItemProperty $key.PSPath FontFamily 54 -Type DWord
        Set-ItemProperty $key.PSPath FontWeight 400 -Type DWord
    }
}

# Start menu shortcut to the newest version, default font for every profile
Invoke-Step 'Windows Terminal setup' {
    $Wt = Get-ChildItem (Join-Path $Tools 'WindowsTerminal') -Recurse -Filter WindowsTerminal.exe |
        Sort-Object LastWriteTime | Select-Object -Last 1
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Windows Terminal.lnk")
    $lnk.TargetPath = $Wt.FullName
    $lnk.Save()

    # Ctrl+Alt+T opens an elevated terminal in the user's home; Explorer only binds hotkeys of Start menu shortcuts
    $adminLnk = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Windows Terminal (Admin).lnk'
    $lnk = $shell.CreateShortcut($adminLnk)
    $lnk.TargetPath = Join-Path $Wt.DirectoryName 'wt.exe'
    $lnk.Arguments = "-d `"$env:USERPROFILE`""
    $lnk.Hotkey = 'CTRL+ALT+T'
    $lnk.Save()
    # WScript.Shell cannot set "Run as administrator": it is LinkFlags bit 0x2000 (MS-SHLLINK), byte 0x15 of the file
    $bytes = [IO.File]::ReadAllBytes($adminLnk)
    $bytes[0x15] = $bytes[0x15] -bor 0x20
    [IO.File]::WriteAllBytes($adminLnk, $bytes)

    # Explorer "Open in Terminal" on folders and folder backgrounds, which only the Store build registers
    foreach ($type in 'Directory', 'Directory\Background') {
        $key = "HKCU:\Software\Classes\$type\shell\OpenWindowsTerminal"
        New-Item "$key\command" -Force | Out-Null
        Set-ItemProperty $key '(default)' 'Open in Terminal'
        Set-ItemProperty $key Icon $Wt.FullName
        # "\." keeps a drive root like C:\ from escaping the closing quote
        Set-ItemProperty "$key\command" '(default)' "`"$(Join-Path $Wt.DirectoryName 'wt.exe')`" -d `"%V\.`""
    }

    $WtSettings = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows Terminal\settings.json'
    if (-not (Test-Path $WtSettings)) {
        New-Item -ItemType Directory -Path (Split-Path $WtSettings) -Force | Out-Null
        Set-Content $WtSettings "{ `"profiles`": { `"defaults`": { `"font`": { `"face`": `"$FontFace`" } } } }" -Encoding Ascii
    } elseif (-not (Select-String -Path $WtSettings -Pattern $FontFace -SimpleMatch -Quiet)) {
        Write-Warning "Windows Terminal settings already exist, set profiles.defaults.font.face in $WtSettings"
    }
}

Invoke-Step 'Explorer: hidden files, protected OS files and extensions (current user)' {
    $advanced = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    Set-ItemProperty $advanced Hidden 1 -Type DWord
    Set-ItemProperty $advanced HideFileExt 0 -Type DWord
    Set-ItemProperty $advanced ShowSuperHidden 1 -Type DWord
    # Winlogon relaunches the shell unelevated; only this session's Explorer, other signed-in users keep theirs
    $session = (Get-Process -Id $PID).SessionId
    Get-Process explorer -ErrorAction SilentlyContinue | Where-Object SessionId -eq $session | Stop-Process -Force
}

Invoke-Step 'PowerShell profile (current user)' {
    # Profiles never load under the client default Restricted policy; an explicit user choice is kept
    $policyKey = 'HKCU:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'
    if ((Get-ExecutionPolicy -Scope CurrentUser) -eq 'Undefined') {
        New-Item $policyKey -Force | Out-Null
        Set-ItemProperty $policyKey ExecutionPolicy RemoteSigned
    }

    $path  = $PROFILE.CurrentUserCurrentHost
    $begin = '# BEGIN dfir-workstation'
    $end   = '# END dfir-workstation'
    $block = "$begin`r`n$($ProfileBlock.Trim())`r`n$end"
    $current = if (Test-Path $path) { Get-Content $path -Raw } else { '' }
    if ($current -match "(?s)$([regex]::Escape($begin)).*?$([regex]::Escape($end))") {
        $content = $current.Replace($Matches[0], $block)
    } elseif ($current.Trim()) {
        $content = $current.TrimEnd() + "`r`n`r`n" + $block
    } else {
        $content = $block
    }
    New-Item -ItemType Directory -Path (Split-Path $path) -Force | Out-Null
    Set-Content $path $content -Encoding UTF8
}

# One .cmd shim per tool in a single PATH folder, rebuilt each run so updated versions are picked up
Invoke-Step 'PATH shims' {
    $bin = Join-Path $Tools 'bin'
    Remove-Item $bin -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    $exes = @(Get-ChildItem $Tools -Recurse -Filter *.exe |
        Where-Object { $_.FullName.Substring($Tools.Length + 1) -notmatch '^(_installers|bin|Volatility3)\\' })
    $exes += @(Get-Item (Join-Path $Tools 'Volatility3\Scripts\vol.exe') -ErrorAction SilentlyContinue)
    $commands = @{}
    foreach ($t in $Portables) { if ($t.Command) { $commands[$t.Name] = $t.Command } }
    # Oldest first so the newest version wins when names collide
    foreach ($exe in $exes | Sort-Object LastWriteTime) {
        $folder = $exe.FullName.Substring($Tools.Length + 1).Split('\')[0]
        $name = if ($commands[$folder]) { $commands[$folder] } else { $exe.BaseName }
        Set-Content (Join-Path $bin "$name.cmd") "@`"$($exe.FullName)`" %*" -Encoding Ascii
    }
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (($machinePath -split ';') -notcontains $bin) {
        [Environment]::SetEnvironmentVariable('Path', "$machinePath;$bin", 'Machine')
    }
}

Restore-ConsoleMode
if ($Failed.Count) {
    Write-Warning "Failed steps: $($Failed -join ', ')"
    exit 1
}
Write-Host "Done. Versions and hashes: $Manifest"
