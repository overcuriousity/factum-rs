# factum installer for Windows (PowerShell 5.1 or newer).
#
#   irm https://raw.githubusercontent.com/overcuriousity/factum-rs/main/install.ps1 | iex
#
# With options (download first, then run):
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Version v2.1.4
#
# Air-gapped: copy factum-x86_64-pc-windows-msvc.zip and SHA256SUMS to the machine, then
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Archive .\factum-x86_64-pc-windows-msvc.zip
#
#   -Version TAG    install this release (default: the latest)
#   -Dir DIR        install here (default: %LOCALAPPDATA%\Programs\factum)
#   -Archive FILE   install from a downloaded archive, checked against the SHA256SUMS file next to it
#   -NoShortcut     do not add a Start menu entry
#   -SkipVerify     do not check the SHA-256 checksum (not recommended)
#   -Uninstall      remove factum and the Start menu entry; the database and seal files are kept
param(
    [string]$Version = "latest",
    [string]$Dir = "",
    [string]$Archive = "",
    [switch]$NoShortcut,
    [switch]$SkipVerify,
    [switch]$Uninstall
)
$ErrorActionPreference = "Stop"
$Repo = if ($env:FACTUM_REPO) { $env:FACTUM_REPO } else { "overcuriousity/factum-rs" }
if (-not $Dir) { $Dir = if ($env:FACTUM_INSTALL_DIR) { $env:FACTUM_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\factum" } }
$Asset = "factum-x86_64-pc-windows-msvc.zip"
$Shortcut = Join-Path ([Environment]::GetFolderPath("Programs")) "Factum Notes.lnk"

function Say($text) { Write-Host "factum-install: $text" }

# the user PATH is read and written through the registry so %VAR% entries stay unexpanded (REG_EXPAND_SZ)
function Get-UserPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment")
    try {
        if ($null -eq $key) { return "" }
        $value = $key.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return [string]$value
    } finally { if ($key) { $key.Close() } }
}
function Set-UserPath($value) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("Environment")
    try { $key.SetValue("Path", $value, [Microsoft.Win32.RegistryValueKind]::ExpandString) } finally { $key.Close() }
    # the registry write does not notify Explorer; setting a (nonexistent) variable makes .NET broadcast the change
    [Environment]::SetEnvironmentVariable("FACTUM_PATH_CHANGED", $null, "User")
}

function Remove-FromPath($folder) {
    $path = Get-UserPath
    if ($path) {
        $parts = $path.Split(";") | Where-Object { $_ -and ([Environment]::ExpandEnvironmentVariables($_).TrimEnd("\") -ne $folder.TrimEnd("\")) }
        Set-UserPath ($parts -join ";")
    }
}

if ($Uninstall) {
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Dir "factum.exe"), $Shortcut
    Remove-FromPath $Dir
    Say "removed $Dir\factum.exe and the Start menu entry. Your database and seal files were not touched."
    return
}

if (-not [Environment]::Is64BitOperatingSystem) { throw "factum needs 64-bit Windows" }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("factum-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
    if ($Archive) {
        if (-not (Test-Path $Archive)) { throw "$Archive does not exist" }
        $Asset = Split-Path $Archive -Leaf
        Copy-Item $Archive (Join-Path $Tmp $Asset)
        $Sums = Join-Path (Split-Path (Resolve-Path $Archive) -Parent) "SHA256SUMS"
        if (-not $SkipVerify) {
            if (-not (Test-Path $Sums)) { throw "SHA256SUMS not found next to $Archive; copy it from the release too (or use -SkipVerify)" }
            Copy-Item $Sums (Join-Path $Tmp "SHA256SUMS")
            if (Test-Path "$Sums.asc") { Copy-Item "$Sums.asc" (Join-Path $Tmp "SHA256SUMS.asc") }
        }
    } else {
        $Base = if ($Version -eq "latest") { "https://github.com/$Repo/releases/latest/download" } else { "https://github.com/$Repo/releases/download/$Version" }
        Say "downloading $Asset ($Version)"
        Invoke-WebRequest -UseBasicParsing "$Base/$Asset" -OutFile (Join-Path $Tmp $Asset)
        if (-not $SkipVerify) {
            Invoke-WebRequest -UseBasicParsing "$Base/SHA256SUMS" -OutFile (Join-Path $Tmp "SHA256SUMS")
            try { Invoke-WebRequest -UseBasicParsing "$Base/SHA256SUMS.asc" -OutFile (Join-Path $Tmp "SHA256SUMS.asc") } catch { Remove-Item -ErrorAction SilentlyContinue (Join-Path $Tmp "SHA256SUMS.asc") }
        }
    }
    if (-not $SkipVerify) {
        # a bad signature stops the install; no gpg, no .asc or no release key only warns (no key is fetched)
        $Asc = Join-Path $Tmp "SHA256SUMS.asc"
        if (-not (Test-Path $Asc)) {
            Say "warning: no SHA256SUMS.asc; only the integrity of the archive was checked, not who published it"
        } elseif (-not (Get-Command gpg -ErrorAction SilentlyContinue)) {
            Say "warning: gpg is not installed; only the integrity of the archive was checked, not who published it"
        } else {
            $ErrorActionPreference = "Continue"
            try { $status = (& gpg --batch --status-fd 1 --verify $Asc (Join-Path $Tmp "SHA256SUMS") 2>$null) -join "`n" } finally { $ErrorActionPreference = "Stop" }
            if ($status -match "(?m)^\[GNUPG:\] (BADSIG|EXPSIG|REVKEYSIG) ") {
                throw "the signature on SHA256SUMS is bad, expired or from a revoked key; nothing was installed"
            } elseif ($status -match "(?m)^\[GNUPG:\] EXPKEYSIG ") {
                Say "warning: the signature on SHA256SUMS is good, but the signing key has expired since; make sure that key is the release key you trust"
            } elseif ($status -match "(?m)^\[GNUPG:\] GOODSIG ") {
                Say "signature on SHA256SUMS is good; make sure that key is the release key you trust"
            } elseif ($status -match "(?m)^\[GNUPG:\] (NO_PUBKEY|ERRSIG) ") {
                Say "warning: the release key is not in your keyring; only the integrity of the archive was checked, not who published it"
            } else {
                throw "SHA256SUMS.asc could not be checked with gpg; nothing was installed"
            }
        }
        $line = Get-Content (Join-Path $Tmp "SHA256SUMS") | Where-Object { $_ -match "  $([regex]::Escape($Asset))$" } | Select-Object -First 1
        if (-not $line) { throw "$Asset is not listed in SHA256SUMS" }
        $expected = $line.Split(" ")[0].ToLower()
        $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $Tmp $Asset)).Hash.ToLower()
        if ($expected -ne $actual) { throw "checksum mismatch for $Asset (expected $expected, got $actual)" }
        Say "checksum OK ($actual)"
    }
    Expand-Archive -Path (Join-Path $Tmp $Asset) -DestinationPath $Tmp -Force
    $Exe = Get-ChildItem -Path $Tmp -Recurse -Filter factum.exe | Select-Object -First 1
    if (-not $Exe) { throw "the archive contains no factum.exe" }
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Copy-Item $Exe.FullName (Join-Path $Dir "factum.exe") -Force
    Get-ChildItem -Path $Exe.DirectoryName -File | Where-Object { $_.Name -ne "factum.exe" } | Copy-Item -Destination $Dir -Force
    Say "installed $Dir\factum.exe"

    $path = Get-UserPath
    if (-not ($path -split ";" | Where-Object { [Environment]::ExpandEnvironmentVariables($_).TrimEnd("\") -eq $Dir.TrimEnd("\") })) {
        Set-UserPath (($path, $Dir) -ne "" -join ";")
        Say "added $Dir to your PATH (open a new terminal to use 'factum')"
    }
    if (-not $NoShortcut) {
        $shell = New-Object -ComObject WScript.Shell
        $link = $shell.CreateShortcut($Shortcut)
        $link.TargetPath = Join-Path $Dir "factum.exe"
        $link.Arguments = "--gui"
        $link.WorkingDirectory = $env:USERPROFILE
        $link.Description = "Forensic notes with signed, tamper-evident case logs"
        $link.Save()
        Say "added Factum Notes to the Start menu"
    }
    if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) {
        Say "note: gpg is not installed; install Gpg4win (https://www.gpg4win.org/) to sign notes"
    }
    Say "done. Start the GUI from the Start menu, or run 'factum --gui'."
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Tmp
}
