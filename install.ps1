# factum installer for Windows (PowerShell 5.1 or newer).
#
#   irm https://raw.githubusercontent.com/overcuriousity/factum-rs/main/install.ps1 | iex
#
# With options (download first, then run):
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Version v2.1.3
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

function Remove-FromPath($folder) {
    $path = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($path) {
        $parts = $path.Split(";") | Where-Object { $_ -and ($_.TrimEnd("\") -ne $folder.TrimEnd("\")) }
        [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
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
        }
    } else {
        $Base = if ($Version -eq "latest") { "https://github.com/$Repo/releases/latest/download" } else { "https://github.com/$Repo/releases/download/$Version" }
        Say "downloading $Asset ($Version)"
        Invoke-WebRequest -UseBasicParsing "$Base/$Asset" -OutFile (Join-Path $Tmp $Asset)
        if (-not $SkipVerify) { Invoke-WebRequest -UseBasicParsing "$Base/SHA256SUMS" -OutFile (Join-Path $Tmp "SHA256SUMS") }
    }
    if (-not $SkipVerify) {
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

    $path = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not ($path -split ";" | Where-Object { $_.TrimEnd("\") -eq $Dir.TrimEnd("\") })) {
        [Environment]::SetEnvironmentVariable("Path", (($path, $Dir) -ne "" -join ";"), "User")
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
