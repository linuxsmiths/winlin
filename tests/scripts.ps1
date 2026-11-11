$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
foreach ($directory in @('scripts', 'tests')) {
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root $directory) -Filter '*.ps1') {
        $tokens = $null
        $errors = $null
        [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
        if ($errors.Count) { throw "$($file.Name): $($errors -join '; ')" }
    }
}
. (Join-Path $root 'scripts/windows-common.ps1')
# Native failures must remain visible even when PowerShell itself would otherwise keep running.
function Test-NativeFailure {
    $engine = (Get-Process -Id $PID).Path
    try {
        Invoke-WinlinNative -File $engine -Arguments @('-NoProfile', '-Command', 'exit 23')
    }
    catch {
        if ($_.Exception.Message -notmatch '23') { throw }
        return
    }
    throw 'Native command failure was ignored.'
}
Test-NativeFailure

# Failed cleanup must be visible but must not prevent subsequent rollback actions.
$engine = (Get-Process -Id $PID).Path
$warnings = @()
$cleaned = Invoke-WinlinCleanup -Description 'simulated native cleanup' -Action {
    Invoke-WinlinNative -File $engine -Arguments @('-NoProfile', '-Command', 'exit 23')
} -WarningVariable warnings -WarningAction SilentlyContinue
if ($cleaned -or $warnings.Count -ne 1 -or $warnings[0] -notmatch 'simulated native cleanup.*23') {
    throw 'Cleanup failure was not reported.'
}
if (-not (Invoke-WinlinCleanup -Description 'subsequent cleanup' -Action {})) {
    throw 'Successful cleanup was rejected.'
}

# A failed rollback must not replace the error that made provisioning fail in the first place.
try {
    try { throw 'original provisioning failure' }
    catch {
        $null = Invoke-WinlinCleanup -Description 'failed rollback' -Action {
            throw 'secondary cleanup failure'
        } -WarningVariable rollbackWarnings -WarningAction SilentlyContinue
        throw
    }
}
catch {
    if ($_.Exception.Message -ne 'original provisioning failure') { throw }
}
if ($rollbackWarnings.Count -ne 1 -or $rollbackWarnings[0] -notmatch 'secondary cleanup failure') {
    throw 'Secondary cleanup failure was not diagnosed.'
}

if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
    $null = Get-Command Set-Acl -CommandType Cmdlet
    $visualStudio = Get-WinlinVisualStudio
    if (-not $visualStudio -or -not (Get-WinlinCMake -VisualStudio $visualStudio) -or -not (Get-WinlinSdk)) {
        throw 'PowerShell toolchain discovery failed.'
    }
    try {
        & (Join-Path $root 'scripts/build.ps1') client
    }
    catch {
        if ($_.Exception.Message -notmatch 'Linux only') { throw }
        Write-Host 'PowerShell tests passed.'
        return
    }
    throw 'Windows client build was not rejected.'
}
else {
    try { Assert-WinlinWindows }
    catch {
        if ($_.Exception.Message -notmatch 'requires Windows') { throw }
        Write-Host 'PowerShell syntax, failure propagation, and OS guard tests passed.'
        return
    }
    throw 'Non-Windows host was accepted.'
}
