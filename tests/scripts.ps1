$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $root 'scripts') -Filter '*.ps1') {
    $tokens = $null
    $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count) { throw "$($file.Name): $($errors -join '; ')" }
}
. (Join-Path $root 'scripts/windows-common.ps1')
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
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
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
