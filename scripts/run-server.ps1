[CmdletBinding()]
param(
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build'),
    [ValidateSet('Debug', 'Release', 'RelWithDebInfo', 'MinSizeRel')][string]$Configuration = 'Release',
    [string]$StateDirectory = (Join-Path $PSScriptRoot '..\.winlin-local'),
    [string]$ServerExe = '',
    [string]$BindAddress = '127.0.0.1',
    [ValidateRange(1, 65535)][int]$Port = 38443,
    [ValidateRange(1, 256)][int]$Workers,
    [ValidateRange(1, 65536)][int]$MaxConnections,
    [string]$Cipher,
    [string]$TokenFile = '',
    [string]$SessionFile,
    [string]$StopFile,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
if ($Help) {
    @'
Usage: .\scripts\run-server.ps1 [-BuildDirectory PATH] [-Configuration Release]
    [-StateDirectory PATH] [-ServerExe PATH] [-BindAddress IP] [-Port N]
    [-Workers N] [-MaxConnections N] [-Cipher SUITE] [-TokenFile PATH]
    [-SessionFile PATH] [-StopFile PATH]

Defaults: build\Release\winlin-server.exe, no authentication, 127.0.0.1:38443.
An explicit -TokenFile enables authentication. Default directories are relative to the repository; supplied
relative paths use the caller's working directory. -ServerExe overrides binary
discovery. Unspecified workload settings retain the native server defaults.

Provision the matching HTTP.sys endpoint with scripts\setup-server.ps1 first.
Run as the same account that owns its URL reservation and credential files.
This launcher never builds, provisions certificates, resets pairing, or changes
firewall/Schannel policies. See docs\windows.md for setup.
'@
    return
}

try {
    . (Join-Path $PSScriptRoot 'windows-common.ps1')
    Assert-WinlinWindows

    foreach ($name in @('BuildDirectory', 'StateDirectory', 'ServerExe', 'BindAddress', 'TokenFile')) {
        if ($PSBoundParameters.ContainsKey($name) -and -not [string]$PSBoundParameters[$name]) {
            throw "$name must not be empty."
        }
    }

    if (-not $ServerExe) {
        $ServerExe = Join-Path (Join-Path $BuildDirectory $Configuration) 'winlin-server.exe'
    }
    # Resolve relative overrides against PowerShell's location, including after Set-Location.
    $ServerExe = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ServerExe)
    if (-not (Test-Path -LiteralPath $ServerExe -PathType Leaf)) {
        throw "Server executable not found: $ServerExe. Run scripts\build.ps1 server first."
    }

    $serverArguments = @('--bind', $BindAddress, '--port', "$Port")
    if ($TokenFile) {
        $TokenFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TokenFile)
        if (-not (Test-Path -LiteralPath $TokenFile -PathType Leaf)) {
            throw "Pairing-token file not found: $TokenFile."
        }
        $serverArguments += @('--token-file', $TokenFile)
    }

    # Do not duplicate native default policy here; forward optional settings only when supplied.
    $optionalOptions = [ordered]@{
        Workers = '--workers'
        MaxConnections = '--max-connections'
        Cipher = '--cipher'
        SessionFile = '--session-file'
        StopFile = '--stop-file'
    }
    foreach ($name in $optionalOptions.Keys) {
        if ($PSBoundParameters.ContainsKey($name)) {
            $value = [string]$PSBoundParameters[$name]
            if (-not $value) {
                throw "$name must not be empty."
            }
            $serverArguments += @($optionalOptions[$name], $value)
        }
    }

    # Native stderr is diagnostic output, not proof of process failure. In particular, recoverable
    # HTTP errors must not terminate the launcher under Windows PowerShell or PowerShell 7.
    $PSNativeCommandUseErrorActionPreference = $false
    $ErrorActionPreference = 'Continue'
    $LASTEXITCODE = 0
    & $ServerExe @serverArguments
    $nativeSucceeded = $?
    $status = $LASTEXITCODE
    if (-not $nativeSucceeded -and $status -eq 0) {
        $status = 1
    }
    if ($status -ne 0) {
        [Console]::Error.WriteLine("winlin server launcher: FATAL: server exited with code $status.")
    }
    exit $status
}
catch {
    [Console]::Error.WriteLine("winlin server launcher: FATAL: $($_.Exception.Message)")
    exit 1
}
