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
# The Windows import container must carry the same public identity pinned by the Linux client.
$publicCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
    (Join-Path $root 'certs/benchmark/server.der'))
$bundle = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
    (Join-Path $root 'certs/benchmark/server.pfx'), 'winlin-public-benchmark',
    [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
try {
    if (-not $bundle.HasPrivateKey -or $bundle.Thumbprint -ne $publicCertificate.Thumbprint) {
        throw 'Public benchmark PFX does not contain the matching certificate/key.'
    }
}
finally {
    $bundle.Dispose()
    $publicCertificate.Dispose()
}

$launcherHelp = & (Join-Path $root 'scripts/run-server.ps1') -Help
if (($launcherHelp -join "`n") -notmatch 'Usage:.*run-server.ps1') {
    throw 'Windows launcher help is unavailable.'
}
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

# Exercise launcher plumbing on either host without claiming to emulate HTTP.sys or Windows ACLs.
$fixture = Join-Path $root ('.winlin-launcher-test-' + [Guid]::NewGuid().ToString())
$fixtureLauncher = Join-Path $fixture 'run-server.ps1'

# Isolate each launcher invocation because its explicit exit must not terminate this test host.
function Invoke-LauncherFixture {
    param([string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    $output = @(& $engine -NoProfile -ExecutionPolicy Bypass -File $fixtureLauncher @Arguments 2>&1)
    $status = $LASTEXITCODE
    return [PSCustomObject]@{
        ExitCode = $status
        Output = @($output | ForEach-Object { [string]$_ })
    }
}

try {
    New-Item -ItemType Directory -Path $fixture | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'scripts/run-server.ps1') -Destination $fixtureLauncher
    # Replace only the OS guard in this copied fixture; the real helper remains independently tested.
    Set-Content -LiteralPath (Join-Path $fixture 'windows-common.ps1') -Value @'
# Permit portable argument/exit tests; no native Windows resources are accessed.
function Assert-WinlinWindows {}
'@
    $fakeServer = Join-Path $fixture 'fake server.ps1'
    Set-Content -LiteralPath $fakeServer -Value @'
[Console]::Out.WriteLine((ConvertTo-Json -InputObject @($args) -Compress))
[Console]::Error.WriteLine('fixture diagnostic')
if ($args -contains 'FAIL_TEST') { exit 23 }
exit 0
'@
    $state = Join-Path $fixture 'private state'
    New-Item -ItemType Directory -Path $state | Out-Null
    $token = Join-Path $state 'pairing-token'
    Set-Content -LiteralPath $token -Value 'fixture, not a credential'

    $result = Invoke-LauncherFixture -Arguments @(
        '-ServerExe', $fakeServer, '-StateDirectory', $state, '-BindAddress', '10.0.0.4',
        '-Port', '9443', '-HttpPort', '9444', '-HttpsPort', '9445', '-Workers', '3', '-MaxConnections', '64',
        '-Cipher', 'TLS_AES_256_GCM_SHA384', '-SessionFile', 'session with spaces',
        '-StopFile', 'stop with spaces'
    )
    if ($result.ExitCode -ne 0) { throw "Launcher fixture failed: $($result.Output)" }
    $arguments = ($result.Output | Where-Object { $_.StartsWith('[') }) | ConvertFrom-Json
    $expected = @(
        '--bind', '10.0.0.4', '--port', '9443', '--http-port', '9444', '--https-port', '9445', '--workers', '3',
        '--max-connections', '64', '--cipher', 'TLS_AES_256_GCM_SHA384',
        '--session-file', 'session with spaces', '--stop-file', 'stop with spaces'
    )
    if (Compare-Object -ReferenceObject $expected -DifferenceObject $arguments -SyncWindow 0) {
        throw "Launcher altered argument boundaries or defaults: $arguments"
    }
    if (($result.Output -join "`n") -notmatch 'fixture diagnostic') {
        throw 'Launcher lost application stderr.'
    }
    $result = Invoke-LauncherFixture -Arguments @(
        '-ServerExe', $fakeServer, '-StateDirectory', (Join-Path $fixture 'no state')
    )
    if ($result.ExitCode -ne 0 -or ($result.Output -join "`n") -match '--token-file') {
        throw "Default launch must need no credential files: $($result.Output)"
    }
    $arguments = ($result.Output | Where-Object { $_.StartsWith('[') }) | ConvertFrom-Json
    $expected = @('--bind', '127.0.0.1', '--port', '38443',
        '--http-port', '38444', '--https-port', '38445')
    if (Compare-Object -ReferenceObject $expected -DifferenceObject $arguments -SyncWindow 0) {
        throw "Default launcher endpoint or authentication changed unexpectedly: $arguments"
    }

    $result = Invoke-LauncherFixture -Arguments @(
        '-ServerExe', $fakeServer, '-TokenFile', $token, '-Cipher', 'FAIL_TEST'
    )
    if ($result.ExitCode -ne 23 -or ($result.Output -join "`n") -notmatch 'FATAL:') {
        throw "Launcher lost application failure: $($result.Output)"
    }
    foreach ($arguments in @(
        @('-BuildDirectory', (Join-Path $fixture 'missing build')),
        @('-ServerExe', $fakeServer, '-TokenFile', (Join-Path $state 'missing token'))
    )) {
        $result = Invoke-LauncherFixture -Arguments $arguments
        if ($result.ExitCode -ne 1 -or ($result.Output -join "`n") -notmatch 'FATAL:') {
            throw "Launcher ignored missing build/state: $($result.Output)"
        }
    }
}
finally {
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
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
