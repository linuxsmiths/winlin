param(
    [Parameter(Mandatory)][string]$ServerExe,
    [Parameter(Mandatory)][string]$PythonExe
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/windows-common.ps1')
Assert-WinlinWindows
Assert-WinlinAdministrator
$directory = Join-Path ([IO.Path]::GetTempPath()) ('winlin-https-test-' + [guid]::NewGuid().ToString('N'))
$configuration = $null
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$listener.Stop()
$primaryFailure = $null
try {
    $configuration = & (Join-Path $PSScriptRoot '../scripts/setup-server.ps1') `
        -Port $port -StateDirectory (Join-Path $directory 'state') -RequireAuthentication
    Invoke-WinlinNative -File $PythonExe -Arguments @(
        (Join-Path $PSScriptRoot 'windows_https.py'),
        $ServerExe, "$port", $configuration.TokenFile, $configuration.CertificateSha256,
        (Join-Path $directory 'state/stop'))
}
catch {
    $primaryFailure = $_
    throw
}
finally {
    # Attempt every cleanup independently, and fail a successful test if resources could not be removed.
    $cleanupFailed = $false
    if ($configuration) {
        if (-not (Invoke-WinlinCleanup -Description 'test URL reservation' -Action {
            Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'delete', 'urlacl', "url=$($configuration.Url)")
        })) { $cleanupFailed = $true }
        if (-not (Invoke-WinlinCleanup -Description 'test TLS binding' -Action {
            Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'delete', 'sslcert', "ipport=127.0.0.1:$port")
        })) { $cleanupFailed = $true }
        if ($configuration.CreatedCertificate) {
            if (-not (Invoke-WinlinCleanup -Description 'test certificate' -Action {
                Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($configuration.CertificateThumbprint)"
            })) { $cleanupFailed = $true }
        }
    }
    if (Test-Path -LiteralPath $directory) {
        if (-not (Invoke-WinlinCleanup -Description 'test directory' -Action {
            Remove-Item -LiteralPath $directory -Recurse
        })) { $cleanupFailed = $true }
    }
    if ($cleanupFailed -and $null -eq $primaryFailure) {
        throw 'Windows HTTPS tests left resources behind; see cleanup warnings.'
    }
}
