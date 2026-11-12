param(
    [Parameter(Mandatory)][string]$ServerExe,
    [Parameter(Mandatory)][string]$PythonExe
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/windows-common.ps1')
Assert-WinlinWindows
Assert-WinlinAdministrator
$directory = Join-Path $PSScriptRoot ('../.winlin-https-test-' + [guid]::NewGuid().ToString('N'))
$configuration = $null
$listeners = @()
try {
    # Reserve three distinct ephemeral ports together, then release them just before provisioning.
    foreach ($index in 1..3) {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $listeners += $listener
    }
    $port, $httpPort, $httpsPort = @($listeners | ForEach-Object { $_.LocalEndpoint.Port })
}
finally {
    foreach ($listener in $listeners) { $listener.Stop() }
}
$primaryFailure = $null
try {
    $configuration = & (Join-Path $PSScriptRoot '../scripts/setup-server.ps1') `
        -Port $port -HttpPort $httpPort -HttpsPort $httpsPort `
        -StateDirectory (Join-Path $directory 'state')
    if ($configuration.Url -ne "http://127.0.0.1:$port/" -or
        $configuration.SslEndpoints.Count -ne 1 -or
        $configuration.SslEndpoints[0] -ne "127.0.0.1:$httpsPort") {
        throw 'Control must use plain HTTP; only the HTTPS workload gets a certificate binding.'
    }
    Invoke-WinlinNative -File $PythonExe -Arguments @(
        (Join-Path $PSScriptRoot 'windows_https.py'),
        $ServerExe, "$port", "$httpPort", "$httpsPort", $configuration.CertificateSha256,
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
        foreach ($url in $configuration.Urls) {
            if (-not (Invoke-WinlinCleanup -Description 'test URL reservation' -Action {
                Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'delete', 'urlacl', "url=$url")
            })) { $cleanupFailed = $true }
        }
        foreach ($endpoint in $configuration.SslEndpoints) {
            if (-not (Invoke-WinlinCleanup -Description 'test TLS binding' -Action {
                Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'delete', 'sslcert', "ipport=$endpoint")
            })) { $cleanupFailed = $true }
        }
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
