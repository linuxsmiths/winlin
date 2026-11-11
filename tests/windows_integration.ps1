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
try {
    $configuration = & (Join-Path $PSScriptRoot '../scripts/setup-server.ps1') `
        -Port $port -StateDirectory (Join-Path $directory 'state')
    Invoke-WinlinNative -File $PythonExe -Arguments @(
        (Join-Path $PSScriptRoot 'windows_https.py'),
        $ServerExe, "$port", $configuration.TokenFile, $configuration.CertificateSha256,
        (Join-Path $directory 'state/stop'))
}
finally {
    if ($configuration) {
        & netsh.exe http delete urlacl "url=$($configuration.Url)" | Out-Null
        & netsh.exe http delete sslcert "ipport=127.0.0.1:$port" | Out-Null
        if ($configuration.CreatedCertificate) {
            Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($configuration.CertificateThumbprint)"
        }
    }
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse }
}
