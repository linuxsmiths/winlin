[CmdletBinding()]
param(
    [string]$BindAddress = '127.0.0.1',
    [ValidateRange(1, 65535)][int]$Port = 8443,
    [string]$StateDirectory = (Join-Path $PSScriptRoot '..\.winlin-local'),
    [string]$CertificateThumbprint = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')
Assert-WinlinWindows
Assert-WinlinAdministrator
$ip = [Net.IPAddress]::Parse($BindAddress)
if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $BindAddress -eq '0.0.0.0') {
    throw 'Use a specific IPv4 address, not a wildcard, for this HTTP.sys binding.'
}
$BindAddress = $ip.ToString()
if ($BindAddress -eq '0.0.0.0') { throw 'Use a specific IPv4 address, not a wildcard.' }
$state = [IO.Path]::GetFullPath($StateDirectory)
Initialize-WinlinPrivateDirectory -Path $state
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$tokenFile = Join-Path $state 'pairing-token'
if (Test-Path -LiteralPath $tokenFile) {
    throw 'Pairing-token file already exists. Reuse its configured endpoint or choose a fresh StateDirectory.'
}
$endpoint = "${BindAddress}:$Port"
$url = "https://${BindAddress}:$Port/"
$createdCertificate = $false
$createdBinding = $false
$createdUrl = $false
$createdToken = $false
# Track only resources created here, so rollback never removes an existing endpoint or certificate.
try {
    if ($CertificateThumbprint) {
        if ($CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw 'Expected a SHA-1 store thumbprint (40 hex digits).' }
        $certificate = Get-Item -LiteralPath "Cert:\LocalMachine\My\$CertificateThumbprint"
        if (-not $certificate.HasPrivateKey) { throw 'Certificate must have a private key in LocalMachine\My.' }
    }
    else {
        $certificate = New-SelfSignedCertificate -Type SSLServerAuthentication -Subject 'CN=winlin-test' `
            -TextExtension @("2.5.29.17={text}IPAddress=$BindAddress") -CertStoreLocation 'Cert:\LocalMachine\My' `
            -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable `
            -NotAfter (Get-Date).AddDays(30)
        $createdCertificate = $true
    }
    $thumbprint = $certificate.Thumbprint
    Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'add', 'sslcert', "ipport=$endpoint",
        "certhash=$thumbprint", 'certstorename=MY', 'appid={49071664-1d0a-4a82-bbb2-72878abc7ca2}',
        'disablehttp2=enable', 'disablequic=enable', 'disablelegacytls=enable', 'disabletls12=enable') | Out-Host
    $createdBinding = $true
    Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'add', 'urlacl', "url=$url",
        "user=$user", 'listen=yes', 'delegate=no') | Out-Host
    $createdUrl = $true
    $random = [byte[]]::new(32)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $token = ([BitConverter]::ToString($random)).Replace('-', '').ToLowerInvariant()
    $stream = New-WinlinPrivateFileStream -Path $tokenFile
    $createdToken = $true
    try {
        $bytes = [Text.Encoding]::ASCII.GetBytes("$token`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $pin = ([BitConverter]::ToString($sha.ComputeHash($certificate.RawData))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    [pscustomobject]@{
        BindAddress = $BindAddress
        Port = $Port
        Url = $url
        CertificateThumbprint = $thumbprint
        CertificateSha256 = $pin
        CreatedCertificate = $createdCertificate
        TokenFile = $tokenFile
    }
}
catch {
    # Cleanup warnings must not prevent later rollback actions or replace the provisioning error.
    if ($createdToken) {
        $null = Invoke-WinlinCleanup -Description 'pairing token' -Action {
            Remove-Item -LiteralPath $tokenFile
        }
    }
    if ($createdUrl) {
        $null = Invoke-WinlinCleanup -Description 'URL reservation' -Action {
            Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'delete', 'urlacl', "url=$url")
        }
    }
    if ($createdBinding) {
        $null = Invoke-WinlinCleanup -Description 'certificate binding' -Action {
            Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'delete', 'sslcert', "ipport=$endpoint")
        }
    }
    if ($createdCertificate) {
        $null = Invoke-WinlinCleanup -Description 'test certificate' -Action {
            Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($certificate.Thumbprint)"
        }
    }
    throw
}
