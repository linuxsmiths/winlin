[CmdletBinding()]
param(
    [string]$BindAddress = '127.0.0.1',
    [ValidateRange(1, 65535)][int]$Port = 38443,
    [ValidateRange(1, 65535)][int]$HttpPort = 38444,
    [ValidateRange(1, 65535)][int]$HttpsPort = 38445,
    [string]$StateDirectory = (Join-Path $PSScriptRoot '..\.winlin-local'),
    [string]$CertificateThumbprint = '',
    [switch]$RequireAuthentication
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
if ($Port -eq $HttpPort -or $Port -eq $HttpsPort -or $HttpPort -eq $HttpsPort) {
    throw 'Control, HTTP and HTTPS workload ports must be distinct.'
}
$state = [IO.Path]::GetFullPath($StateDirectory)
Initialize-WinlinPrivateDirectory -Path $state
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$tokenFile = if ($RequireAuthentication) { Join-Path $state 'pairing-token' } else { $null }
if ($RequireAuthentication -and (Test-Path -LiteralPath $tokenFile)) {
    throw 'Pairing-token file already exists. Reuse its configured endpoint or choose a fresh StateDirectory.'
}
$endpoint = "${BindAddress}:$Port"
$url = "https://${BindAddress}:$Port/"
$createdCertificate = $false
$httpUrl = "http://${BindAddress}:$HttpPort/"
$httpsUrl = "https://${BindAddress}:$HttpsPort/"
$createdBindings = @()
$createdUrls = @()
$createdToken = $false
# Track only resources created here, so rollback never removes an existing endpoint or certificate.
try {
    if ($CertificateThumbprint) {
        if ($CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw 'Expected a SHA-1 store thumbprint (40 hex digits).' }
        $certificate = Get-Item -LiteralPath "Cert:\LocalMachine\My\$CertificateThumbprint"
        if (-not $certificate.HasPrivateKey) { throw 'Certificate must have a private key in LocalMachine\My.' }
    }
    else {
        # Reuse the repository's deliberately public identity, never a real credential. Loading the
        # public DER first avoids importing/replacing a certificate already used by another binding.
        $fixtures = Join-Path $PSScriptRoot '../certs/benchmark'
        $publicCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            [IO.Path]::GetFullPath((Join-Path $fixtures 'server.der')))
        try { $fixtureThumbprint = $publicCertificate.Thumbprint }
        finally { $publicCertificate.Dispose() }
        $storePath = "Cert:\LocalMachine\My\$fixtureThumbprint"
        if (Test-Path -LiteralPath $storePath) {
            $certificate = Get-Item -LiteralPath $storePath
            if (-not $certificate.HasPrivateKey) {
                throw 'The benchmark certificate already exists without its private key; resolve the store entry before retrying.'
            }
        }
        else {
            $password = ConvertTo-SecureString 'winlin-public-benchmark' -AsPlainText -Force
            $certificate = Import-PfxCertificate -FilePath (Join-Path $fixtures 'server.pfx') `
                -CertStoreLocation 'Cert:\LocalMachine\My' -Password $password
            $createdCertificate = $true
        }
        Write-Warning 'Using the PUBLIC benchmark certificate/key; this provides no trustworthy server identity.'
    }
    $thumbprint = $certificate.Thumbprint
    foreach ($bindingEndpoint in @($endpoint, "${BindAddress}:$HttpsPort")) {
        # Add, never update: a conflict must fail without overwriting an existing endpoint.
        Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'add', 'sslcert', "ipport=$bindingEndpoint",
            "certhash=$thumbprint", 'certstorename=MY', 'appid={49071664-1d0a-4a82-bbb2-72878abc7ca2}',
            'disablehttp2=enable', 'disablequic=enable', 'disablelegacytls=enable', 'disabletls12=enable') | Out-Host
        $createdBindings += $bindingEndpoint
    }
    foreach ($reservation in @($url, $httpUrl, $httpsUrl)) {
        Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'add', 'urlacl', "url=$reservation",
            "user=$user", 'listen=yes', 'delegate=no') | Out-Host
        $createdUrls += $reservation
    }
    if ($RequireAuthentication) {
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
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $pin = ([BitConverter]::ToString($sha.ComputeHash($certificate.RawData))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    [pscustomobject]@{
        BindAddress = $BindAddress
        Port = $Port
        HttpPort = $HttpPort
        HttpsPort = $HttpsPort
        Url = $url
        HttpUrl = $httpUrl
        HttpsUrl = $httpsUrl
        Urls = $createdUrls
        SslEndpoints = $createdBindings
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
    foreach ($reservation in $createdUrls) {
        $null = Invoke-WinlinCleanup -Description 'URL reservation' -Action {
            Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'delete', 'urlacl', "url=$reservation")
        }
    }
    foreach ($bindingEndpoint in $createdBindings) {
        $null = Invoke-WinlinCleanup -Description 'certificate binding' -Action {
            Invoke-WinlinNative -File netsh.exe -Arguments @('http', 'delete', 'sslcert', "ipport=$bindingEndpoint")
        }
    }
    if ($createdCertificate) {
        $null = Invoke-WinlinCleanup -Description 'test certificate' -Action {
            Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($certificate.Thumbprint)"
        }
    }
    throw
}
