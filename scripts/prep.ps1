[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$IntegrationTests
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')
Assert-WinlinWindows

$visualStudio = Get-WinlinVisualStudio
$cmake = Get-WinlinCMake -VisualStudio $visualStudio
$sdk = Get-WinlinSdk
$python = $null
if ($IntegrationTests) { $python = Get-WinlinPython }
if ($Check) {
    if (-not $visualStudio -or -not $cmake -or -not $sdk -or ($IntegrationTests -and -not $python)) {
        throw 'Missing VS 2022 (17.6+) C++ tools/CMake, or Python for integration tests. Run prep.ps1 without -Check.'
    }
    Write-Host "Ready: VS $visualStudio; CMake $cmake"
    return
}

# Verify the publisher before executing an elevated installer and always remove the downloaded file.
function Install-WinlinTool {
    param([string]$Uri, [string[]]$Arguments, [string]$Publisher)
    Assert-WinlinAdministrator
    $installer = Join-Path ([IO.Path]::GetTempPath()) ("winlin-" + [guid]::NewGuid().ToString('N') + '.exe')
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $installer
        $signature = Get-AuthenticodeSignature -LiteralPath $installer
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch $Publisher) {
            throw 'Installer signature/publisher verification failed.'
        }
        $process = Start-Process -FilePath $installer -ArgumentList $Arguments -Wait -PassThru
        if ($process.ExitCode -eq 3010) {
            throw 'Installation requires a reboot. Reboot and rerun prep.ps1.'
        }
        if ($process.ExitCode -ne 0) { throw "Installer failed with exit code $($process.ExitCode)." }
    }
    finally {
        if (Test-Path -LiteralPath $installer) { Remove-Item -LiteralPath $installer }
    }
}

if (-not $visualStudio -or -not $cmake -or -not $sdk) {
    Install-WinlinTool -Uri 'https://aka.ms/vs/17/release/vs_buildtools.exe' -Publisher 'Microsoft Corporation' `
        -Arguments @('--quiet', '--wait', '--norestart', '--nocache',
            '--add', 'Microsoft.VisualStudio.Workload.VCTools', '--includeRecommended',
            '--add', 'Microsoft.VisualStudio.Component.VC.CMake.Project')
    $visualStudio = Get-WinlinVisualStudio
    $cmake = Get-WinlinCMake -VisualStudio $visualStudio
    $sdk = Get-WinlinSdk
}
if ($IntegrationTests -and -not $python) {
    Install-WinlinTool -Uri 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe' `
        -Publisher 'Python Software Foundation' `
        -Arguments @('/quiet', 'InstallAllUsers=1', 'PrependPath=0', 'Include_launcher=1',
            'InstallLauncherAllUsers=1', 'Include_test=0')
    $python = Get-WinlinPython
}
if (-not $visualStudio -or -not $cmake -or -not $sdk -or ($IntegrationTests -and -not $python)) {
    throw 'Required tools are still unavailable. Check the Visual Studio Installer and rerun prep.ps1 -Check.'
}
Write-Host "Ready: VS $visualStudio; CMake $cmake"
Write-Host 'No Schannel policies, firewall rules, URL ACLs, or certificate bindings were changed.'
Write-Host 'Build with .\scripts\build.ps1 server; configure HTTPS with .\scripts\setup-server.ps1.'
