Set-StrictMode -Version Latest

# Reject platforms without the native TLS 1.3 and x64 APIs used by the server.
function Assert-WinlinWindows {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'This script requires Windows Server 2022 or Windows 11, x86_64.'
    }
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess -or
        [Environment]::OSVersion.Version.Build -lt 20348) {
        throw 'Windows Server 2022 or Windows 11, x86_64, and 64-bit PowerShell are required.'
    }
}

function Assert-WinlinAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this operation in an elevated PowerShell terminal.'
    }
}

# PowerShell does not turn native exit codes into exceptions, even with ErrorActionPreference=Stop.
function Invoke-WinlinNative {
    param([Parameter(Mandatory)][string]$File, [string[]]$Arguments = @())
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$File failed with exit code $LASTEXITCODE."
    }
}

# Rollback must attempt every resource and retain the original failure; warn and report each failure.
function Invoke-WinlinCleanup {
    param([Parameter(Mandatory)][string]$Description, [Parameter(Mandatory)][scriptblock]$Action)
    try {
        & $Action | Out-Host
        return $true
    }
    catch {
        Write-Warning "Cleanup failed ($Description): $($_.Exception.Message)"
        return $false
    }
}

# Discover installed tools without installing anything; callers report missing optional candidates.
function Get-WinlinVisualStudio {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { return $null }
    $installation = & $vswhere -latest -products '*' -version '[17.6,18.0)' `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0) { throw 'vswhere failed.' }
    if ($installation) { return ([string]$installation).Trim() }
    return $null
}

# Prefer an existing usable CMake, falling back to Visual Studio's bundled installation.
function Get-WinlinCMake {
    param([string]$VisualStudio)
    $command = Get-Command cmake.exe -CommandType Application -ErrorAction SilentlyContinue
    $candidates = @()
    if ($command) { $candidates += $command.Source }
    if ($VisualStudio) {
        $candidates += Join-Path $VisualStudio 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
    }
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        $output = @(& $candidate --version)
        if ($LASTEXITCODE -eq 0 -and $output[0] -match 'cmake version (\d+\.\d+\.\d+)' -and
            [version]$Matches[1] -ge [version]'3.24.0') {
            return $candidate
        }
    }
    return $null
}

# Probe known Python candidates; an absent or unsuitable interpreter is not an installation failure.
function Get-WinlinPython {
    $command = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue
    $candidates = @()
    if ($command) { $candidates += $command.Source }
    $candidates += Join-Path $env:ProgramFiles 'Python312\python.exe'
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        $version = & $candidate -c 'import sys; print(sys.version_info.major)' 2>$null
        if ($LASTEXITCODE -eq 0 -and $version -eq '3') { return $candidate }
    }
    return $null
}

# Both headers and x64 import libraries must exist; a registry entry alone is not a usable SDK.
function Get-WinlinSdk {
    $roots = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' `
        -ErrorAction SilentlyContinue
    if (-not $roots -or -not $roots.PSObject.Properties['KitsRoot10']) { return $null }
    $include = Join-Path $roots.KitsRoot10 'Include'
    if (-not (Test-Path -LiteralPath $include -PathType Container)) { return $null }
    foreach ($version in Get-ChildItem -LiteralPath $include -Directory) {
        $header = Join-Path $version.FullName 'um\http.h'
        $library = Join-Path $roots.KitsRoot10 "Lib\$($version.Name)\um\x64\httpapi.lib"
        if ((Test-Path -LiteralPath $header) -and (Test-Path -LiteralPath $library)) {
            return $roots.KitsRoot10
        }
    }
    return $null
}

# Never repair permissions on an existing shared directory: that could break unrelated workloads.
function Initialize-WinlinPrivateDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'StateDirectory must be a regular directory, not a reparse point.'
        }
        $existing = Get-Acl -LiteralPath $Path
        $raw = [Security.AccessControl.RawSecurityDescriptor]::new($existing.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $raw.DiscretionaryAcl) { throw 'StateDirectory has an unrestricted DACL.' }
        if ($existing.GetOwner([Security.Principal.SecurityIdentifier]) -ne $sid) {
            throw 'StateDirectory must be owned by this user.'
        }
        foreach ($rule in $existing.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and
                $rule.IdentityReference.Value -notin @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')) {
                throw 'StateDirectory must be private. Choose a new directory instead of changing a shared directory.'
            }
        }
        return
    }
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($sid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
                            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
