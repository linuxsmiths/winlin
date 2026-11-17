[CmdletBinding()]
param(
    [Parameter(Position = 0)][ValidateSet('client', 'server', 'all')][string]$Component = 'server',
    [ValidateRange(1, 256)][int]$Jobs = 2,
    [string]$BuildDirectory = (Join-Path $PSScriptRoot '..\build'),
    [switch]$IntegrationTests
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')
Assert-WinlinWindows
if ($Component -eq 'client') { throw 'The client builds on Linux only.' }
$visualStudio = Get-WinlinVisualStudio
$cmake = Get-WinlinCMake -VisualStudio $visualStudio
if (-not $visualStudio -or -not $cmake -or -not (Get-WinlinSdk)) { throw 'Run scripts\prep.ps1 first.' }
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$build = [IO.Path]::GetFullPath($BuildDirectory)
# Select one native MSVC instance explicitly; do not inherit an incompatible generator or architecture.
$configure = @('-S', $root, '-B', $build, '-G', 'Visual Studio 17 2022', '-A', 'x64',
    "-DCMAKE_GENERATOR_INSTANCE=$visualStudio", '-DWINLIN_BUILD_CLIENT=OFF',
    '-DWINLIN_BUILD_SERVER=ON', '-DBUILD_TESTING=ON', '-DWINLIN_WINDOWS_HTTPS_TESTS=OFF')
if ($IntegrationTests) {
    $python = Get-WinlinPython
    if (-not $python) { throw 'Run scripts\prep.ps1 -IntegrationTests first.' }
    $configure[-1] = '-DWINLIN_WINDOWS_HTTPS_TESTS=ON'
    $configure += "-DPython3_EXECUTABLE=$python"
}
Invoke-WinlinNative -File $cmake -Arguments $configure
Invoke-WinlinNative -File $cmake -Arguments @('--build', $build, '--config', 'Release', '--parallel', "$Jobs")
Write-Host "Server: $(Join-Path $build 'Release\winlin-server.exe')"
Write-Host "Run tests: ctest --test-dir `"$build`" -C Release --output-on-failure"
