#Requires -Version 7.0
<#
.SYNOPSIS
    Starts a vCenter simulator (vcsim, from the govmomi project) for the MIThrandir demo.

.DESCRIPTION
    Requires the vcsim executable (download it from the govmomi releases page on GitHub) and its path as
    -VcsimPath, or on PATH. The simulator listens on 127.0.0.1 with a self-signed certificate.
    The default account of vcsim is user / pass; use -User and -Password to change it.
    Stop it with Ctrl+C or by closing the window.

.EXAMPLE
    .\demo\Start-Vcsim.ps1 -VcsimPath C:\Tools\vcsim.exe
#>
[CmdletBinding()]
param(
    [string]$VcsimPath = 'vcsim',
    [string]$Listen = '127.0.0.1:8989',
    [int]$VmCount = 30,
    [string]$User = 'user',
    [string]$Password = 'pass'
)

$command = Get-Command $VcsimPath -ErrorAction SilentlyContinue
if (-not $command) { throw "vcsim not found ($VcsimPath). Download it from the govmomi releases and pass -VcsimPath." }

Write-Host "vcsim on https://$Listen/sdk, $VmCount VMs, account $User" -ForegroundColor Cyan
& $command.Source -l $Listen -vm $VmCount -username $User -password $Password
