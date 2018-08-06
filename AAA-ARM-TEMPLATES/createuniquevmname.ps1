﻿param(
[string] $tenantid,
[string] $appid,
[string] $apppwd
)


$secPassword = ConvertTo-SecureString $apppwd -AsPlainText –Force
$credential = New-Object System.Management.Automation.PSCredential($appid, $secPassword)
Add-AzureRmAccount -Credential $credential -ServicePrincipal -Tenant $tenantid
Select-AzureRmSubscription -SubscriptionName $subname


$rgName = '*azsaw*'
$prefix = 'azsaw'
$seqNo = 000
$lastVm = Get-AzureRmVM | Where-Object Name -Like $rgName | Sort-Object Name -Descending | Select-Object -First(1) Name

if($lastVm.Name -match "\d"){
    write-host "Seq does not exists!"
    write-host "Last VM: $($lastVm.Name)"
    $seqNo = ($lastVm.Name.Split('azsaw')) | Out-String 
    }

$newNo = [int]($seqNo)+1
$newNo = $newNo.ToString("0000")
$uniqueMcName = "$($prefix)$newNo"

Write-Host New VM Name $uniqueMcName
Write-Host "##vso[task.setvariable variable=vmname]$uniqueMcName"

Write-Host VM Name variable set to $(vmname)