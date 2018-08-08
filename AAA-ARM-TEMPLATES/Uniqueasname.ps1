param(
[string] $service,
[string] $resourcegroup,
[string] $env,
[string] $function,
[string] $tenantid,
[string] $appid,
[string] $apppwd,
[string] $sname
)

$secPassword = ConvertTo-SecureString $apppwd -AsPlainText –Force
$credential = New-Object System.Management.Automation.PSCredential($appid, $secPassword)
Add-AzureRmAccount -Credential $credential -ServicePrincipal -Tenant $tenantid
Select-AzureRmSubscription -SubscriptionName $sname

$asName = '*as-*'
$prefix = "$service-$function-$env-as-"
$seqNo = 00
$lastas = Get-AzureRmAvailabilitySet -ResourceGroupName $resourcegroup | Where-Object Name -Like $asName | Sort-Object Name -Descending | Select-Object -First(1) Name


if($lastas.Name -match "\d"){
    write-host "Seq does not exists!"
    write-host "Last Availability Set: $($lastas.Name)"
    $seqNo = [int]($lastas.Name.Split('-')[3]) 
    }

$newNo = [int]($seqNo)+1
$newNo = $newNo.ToString("00")
$uniqueasname = "$($prefix)$newNo"
Write-Host $uniqueasname
Write-Host "##vso[task.setvariable variable=asnamecrm]$uniqueasname"