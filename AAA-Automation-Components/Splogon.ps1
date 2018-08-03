$secPassword = ConvertTo-SecureString “@gl@utomate” -AsPlainText –Force
$clientid = "426c1c46-45df-4c9f-ac98-9786cd8f7531"
$tenantid = "123913b9-915d-4d67-aaf9-ce327e8fc59f"

$credential = New-Object System.Management.Automation.PSCredential($clientid, $secPassword)


Add-AzureRmAccount -Credential $credential -ServicePrincipal -Tenant $tenantid
