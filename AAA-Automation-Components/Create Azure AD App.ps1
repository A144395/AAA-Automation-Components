## Create Azure AD Application for Automation

$SecureStringPassword = ConvertTo-SecureString -String "@gl@utomate" -AsPlainText -Force
$azureAdApplication = New-AzureRmADApplication -DisplayName "aaa.automation.app" -HomePage "http://aaaautomationapp" -IdentifierUris "http://aaaautomationapp" -Password $SecureStringPassword

## Create Service Principal and link to Cert

$ServicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $azureAdApplication.ApplicationId

#Wait for SP to be created

Start-Sleep -Seconds 10

##Assign Role to Azure AD App

New-AzureRmRoleAssignment -ApplicationId $azureAdApplication.ApplicationId -RoleDefinitionName Contributor 

#Remove-AzureRmADApplication -ApplicationId $azureAdApplication.ApplicationId
