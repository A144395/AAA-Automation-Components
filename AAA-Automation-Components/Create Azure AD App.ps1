## Create Azure AD Application for Automation

Add-Type -Assembly System.Web

$password = [System.Web.Security.Membership]::GeneratePassword(16,3)
$securePassword = ConvertTo-SecureString -Force -AsPlainText -String $password

#New-AzureRmADServicePrincipal -ApplicationId 00c01aaa-1603-49fc-b6df-b78c4e5138b4 -Password $securePassword
#$SecureStringPassword = ConvertTo-SecureString -String "@gl@utomate" -AsPlainText -Force
$azureAdApplication = New-AzureRmADApplication -DisplayName "aaa.automation.app" -HomePage "http://aaaautomationapp" -IdentifierUris "http://aaaautomationapp" -Password $securePassword

## Create Service Principal and link to Cert

$ServicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $azureAdApplication.ApplicationId

#Wait for SP to be created

Start-Sleep -Seconds 10

##Assign Role to Azure AD App

New-AzureRmRoleAssignment -ApplicationId $azureAdApplication.ApplicationId -RoleDefinitionName Contributor 

#Remove-AzureRmADApplication -ApplicationId $azureAdApplication.ApplicationId
