﻿## Create Azure AD Application for Automation

$SecureStringPassword = ConvertTo-SecureString -String "@gl@utomate" -AsPlainText -Force
$azureAdApplication = New-AzureRmADApplication -DisplayName "aaa.automation.app" -HomePage "http://aaaautomationapp" -IdentifierUris "http://aaaautomationapp" -Password $SecureStringPassword

##Assign Role to Azure AD App

## Create Service Principal and link to Cert

$ServicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $azureAdApplication.ApplicationId
New-AzureRmRoleAssignment -ApplicationId $azureAdApplication.ApplicationId -RoleDefinitionName Contributor 


#Remove-AzureRmADApplication -ApplicationId 0a27f4f2-258e-4d24-8d35-a1422e3fcfba
