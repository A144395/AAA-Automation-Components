#Windows Boostrap build script

#Var Declerations
$ServerName=$env:COMPUTERNAME
$ManagementGroupName = 'AGL_OM'
$ManagementServerName = 'GLBWI1086.agl.int'
$workspaceID = "e4accf17-f699-45f7-89dc-a72c8b4073dd"
$workspaceKey = "3wPU+fnhq39SOnFDU6RJKNQesdic/Jivfj7UCP0nG4wIvgWBoFxZ3bMDnzGfOMB/cPDCqGAEYDRfr/nq8RYZEw=="

#Storage Account details
$storName = "dscfilestor01"
$storKey = "rkijoTYCcp/LJsOnbjJp6YKHd//m6K8Dvcc0LeO5zbofBlIAhkOynHao8Yi07u2sMDsfIlph9+4fdzRDqkvLAg=="

#Mount Azure file Share to Z Drive
$acctKey = ConvertTo-SecureString -String $storKey -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential -ArgumentList "Azure\$storName", $acctKey
New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$storName.file.core.windows.net\agents" -Credential $credential -Persist

#Create Log Folder
#New-Item -ItemType Directory -Name Logs -Path C:\

#Copy Azure FileStore to Local Packages Dir
Copy-Item -Path "z:\WindowsServer" -Destination "C:\Packages\" -Recurse

#wait for file Copy
Start-Sleep -Seconds 30

#Install CrowdStrike
$crowdstrikeArgs = 'CID=06B2DE7AA17147DF90C15FFB6D7098BC-DC AcceptEula={YES} /quiet REBOOT=ReallySupress /norestart /log c:\logs\CrowdStrike.txt'
$CrowdStrikeResult = Start-Process -Wait -PassThru "C:\Packages\WindowsServer\Falcon\FalconSensor.exe" -ArgumentList $crowdstrikeArgs

#Install Flexera
$flexeraArgs = 'TRANSFORMS="C:\Packages\WindowsServer\Flexera\agent.Mst" /qn REBOOT=ReallySupress /log c:\logs\flexera.txt'
$FlexeraResult = Start-Process -Wait -PassThru "C:\Packages\WindowsServer\Flexera\latest_FlexeraAgent.msi" -ArgumentList $flexeraArgs

#Install Qualys
$qualysArgs = 'CustomerId={7c453108-5673-e68e-8194-67bf9830cdde} ActivationId={0fd568ab-4302-48c7-8c45-b8d467929338}'
$QualysResult = Start-Process -Wait -PassThru "C:\Packages\WindowsServer\Qualys\QualysCloudAgent.exe" -ArgumentList $qualysArgs

#Join Domain
# Start logging results
# Start-Transcript "C:\Logs\DomainJoin.txt" -NoClobber -Append
# Add-Computer -DomainName agl.int -OUPath "OU=Servers,OU=Resources,DC=agl,DC=int" -Credential $domainJoinCred
# Stop logging results
# Stop-Transcript 

#Add Groups
#$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
#Set-ItemProperty -Path $RunOnceKey -Name "!DomainGroupAdd" -Value ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + "C:\Packages\WindowsServer\DomainGroupsAdd.ps1")

#SAP APP Server Specific Changes
#Remove SMB1.0
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol

#OMS install failing with 1618 which is another install in progress
Start-Sleep -Seconds 30
#Install OMS
# Get installer file
$File = Get-ChildItem 'C:\Packages\WindowsServer\MMA\MOMAgent.msi'
# Get date and time for unique install log file name
$DataStamp = get-date -Format yyyyMMddTHHmmss
# Create install log file path and name
$logFile = '{0}{1}-{2}.log' -f 'C:\Logs\',$File.Name,$DataStamp
# Create command line arguments
$MSIArguments = @(
    "/i"
    ('"{0}"' -f $file.fullname)
    "/qn"
    "/norestart"
    "/L*v"
    $logFile
    "ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_ID=$workspaceID OPINSIGHTS_WORKSPACE_KEY=$workspaceKey AcceptEndUserLicenseAgreement=1 MANAGEMENT_GROUP=AGL_OM MANAGEMENT_SERVER_DNS=GLBWI1086.agl.int MANAGEMENT_SERVER_AD_NAME=GLBWI1086.agl.int ACTIONS_USE_COMPUTER_ACCOUNT=1 USE_MANUALLY_SPECIFIED_SETTINGS=1"
)
# Do install and wait for it to complete before proceeding
$OMSResult= $null
Do{
    $OMSResult = Start-Process -Wait -PassThru "msiexec.exe" -ArgumentList $MSIArguments 
}While($OMSResult.ExitCode -eq 1618)
# Outputting all install results
Set-Content -Path 'C:\Logs\InstallResults.log' -Value ('Crowdstrike install finished with a result of '+$CrowdStrikeResult.ExitCode) -Force
Add-Content -Path 'C:\Logs\InstallResults.log' -Value ('Flexera install finished with a result of '+$FlexeraResult.ExitCode)
Add-Content -Path 'C:\Logs\InstallResults.log' -Value ('Qualys install finished with a result of '+$QualysResult.ExitCode)
Add-Content -Path 'C:\Logs\InstallResults.log' -Value ('OMS install finished with a result of '+$OMSResult.ExitCode)
# Confirming OMS configuration
# Start logging results
Start-Transcript "C:\Logs\MMA-Agent_Config.txt" -NoClobber -Append
# Create new object that is for configuring agent
$NewObject = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
# Get SCOM management groups into array
[array]$ManagementGroups=$NewObject.GetManagementGroups() | Select-Object managementGroupName | % {$_.managementgroupname}
# Check if SCOM management group exists
if ($ManagementGroups -contains $ManagementGroupName){
    # Output management group already exists
    $ServerName + ' SCOM agent is already member of ' + $ManagementGroupName
}else{
    # Add SCOM settings
    $NewObject.AddManagementGroup($ManagementGroupName, $ManagementServerName,5723)
    $NewObject.EnableActiveDirectoryIntegration()
    # Output agent has been added
    'Adding ' + $ServerName + ' to ' + $ManagementGroupName + ' Management Group'
    # Restart service to apply new settings
    Restart-Service HealthService
}
# Get OMS workspaces into array
[array]$WorkSpaces=$NewObject.GetCloudWorkspaces() | Select-Object workspaceId | % {$_.workspaceId}
# Check if OMS workspace exists
if ($WorkSpaces -contains $WorkSpaceID){
    # Output workspace already exists
    $ServerName + ' MMA agent already has a workspace with ID ' + $WorkSpaceID
}else{å
    # Add OMS settings
    $NewObject.AddCloudWorkspace($WorkSpaceID, $workspaceKey)
    # Output workspace has been added
    'Adding ' + $ServerName + ' to ' + $WorkSpaceID + ' Workspace'
    # Restart service to apply new settings
    Restart-Service HealthService
}

# Stop logging
Stop-Transcript

#Remove IE
dism /online /Disable-Feature /NoRestart /FeatureName:Internet-Explorer-Optional-amd64

# Add users to local admin group
Add-LocalGroupMember -Group Administrators -Member agl\PT3_SAP_BASIS

### Stops the Hardware Detection Service ###
Stop-Service -Name ShellHWDetection

### Grabs all the new RAW disks into a variable ###
$disk = get-disk | where partitionstyle -eq ‘raw’

### Starts a foreach loop that will add the drive
### and format the drive for each RAW drive 
### the OS detects ###
foreach ($d in $disk){
$diskNumber = $d.Number
$dl = get-Disk $d.Number | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize
Format-Volume -driveletter $dl.Driveletter -FileSystem NTFS -Confirm:$false
### 2 Second pause between each disk ###
### Initialization, Partitioning, and formatting ###
Start-Sleep 2
}
### Starts the Hardware Detection Service again ###
Start-Service -Name ShellHWDetection

function Resolve-SamAccount {
<#
.SYNOPSIS
    Helper function that resolves SAMAccount
#>
    param(
        [string]
            $SamAccount
    )
    
    process {
        try
        {
            $ADResolve = ([adsisearcher]"(samaccountname=$Trustee)").findone().properties['samaccountname']
        }
        catch
        {
            $ADResolve = $null
        }

        if (!$ADResolve) {
            Write-Warning "User `'$SamAccount`' not found in AD, please input correct SAM Account"
        }
        $ADResolve
    }
}

function Add-ADAccounttoRDPUser {
<#
.SYNOPSIS   
Script to add an AD User or group to the Remote Desktop Users group
    
.DESCRIPTION 
The script can use either a plaintext file or a computer name as input and will add the trustee (user or group) to the Remote Desktop Users group on the computer
	
.PARAMETER InputFile
A path that contains a plaintext file with computer names

.PARAMETER Computer
This parameter can be used instead of the InputFile parameter to specify a single computer or a series of computers using a comma-separated format
	
.PARAMETER Trustee
The SamAccount name of an AD User or AD Group that is to be added to the Remote Desktop Users group

.NOTES   
Name       : Add-ADAccounttoRDPUser.ps1
Author     : Jaap Brasser
Version    : 1.0.0
DateCreated: 2016-07-28
DateUpdated: 2016-07-28

.LINK
http://www.jaapbrasser.com

.EXAMPLE
. .\Add-ADAccounttoRDPUser.ps1

Description
-----------
This command dot sources the script to ensure the Add-ADAccounttoRDPUser function is available in your current PowerShell session

.EXAMPLE   
Add-ADAccounttoRDPUser -Computer Server01 -Trustee JaapBrasser

Description:
Will add the the JaapBrasser account to the Remote Desktop Users group on Server01

.EXAMPLE   
Add-ADAccounttoRDPUser -Computer 'Server01','Server02' -Trustee Contoso\HRManagers

Description:
Will add the HRManagers group in the contoso domain as a member of Remote Desktop Users group on Server01 and Server02

.EXAMPLE   
Add-ADAccounttoRDPUser -InputFile C:\ListofComputers.txt -Trustee User01

Description:
Will add the User01 account to the Remote Desktop Users group on all servers and computernames listed in the ListofComputers file
#>
    param(
        [Parameter(ParameterSetName= 'InputFile',
                   Mandatory       = $true
        )]
        [string]
            $InputFile,
        [Parameter(ParameterSetName= 'Computer',
                   Mandatory       = $true
        )]
        [string[]]
            $Computer,
        [Parameter(Mandatory=$true)]
        [string]
            $Trustee
    )


    if ($Trustee -notmatch '\\') {
        $ADResolved = (Resolve-SamAccount -SamAccount $Trustee)
        $Trustee = 'WinNT://',"$env:userdomain",'/',$ADResolved -join ''
    } else {
        $ADResolved = ($Trustee -split '\\')[1]
        $DomainResolved = ($Trustee -split '\\')[0]
        $Trustee = 'WinNT://',$DomainResolved,'/',$ADResolved -join ''
    }

    if (!$InputFile) {
	    $Computer | ForEach-Object {
		    Write-Verbose "Adding '$ADResolved' to Remote Desktop Users group on '$_'"
		    try {
			    ([adsi]"WinNT://$_/Remote Desktop Users,group").add($Trustee)
			    Write-Verbose "Successfully completed command for '$ADResolved' on '$_'"
		    } catch {
			    Write-Warning $_
		    }	
	    }
    } else {
	    if (!(Test-Path -Path $InputFile)) {
		    Write-Warning 'Input file not found, please enter correct path'
	    }
	    Get-Content -Path $InputFile | ForEach-Object {
		    Write-Verbose "Adding '$ADResolved' to Remote Desktop Users group on '$_'"
		    try {
			    ([adsi]"WinNT://$_/Remote Desktop Users,group").add($Trustee)
			    Write-Verbose 'Successfully completed command'
		    } catch {
			    Write-Warning $_
		    }        
	    }
    }
}

Add-ADAccounttoRDPUser -Computer $ServerName -Trustee AGL\PT3_SAP_BASIS
Add-ADAccounttoRDPUser -Computer $ServerName -Trustee AGL\LocalAdmin-AzureNonProdServers