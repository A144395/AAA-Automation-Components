 [CmdletBinding()] 
 Param 
 ( 
      [Parameter(Mandatory=$true)] 
      [char]$DriveLetter, 
  
      [Parameter(Mandatory=$true)] 
      [int]$Interleave, 
  
      [Parameter(Mandatory=$true)] 
      [string]$Label
 ) 

$ErrorActionPreference = "Stop"

$DataDisks = Get-PhysicalDisk | ? CanPool

If ($DataDisks.Count -eq 0) 
    { 
        Write-Host "[INFO] No disks available for pooling" 
        Write-Host "Exiting..." 
        [Environment]::Exit(0) 
    } 

Try {

        New-StoragePool -FriendlyName Pool1 -PhysicalDisk $Disks
        New-VirtualDisk -FriendlyName $Label -Interleave $Interleave -NumberOfColumns $DataDisks.Count -ResiliencySettingName simple -UseMaximumSize
        Initialize-Disk -PartitionStyle GPT -PassThru 
        New-Partition -DriveLetter $DriveLetter -UseMaximumSize 
        Format-Volume -FileSystem NTFS -NewFileSystemLabel $FileSystemLabel -AllocationUnitSize 65536 -Confirm:$false
    }


Catch 
    { 
      Write-Error "$($_.Exception.Message)" 
      [Environment]::Exit(1) 
    }