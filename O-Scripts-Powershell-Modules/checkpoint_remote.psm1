$global:servername = "remote_server.acme.com"
$global:targetDirectory = "D:\Powershell\Checkpoint\AddHosts" # root folder of the remote scripts on the above server

# Helper function to read credentials from the local Windows Credential Manager
function Get-StoredCredential {
    param (
        [string]$TargetName
    )
    $cSharpSource = @"
    using System;
    using System.Runtime.InteropServices;
    using System.Management.Automation;

    public static class CredentialHelper {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(string target, int type, int flags, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern void CredFree(IntPtr buffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL {
            public int Flags; public int Type; public string TargetName; public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
            public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
        }

        public static PSCredential GetCredential(string target) {
            IntPtr credPtr;
            if (!CredRead(target, 1, 0, out credPtr)) { return null; }
            try {
                var cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
                var password = Marshal.PtrToStringUni(cred.CredentialBlob, cred.CredentialBlobSize / 2);
                return new PSCredential(cred.UserName, (new System.Net.NetworkCredential(string.Empty, password)).SecurePassword);
            }
            finally { CredFree(credPtr); }
        }
    }
"@
    if (-not ([System.Management.Automation.PSTypeName]'CredentialHelper').Type) {
        try { Add-Type -TypeDefinition $cSharpSource -Language CSharp } catch { return $null }
    }
    try { return [CredentialHelper]::GetCredential($TargetName) } catch { return $null }
}


function Add-RemoteDrive {
    param (
        [string]$servername,
        [string]$driveletter,
        [pscredential]$cred
    )    

    New-PSDrive `
    -Persist `
    -Name $driveletter `
    -PSProvider "FileSystem" `
    -Root "\\$($servername)\D$\Powershell\Checkpoint\AddHosts" `
    -Credential $cred `
    -Scope Global
    
}

function Open-RemoteFolder {
    param (
        [string]$folder,
        [string]$drive
    )   

    Invoke-Item "$($drive):\$($folder)"
}

function Add-CPHosts {
    param (        
        [string]$changeRequest,        
        [string]$fwmgrName,
        [string]$mode,
        [pscredential]$cred
    )        

    Invoke-Command -ComputerName $servername -Credential $cred -ScriptBlock {
        param ($targetDirectory, $changeRequest, $fwmgrName, $mode)    

        Set-Location -Path $targetDirectory         
        .\addhosts_v4.ps1 $fwmgrName ".\csv\$($ChangeRequest).csv" $mode
    } -ArgumentList $targetDirectory, $changeRequest, $fwmgrName, $mode

}

function Push-CPPolicy {
    param (        
        [string]$fwmgrName,        
        [string]$policyName,
        [pscredential]$cred
    )        
    
    Invoke-Command -ComputerName $servername -Credential $cred -ScriptBlock {
        param ($targetDirectory, $fwmgrName, $policyName)    
        
        Set-Location -Path $targetDirectory
        .\installpolicy.ps1 $fwmgrName $policyName 
    } -ArgumentList $targetDirectory, $fwmgrName, $policyName
}

function Get-CPWhereUsed_v2 {
    param (
        [string]$fwmgrName,
        [string]$ipToQuery,
        [pscredential]$cred
    )

    $credentialTarget = "fwmgr"
    Write-Host "Attempting to read local credential for '$credentialTarget'..." -ForegroundColor Gray
    $apiCredential = Get-StoredCredential -TargetName $credentialTarget
    if ($apiCredential) {
        Write-Host "Local credential found. Proceeding with remote execution." -ForegroundColor Green
    } else {
        Write-Error "Failed to execute: Could not find local credential '$credentialTarget' in your Windows Credential Manager."
        return
    }

    Invoke-Command -ComputerName $servername -Credential $cred -ScriptBlock {
        param ([string]$targetDirectory, [string]$fwmgrName, [string]$ipToQuery, [pscredential]$apiCredential)

        Set-Location -Path $targetDirectory
        # Call the remote script with named parameters, passing the credential object if it was retrieved
        .\whereused_v2.ps1 -MgmtServer $fwmgrName -IpAddress $ipToQuery -ApiCredential $apiCredential
    } -ArgumentList $targetDirectory, $fwmgrName, $ipToQuery, $apiCredential
}

function Add-CPHosts_v7 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FwmgrName,

        [Parameter(Mandatory=$true)]
        [pscredential]$Credential,

        [Parameter(Mandatory=$true)]
        [Alias('ch')]
        [string]$ChangeRequest,

        [Parameter(Mandatory=$true)]
        [Alias('m')]
        [ValidateSet('test', 'full')]
        [string]$Mode
    )
    
    $apiCredential = $null
    $credToUse = $Credential # Default to the provided admin credential

    if ($Mode -eq 'test') {
        $credentialTarget = "fwmgr"
        Write-Host "Test mode detected. Attempting to read local credential for '$credentialTarget'..." -ForegroundColor Gray
        $apiCredential = Get-StoredCredential -TargetName $credentialTarget
        if ($apiCredential) {
            Write-Host "Local credential found. Proceeding with remote execution using read-only account." -ForegroundColor Green
        } else {
            Write-Error "Test mode failed: Could not find local credential '$credentialTarget' in your Windows Credential Manager."
            return
        }
    }

    # command call on the remote server
    Invoke-Command -ComputerName $servername -Credential $credToUse -ScriptBlock {
        # Parameters passed to the script block
        param ([string]$targetDirectory, [string]$changeRequest, [string]$fwmgrName, [string]$mode, [pscredential]$apiCredential)
        
        # Location setting, as before
        Set-Location -Path $targetDirectory
        
        # We call the new script with named parameters
        .\addhosts_v7.ps1 -MgmtServer $fwmgrName -CsvPath ".\csv\$($ChangeRequest).csv" -RunMode $mode -ApiCredential $apiCredential

    } -ArgumentList $targetDirectory, $ChangeRequest, $FwmgrName, $Mode, $apiCredential
}