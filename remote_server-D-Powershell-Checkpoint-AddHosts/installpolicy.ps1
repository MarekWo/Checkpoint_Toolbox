Import-Module -Name 'D:\Powershell\Checkpoint\AddHosts\Modules\Get-Sessionid.psm1'

# Define variables
$global:logFile = "D:\Powershell\Checkpoint\AddHosts\log\installpolicy.log"

function Write-AppLog {
    param (
        [string]$level,
        [string]$message        
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$level] $message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Output $logMessage
}
 
try {
    # Write-AppLog -level "INFO" -message "Script started."
    Write-Host "Installing started policy started." 
    # Write-Host "Started" -ForegroundColor Cyan # for quick debugging 

    # Check if arguments were provided
    if ($args.Count -ne 2) {
        Write-AppLog -level "ERROR" -message "Incorrect number of arguments"
        Write-Output "Usage: .\installpolicy.ps1 <mgmt_server> <policy_name>"
        exit 1
    }

    Set-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section CHECKPOINT -Key fwmgr -Value $args[0] # set the FW server name

    # $global:mgmtServer = "https://$($args[0]).example.com"
    $policy_name = $args[1]

    # store current session id in a file in a user home directory
    # $global:sessionIdFile = "$($HOME)\sessionid_$($args[0]).txt"

    $sessionID = Get-SessionID
    # Write-Host "Session ID: $sessionID" -ForegroundColor Cyan # for quick debugging 

    if (-Not $sessionID) {
        Write-AppLog -level "ERROR" -message "Session ID could not be generated. Exiting."
        exit 1
    } 
 
    # Install policy
    $jsonResponse = Invoke-CheckpointApi -endpoint "install-policy" -body @{"policy-package" = $policy_name} -sessionID $sessionID
    $task_id = $jsonResponse.'task-id'
    if ($task_id) {
        Write-Host "`nInstalling policy $($policy_name)" -NoNewline
        Start-Sleep -Seconds 2
        while ($true) {
            Write-Host '.' -NoNewline
            $status = (Invoke-CheckpointApi -endpoint "show-task" -body @{"task-id" = $task_id} -sessionID $sessionID).tasks[0].status            
            if ($status -ne 'in progress') {
                if ($status -eq 'succeeded') {
                    Write-Host $status -ForegroundColor Green                                        
                } else {
                    Write-Host $status -ForegroundColor Red
                } 
                break
            }
            Start-Sleep -Seconds 2
        }
    } else {
        Write-AppLog -level "INFO" -message "Install status: Failed"
    }     
 
} catch {
    Write-AppLog -level "ERROR" -message "An error occurred: $_"
    throw
} finally {
    Get-Module | Remove-Module
}
 