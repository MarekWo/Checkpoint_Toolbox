Import-Module -Name 'D:\Powershell\Modules\Write-AppLog.psm1'
Import-Module -Name 'D:\Powershell\Checkpoint\AddHosts\Modules\IniFilesHandler.psm1'

# Bypass SSL certificate check
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

function Get-SessionID {
    param (
        [string]$ApiPassword
    )

    if (-not [string]::IsNullOrEmpty($ApiPassword)) {
        # Non-interactive method using the provided API password
        try {
            $apiUser = Get-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section USER -Key api_user
            if (-not $apiUser) {
                $apiUser = "fwapi" # Fallback to a default username if not specified in the INI file
                Write-Host "API username not found in cp_tools.ini, using default 'fwapi'." -ForegroundColor Yellow
            }

            $fwmgr = Get-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section CHECKPOINT -Key fwmgr
            $domain = Get-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section CHECKPOINT -Key domain -DefaultValue "example.com"
            $mgmtServer = "https://$($fwmgr).$($domain)"

            $response = Invoke-RestMethod -Uri "$mgmtServer/web_api/login" -Method Post -ContentType "application/json" -Body (@{ user = $apiUser; password = $ApiPassword } | ConvertTo-Json)
            $sessionID = $response.sid
            Write-Host "Successfully obtained a session ID using the provided API password." -ForegroundColor Green
            return $sessionID
        } catch {
            Write-Host "Failed to obtain a session ID using the provided API password. Error: $_" -ForegroundColor Red
            throw
        }
    } else {
        # Fallback to the original interactive RSA token method
        $sessionID = ""
        try {
            $fwmgr = Get-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section CHECKPOINT -Key fwmgr
            $sessionID = Get-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section USER -Key "sessionid_$($fwmgr)"
            if ($sessionID) {
                if (-Not (Test-SessionID -sessionID $sessionID)) {
                    $sessionID = New-SessionID
                }
            }
            else {
                $sessionID = New-SessionID
            }
        } catch {
            Write-Host "Unable to get an interactive session ID." -ForegroundColor Red
            throw
        }
        return $sessionID
    }
}

function Test-SessionID {
    param (
        [string]$sessionID        
    )

    $retValue = $false
    try {
        $response = Invoke-CheckpointApi -endpoint "show-session" -body @{} -sessionID $sessionID
        if ($response) { 
            $retValue = $true
        } else {
            $retValue = $false
        }
    } catch {
        $retValue = $false
    }
    
    return $retValue
}

function New-SessionID {
    $sessionID = ''
    $username = Get-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section USER -Key username
    if ($username -eq '') {
        $username = Read-Host "Provide the user name"
        Set-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section USER -Key username -Value $username
    }    
    $rsaToken = Read-Host "Provide the RSA Token for user $username"

    try {        
        $fwmgr = Get-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section CHECKPOINT -Key fwmgr        
        $domain = Get-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section CHECKPOINT -Key domain -Default "example.com"
        $mgmtServer = "https://$($fwmgr).$($domain)"
        
        $response = Invoke-RestMethod -Uri "$mgmtServer/web_api/login" -Method Post -ContentType "application/json" -Body (@{ user = $username; password = $rsaToken } | ConvertTo-Json)         
        $sessionID = $response.sid
        
        Set-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section USER -Key "sessionid_$($fwmgr)" -Value $sessionID
    } catch {       
        throw
    } 

    return $sessionID   
}

function Invoke-CheckpointApi {
    param (
        [string]$endpoint,
        [hashtable]$body,
        [string]$sessionID
    )

    $fwmgr = Get-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section CHECKPOINT -Key fwmgr
    $domain = Get-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section CHECKPOINT -Key domain -Default "example.com"
    $mgmtServer = "https://$($fwmgr).$($domain)"

    $uri = "$mgmtServer/web_api/$endpoint"
    $headers = @{ "X-chkp-sid" = $sessionID }
    try {
        $return = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Headers $headers -Body ($body | ConvertTo-Json) 
        return $return
    } catch { return $null }
}