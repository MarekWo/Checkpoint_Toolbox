[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Checkpoint Management Server name or IP.")]
    [string]$MgmtServer,

    [Parameter(Mandatory = $true, HelpMessage = "Path to the CSV file with objects to add.")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$CsvPath,

    [Parameter(Mandatory = $true, HelpMessage = "Run mode: 'test' for simulation, 'full' for execution.")]
    [ValidateSet('test', 'full')]
    [string]$RunMode,

    [Parameter(Mandatory=$false)]
    [pscredential]$ApiCredential
)

#region Setup Paths and Modules
# Make paths relative to the script location for portability
$scriptRoot = $PSScriptRoot
$modulesPath = Join-Path -Path $scriptRoot -ChildPath "Modules"
$logPath = Join-Path -Path $scriptRoot -ChildPath "log"
$exportPath = Join-Path -Path $scriptRoot -ChildPath "export"

# Create directories if they don't exist
if (-not (Test-Path $logPath)) { New-Item -Path $logPath -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $exportPath)) { New-Item -Path $exportPath -ItemType Directory -Force | Out-Null }

$global:logFile = Join-Path -Path $logPath -ChildPath "addhosts.log"
$global:iniFilePath = Join-Path -Path $env:USERPROFILE -ChildPath "cp_tools.ini"

# Import required modules
try {
    Import-Module (Join-Path -Path $modulesPath -ChildPath "Get-Sessionid.psm1") -ErrorAction Stop
    Import-Module (Join-Path -Path $modulesPath -ChildPath "IniFilesHandler.psm1") -ErrorAction Stop
}
catch {
    Write-Host "ERROR: Failed to import required modules from '$modulesPath'. Please check the path and module files." -ForegroundColor Red
    exit 1
}
#endregion

# Define global variables
$global:changesMade = 0 

# Function to write a log message to console and file
function Write-ApplicationLog {
    param (
        [string]$level,
        [string]$message,
        [string]$color,
        [switch]$skiplog
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$level] $message"
    if (-Not $skiplog.IsPresent) {
        Add-Content -Path $logFile -Value "$timestamp $logMessage"
    }
    
    if ($color) {
        Write-Host $logMessage -ForegroundColor $color
    } else {
        Write-Host $logMessage
    }
}
 
# Function to validate IP address
function Test-IsValidIPAddress {
    param (
        [string]$ip
    )
    return [System.Net.IPAddress]::TryParse($ip, [ref]$null)
}
 
# Function to validate network in CIDR notation
function Test-IsValidCIDR {
    param (
        [string]$cidr
    )
    if ($cidr -match '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
        $ip, $prefixLength = $cidr -split '/'
        if ((Test-IsValidIPAddress -ip $ip) -and ($prefixLength -ge 0 -and $prefixLength -le 32)) {
            return $true
        }
    }
    return $false
}

# Function to validate IP address range
function Test-IsValidIPRange {
    param (
        [string]$range
    )
    if ($range -match '^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$') {
        $ips = $range -split '-'
        if ((Test-IsValidIPAddress -ip $ips[0]) -and (Test-IsValidIPAddress -ip $ips[1])) {
            return $true
        }
    }
    return $false
}
 
# Function to check if the IP address is in a private range
function Test-IsPrivateIPAddress {
    param (
        [string]$ip
    )
    $octets = $ip -split '\.'
    $i1, $i2 = [int]$octets[0], [int]$octets[1]
 
    if ($i1 -eq 10 -or ($i1 -eq 172 -and $i2 -ge 16 -and $i2 -le 31) -or ($i1 -eq 192 -and $i2 -eq 168)) {
        return $true
    }
    return $false
}
 
# Function to convert CIDR to subnet and mask
function ConvertFrom-CIDR {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory)]
        [ValidateScript( { $_ -match "(.*)\/(\d+)" })]
        [string] $IPAddress
    )

    [void] ($IPAddress -match "(.*)\/(\d+)")
    $ip = [IPAddress] $Matches[1]
    $suffix = [int] $Matches[2]
    $mask = ("1" * $suffix) + ("0" * (32 - $suffix))
    $mask = [IPAddress] ([Convert]::ToUInt64($mask, 2))

    @{
        IPAddress  = $ip.ToString()
        CIDR       = $IPAddress
        CIDRSuffix = $suffix
        NetworkID  = ([IPAddress] ($ip.Address -band $mask.Address)).IPAddressToString
        SubnetMask = $mask.IPAddressToString
    }
}

# Function to check the result of a Checkpoint API call
function Test-CheckpointApiResult {
    param (
        [psobject]$result,
        [string]$operation
    )
    if (-not $result -or $result.PSObject.Properties.Name -contains "message" -or $result.PSObject.Properties.Name -contains "errors") {
        $errorMessage = $result.message | Out-String
        Write-ApplicationLog -level "ERROR" -message "API call for '$operation' failed. Details: $errorMessage" -color Red
        return $false
    }
    return $true
}

# Function to process a generic Checkpoint object (host, network, or range)
function Sync-CheckpointObject {
    param (
        [string]$objectType,
        [string]$objectName,
        [string]$ipAddress,
        [string]$groupName,
        [string]$sessionID,
        [string]$runMode,
        [string]$pause,
        [hashtable]$apiParams
    )

    $objectCreate = ""
    $addToGroup = ""

    # Determine API endpoints and parameters based on object type
    $showEndpoint = ""
    $addEndpoint = ""
    $filterProperty = ""

    switch ($objectType) {
        "host" {
            $showEndpoint = "show-hosts"
            $addEndpoint = "add-host"
            $filterProperty = "filter"
        }
        "network" {
            $showEndpoint = "show-networks"
            $addEndpoint = "add-network"
            $filterProperty = "filter"
        }
        "range" {
            $showEndpoint = "show-address-ranges"
            $addEndpoint = "add-address-range"
            # Range API does not support filtering, so we get all and filter locally
        }
    }

    # Check if the object already exists
    $existingObject = $null
    if ($objectType -eq "range") {
        $allRanges = Invoke-CheckpointApi -endpoint $showEndpoint -body @{"details-level" = "full"} -sessionID $sessionID
        $existingObject = $allRanges.objects | Where-Object { $_."ipv4-address-first" -eq $apiParams.body."ip-address-first" -and $_."ipv4-address-last" -eq $apiParams.body."ip-address-last" } | Select-Object -First 1
    } else {
        $response = Invoke-CheckpointApi -endpoint $showEndpoint -body @{$filterProperty = $ipAddress} -sessionID $sessionID
        $existingObject = $response.objects[0]
    }
    
    $objectNameFound = $existingObject.name

    if (-not $objectNameFound) {
        if (-not $objectName) {
            Write-ApplicationLog -level "WARNING" -message "Unable to create a $objectType object for $($ipAddress): 'Object_Name' column value is missing." -skiplog
            return @{ ObjectNameMissing = 'YES' }
        }

        $objectNameFound = if ($objectType -eq "network") { "$($objectName)-$($apiParams.body.subnet)" } else { "$($objectName)-$($ipAddress)" }
        Write-ApplicationLog -level "INFO" -message "$($objectType.ToUpper()) object $ipAddress does not exist. Creating as '$objectNameFound'."
        
        $apiParams.body.name = $objectNameFound

        if ($pause -eq 'YES') {
            Write-ApplicationLog -level "INFO" -message "PAUSED: Creating $objectType '$objectNameFound'" -color DarkGray -skiplog
        } else {
            if ($runMode -eq "full") {
                Write-ApplicationLog -level "INFO" -message "Creating $objectType '$objectNameFound'"
                $addResult = Invoke-CheckpointApi -endpoint $addEndpoint -body $apiParams.body -sessionID $sessionID
                if (Test-CheckpointApiResult -result $addResult -operation "add $objectType") {
                    $global:changesMade++
                    $objectCreate = 'YES'
                } else {
                    # Stop processing this item if creation failed
                    return @{ CPObjectName = $objectNameFound; ObjectCreate = 'FAIL' }
                }
            } else {
                $ipInfo = if ($objectType -eq "network") { "$($apiParams.body.subnet)/$($apiParams.body.'subnet-mask')" } else { $ipAddress }
                Write-ApplicationLog -level "TEST" -message "CREATE $($objectType.ToUpper()) ""$objectNameFound"" (""$ipInfo""), color: ""$($apiParams.body.color)""" -color Green -skiplog
                $objectCreate = 'YES'
            }
        }
    } else {
        Write-ApplicationLog -level "INFO" -message "$($objectType.ToUpper()) object $ipAddress already exists as '$objectNameFound'. Skipping creation." -skiplog
    }

    # Add to group if groupName is specified and object exists/was created successfully
    if ($groupName -and $objectCreate -ne 'FAIL') {
        $groupMembers = Invoke-CheckpointApi -endpoint "show-group" -body @{name = $groupName} -sessionID $sessionID | Select-Object -ExpandProperty members | Select-Object -ExpandProperty name
        if ($groupMembers -contains $objectNameFound) {
            Write-ApplicationLog -level "INFO" -message "Object '$objectNameFound' is already a member of group '$groupName'." -skiplog
        } else {
            if ($pause -eq 'YES') {
                Write-ApplicationLog -level "INFO" -message "PAUSED: Adding '$objectNameFound' to group '$groupName'." -color DarkGray -skiplog
            } else {
                if ($runMode -eq "full") {
                    Write-ApplicationLog -level "INFO" -message "Adding '$objectNameFound' to group '$groupName'."
                    $setGroupResult = Invoke-CheckpointApi -endpoint "set-group" -body @{name = $groupName; "members" = @{"add" = $objectNameFound}} -sessionID $sessionID
                    if (Test-CheckpointApiResult -result $setGroupResult -operation "set-group") {
                        $global:changesMade++
                        $addToGroup = 'YES'
                    } else {
                        $addToGroup = 'FAIL'
                    }
                } else {
                    Write-ApplicationLog -level "TEST" -message "ADD ""$objectNameFound"" to ""$groupName""" -color Green -skiplog
                    $addToGroup = 'YES'
                }
            }
        }
    }

    return @{
        CPObjectName    = $objectNameFound
        ObjectCreate    = $objectCreate
        AddToGroup      = $addToGroup
        ObjectNameMissing = ''
    }
}
 
 try {
     Write-ApplicationLog -level "INFO" -message "Script started." -skiplog
    
    # Write settings to INI file for external tools
    Set-IniValue -FilePath $global:iniFilePath -Section CHECKPOINT -Key fwmgr -Value $MgmtServer
    Set-IniValue -FilePath $global:iniFilePath -Section PATHS -Key csv_addhosts -Value $CsvPath
    Set-IniValue -FilePath $global:iniFilePath -Section REQUEST -Key mode -Value $RunMode
    
    $apiPassword = $null
    if ($null -ne $ApiCredential) {
        $apiPassword = $ApiCredential.GetNetworkCredential().Password
    }
    $sessionID = Get-SessionID -ApiPassword $apiPassword -ApiPassword $ApiPassword
    Set-IniValue -FilePath $global:iniFilePath -Section USER -Key sessionid -Value $sessionID
 
    if (-not $sessionID) {
        Write-ApplicationLog -level "ERROR" -message "Session ID could not be generated. Exiting." -color Red
        exit 1
    }
 
    # Read the CSV file
    $csvData = Import-Csv $CsvPath
    $columnNames = $csvData[0].PSObject.Properties.Name
 
    # Check if required columns exist
    if (-not ($columnNames -contains "Object_Name")) {
        Write-ApplicationLog -level "ERROR" -message 'Column "Object_Name" does not exist in the CSV file. Exiting.' -color Red
        exit 1
    }
 
    if (-not ($columnNames -contains "IP Address")) {
        Write-ApplicationLog -level "ERROR" -message 'Column "IP Address" does not exist in the CSV file. Exiting.' -color Red
        exit 1
    }
 
    if ($runMode -eq "test") {
        Write-ApplicationLog -level "INFO" -message " -=RUNNING IN TEST MODE=-" -color Cyan -skiplog
    } else {
        Write-ApplicationLog -level "INFO" -message " -=RUNNING IN FULL MODE=-" -color Cyan -skiplog
    }
    
    Write-ApplicationLog -level "INFO" -message "SESSION ID: $sessionID" -color Yellow -skiplog
    
    # Process each row in the CSV file
    # collect all actions to display them as summary
    $summary = @()
     foreach ($row in $csvData) {
        $objectName = $row."Object_Name".ToString().Trim().Replace(' ', '-').ToUpper()
        $ipAddress = $row."IP Address".ToString().Replace(' ', '')
        $groupName = $row."Group_Name".ToString().Trim()
        $Pause = $row."Pause".ToString().Trim().ToUpper()
        $Completed = $row."Completed".ToString().Trim().ToUpper()
        $ItemInvalid = ''
        
        # Build a comprehensive comment for the object
        $baseComment = $row."Object_Comment".ToString()
        $requestInfo = $row."Request".ToString().Trim().Replace(',', '')
        $changeInfo = $row."Change_Request".ToString().Trim()
        $ticketInfo = (@($requestInfo, $changeInfo) | Where-Object { $_ }) -join '/'
        if ($ticketInfo) {
            $ticketInfo = "Ticket/Change: $ticketInfo"
        }
        $fullObjectComment = (@($baseComment, $ticketInfo) | Where-Object { $_ }) -join " | "

        $result = $null

        if ($Completed -ne 'YES') {
            $objectType = ""
            $apiParams = @{ body = @{} }

            if (Test-IsValidIPAddress -ip $ipAddress) {
                $objectType = "host"
                $apiParams.body = @{
                    "ip-address" = $ipAddress
                    comments     = $fullObjectComment
                    color        = if (Test-IsPrivateIPAddress -ip $ipAddress) { "Sea Green" } else { "Red" }
                }
            }
            elseif (Test-IsValidCIDR -cidr $ipAddress) {
                $objectType = "network"
                $networkInfo = ConvertFrom-CIDR -IPAddress $ipAddress
                $apiParams.body = @{
                    subnet        = $networkInfo["NetworkID"]
                    "subnet-mask" = $networkInfo["SubnetMask"]
                    comments      = $fullObjectComment
                    color         = if (Test-IsPrivateIPAddress -ip $networkInfo["NetworkID"]) { "Sea Green" } else { "Red" }
                }
            }
            elseif (Test-IsValidIPRange -range $ipAddress) {
                $objectType = "range"
                $ips = $ipAddress -split '-'
                $apiParams.body = @{
                    "ip-address-first" = $ips[0]
                    "ip-address-last"  = $ips[1]
                    comments           = $fullObjectComment
                    color              = if (Test-IsPrivateIPAddress -ip $ips[0]) { "Sea Green" } else { "Red" }
                }
            }
            else {
                Write-ApplicationLog -level "WARNING" -message "$ipAddress is not a valid IP address, network or range. Skipping." -skiplog
                $ItemInvalid = 'YES'
            }

            if ($objectType) {
                $result = Sync-CheckpointObject -objectType $objectType -objectName $objectName -ipAddress $ipAddress -groupName $groupName -sessionID $sessionID -runMode $runMode -pause $Pause -apiParams $apiParams
            }
        }
        
        $summary += [PSCustomObject]@{
            "Object"                = $ipAddress
            "Name"                  = $objectName
            "CP Name"               = $result.CPObjectName
            "Group"                 = $groupName            
            "Request"               = $row."Request".ToString().Trim().Replace(',', '')
            "Change"                = $row."Change_Request".ToString().Trim()
            "Create"                = $result.ObjectCreate            
            "Add to group"          = $result.AddToGroup
            "Paused"                = $Pause
            "Completed"             = $Completed
            "Invalid"               = $ItemInvalid
            "Name missing"          = $result.ObjectNameMissing
        }
    }
 
    # Publish the changes if any were made
    if ($global:changesMade -gt 0) {
        if ($runMode -eq "full") {
            try {
                Write-ApplicationLog -level "INFO" -message "Publishing $global:changesMade changes..."
                $publishResult = Invoke-CheckpointApi -endpoint "publish" -body @{} -sessionID $sessionID
                if (Test-CheckpointApiResult -result $publishResult -operation "publish") {
                    Write-ApplicationLog -level "INFO" -message "Publish successful."
                }
            } catch {
                Write-ApplicationLog -level "ERROR" -message "Failed to publish the changes." -color Red
            }
        } else {
            Write-ApplicationLog -level "TEST" -message "PUBLISH CHANGES --session-id $sessionID" -color Green -skiplog
        }
    } else {
        Write-ApplicationLog -level "INFO" -message "No changes were made, skipping publish." -skiplog
    }
 
    if ($runMode -eq "test") {
        Write-ApplicationLog -level "INFO" -message " -=END OF TEST MODE=-" -color Cyan -skiplog
    } else {
        Write-ApplicationLog -level "INFO" -message " -=END OF FULL MODE=-" -color Cyan
    }
 
    Write-ApplicationLog -level "INFO" -message "Script completed successfully." -skiplog

    Write-Host "`n--==SUMMARY==--"

    $summary = $summary | Select-Object "Object", "Name", "CP Name", "Group", "Request", "Change", "Create", "Add to group","Paused", "Completed", "Invalid", "Name missing"
    $ExportCSVFile = "$($exportPath)\export_$(Get-Date -Format "yyyyMMddHHmmss")_$($MgmtServer)_$($RunMode).csv"
    $summary | Format-Table
    $summary | Export-Csv -Path $ExportCSVFile -NoTypeInformation
    Write-Host "The report was exported to $ExportCSVFile on $env:computername"
 
} catch {
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-ApplicationLog -level "ERROR" -message "An unexpected error occurred: $_, line: $line"
    throw
} finally {
    # Remove only the modules imported by this script
    Remove-Module -Name 'Get-Sessionid', 'IniFilesHandler' -Force -ErrorAction SilentlyContinue
}
