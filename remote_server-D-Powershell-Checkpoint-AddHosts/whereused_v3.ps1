[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$MgmtServer,

    [Parameter(Mandatory=$true)]
    [string]$IpAddress,

    [Parameter(Mandatory=$false)]
    [pscredential]$ApiCredential
)

#region Modules and Helper Functions
Import-Module -Name 'D:\Powershell\Checkpoint\AddHosts\Modules\Get-Sessionid.psm1' -Force

# Function to validate IP address
function Test-IsValidIPAddress {
    param ([string]$ip)
    return [System.Net.IPAddress]::TryParse($ip, [ref]$null)
}
 
# Function to validate network in CIDR notation
function Test-IsValidCIDR {
    param ([string]$cidr)
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
    param ([string]$range)
    if ($range -match '^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$') {
        $ips = $range -split '-'
        if ((Test-IsValidIPAddress -ip $ips[0]) -and (Test-IsValidIPAddress -ip $ips[1])) {
            return $true
        }
    }
    return $false
}
 
# Function to convert CIDR to subnet and mask
function ConvertFrom-CIDR {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({ $_ -match "(.*)\/(\d+)" })]
        [string] $IPAddress
    )
    [void]($IPAddress -match "(.*)\/(\d+)")
    $ip = [IPAddress]$Matches[1]
    $suffix = [int]$Matches[2]
    $mask = ("1" * $suffix) + ("0" * (32 - $suffix))
    $mask = [IPAddress]([Convert]::ToUInt64($mask, 2))
    @{
        IPAddress  = $ip.ToString()
        CIDR       = $IPAddress
        CIDRSuffix = $suffix
        NetworkID  = ([IPAddress]($ip.Address -band $mask.Address)).IPAddressToString
        SubnetMask = $mask.IPAddressToString
    }
}
#endregion

# Main script
function Get-CheckpointObjectInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Query,
        [Parameter(Mandatory=$true)]
        [string]$sessionID        
    )

    $retValue = @() # 2 elements array: 1-whereused, 2-object found (true/false)
    $usageTypes = @('used-directly', 'used-indirectly')
    $whereUsed = @()
    $dnsNameInfo = ''
    $dnsName = $null
    $foundObject = $null
    $objectNameFound = $null
    $objectType = ''
    $natAddress = $null

    # Determine object type and find it
    if (Test-IsValidCIDR -cidr $Query) {
        $objectType = "network"
        $response = Invoke-CheckpointApi -endpoint "show-networks" -body @{filter = $Query} -sessionID $sessionID
        if ($response.objects) {
            $foundObject = $response.objects | Select-Object -First 1
        }
    }
    elseif (Test-IsValidIPRange -range $Query) {
        $objectType = "range"
        $ips = $Query -split '-'
        $ipFirst = $ips[0]
        $ipLast = $ips[1]
        $allRanges = Invoke-CheckpointApi -endpoint "show-address-ranges" -body @{"details-level" = "full"} -sessionID $sessionID
        if ($allRanges.objects) {
            $foundObject = $allRanges.objects | Where-Object { $_."ipv4-address-first" -eq $ipFirst -and $_."ipv4-address-last" -eq $ipLast } | Select-Object -First 1
        }
    }
    elseif (Test-IsValidIPAddress -ip $Query) {
        # First, assume it's a host and try to find an exact match
        $objectType = "host"
        $matchingHostObjects = Invoke-CheckpointApi -endpoint "show-hosts" -body @{filter = $Query} -sessionID $sessionID
        if ($matchingHostObjects.objects -and $matchingHostObjects.objects.Count -gt 0) {
            foreach ($matchingHost in $matchingHostObjects.objects) {
                $currentHostObject = Invoke-CheckpointApi -endpoint "show-host" -body @{"name" = $matchingHost.name} -sessionID $sessionID
                if ($currentHostObject.'ipv4-address' -eq $Query) {
                    $foundObject = $currentHostObject
                    break
                }
            }
        }

        # If no exact host match was found, it might be a network object identified by its network address
        if (-not $foundObject) {
            $objectType = "network"
            $response = Invoke-CheckpointApi -endpoint "show-networks" -body @{filter = $Query} -sessionID $sessionID
            if ($response.objects) {
                # The filter might return multiple networks (e.g., containing networks). Find the one where the subnet address is exactly our query.
                $foundObject = $response.objects | Where-Object { $_.subnet -eq $Query } | Select-Object -First 1
            }
        }
    }

    if ($foundObject) {
        $objectNameFound = $foundObject.name
        if ($objectType -eq 'host') {
            $natAddress = $foundObject.'nat-settings'.'ipv4-address'
        }
    }

    if ($null -ne $objectNameFound) {
        # Object was found, now search for where it is being used
        $usageSearch = Invoke-CheckpointApi -endpoint "where-used" -body @{"name" = $objectNameFound;"indirect" = "true"} -sessionID $sessionID
    
        if ($usageSearch."$($usageTypes[0])" -or $usageSearch."$($usageTypes[1])") {            
            if ($objectType -eq 'host') {
                $dnsName = (Resolve-DnsName -Type PTR -Name $Query -ErrorAction SilentlyContinue).NameHost -join ', '
                if ($null -ne $dnsName) {
                    $dnsNameInfo = "DNS name:`t`t$dnsName"
                }
            }

            Write-Host "`nQuery:`t`t`t" -NoNewline
            Write-Host "$($Query)" -ForegroundColor Cyan -NoNewline
            if ($natAddress -and $natAddress -ne $Query) {
                Write-Host " (NAT: $($natAddress))"
            } else {
                Write-Host
            }
            Write-Host "Object type:`t`t$objectType"
            Write-Host "Object name:`t`t$objectNameFound"
            if ($dnsNameInfo) { Write-Host $dnsNameInfo }

            foreach ($usageType in $usageTypes) {
                if ($usageSearch."$usageType") {
                    foreach ($object in $usageSearch."$usageType".objects) {
                        $whereUsed += [PSCustomObject]@{
                            Query = $Query
                            NAT = $natAddress
                            ObjectType = $objectType
                            ObjectName = $objectNameFound
                            DNSName = $dnsName
                            Used = ($usageType -split '-')[1]
                            Type = $object.type
                            Name = $object.name                            
                            Column = 'n/a'
                            Position = 'n/a'
                            Policy = 'n/a'
                        }
                    }
                    foreach ($rule in $usageSearch."$usageType".'access-control-rules') {
                        $whereUsed += [PSCustomObject]@{
                            Query = $Query
                            NAT = $natAddress
                            ObjectType = $objectType
                            ObjectName = $objectNameFound
                            DNSName = $dnsName
                            Used = ($usageType -split '-')[1]
                            Type = 'rule'
                            Name = $rule.rule.name                            
                            Column = $rule.'rule-columns' -join ", "
                            Position = $rule.position
                            Policy = $rule.package.name
                        }                        
                    }
                }
            }   
            
            $retValue = @($whereUsed, $true, $natAddress, $objectNameFound, $dnsName, $objectType)
            return $retValue

        } else {    
            # object is not used anywhere      
            $retValue = @($null, $true, $natAddress, $objectNameFound, $dnsName, $objectType)
            return $retValue
        }
    } else {    
        # object was not found in database    
        $retValue = @($null, $false, "", "", "", "")
        return $retValue
    }
}

try {
    $WhereusedArray = @()

    Set-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section CHECKPOINT -Key fwmgr -Value $MgmtServer # set the FW server name
    $apiPassword = $null
    if ($null -ne $ApiCredential) {
        $apiPassword = $ApiCredential.GetNetworkCredential().Password
    }
    $sessionID = Get-SessionID -ApiPassword $apiPassword

    if (-not $sessionID) {
        Write-Error "Failed to get a session ID. Halting script."
        exit 1
    }

    $queries = $IpAddress

    if ($queries.Substring($queries.Length - 3, 3) -eq 'txt') { 
        $queryArray = Get-Content $queries
    } else {
        $queryArray = $queries -split ' '
    }    

    foreach ($itemToQuery in $queryArray) {
        $Whereused = @()
        $Whereused = Get-CheckpointObjectInfo -Query $itemToQuery -sessionID $sessionID 

        if ($null -ne $Whereused[0] ) {
            $Whereused[0] | Select-Object Used,Type,Name,Policy,Column,Position | Format-Table -AutoSize
            $WhereusedArray += $Whereused[0]
        } else {    
            if ($Whereused[1]) { 
                $ObjectName =  $Whereused[3] 
                $message = "$($Whereused[3]) ($($Whereused[5])): object not used" 
            } else { 
                $ObjectName = "object not found"
                $message = "$ObjectName"
            }

            $WhereusedArray += [PSCustomObject]@{
                            Query = $itemToQuery
                            NAT = $Whereused[2]
                            ObjectType = $Whereused[5]
                            ObjectName = $ObjectName
                            DNSName = $Whereused[4]
                            Used = "FALSE"
                            Type = ""
                            Name = ""
                            Column = ""
                            Position = ""
                            Policy = ""
                        }

            Write-Host "Query '$itemToQuery' - $message" -ForegroundColor Yellow
        }
        Write-Host '------------------------------------------------------------------------------------------------'
    }

    $exportPath = "D:\Powershell\Checkpoint\AddHosts\export"
    if (-not (Test-Path $exportPath)) { New-Item -Path $exportPath -ItemType Directory -Force | Out-Null }
    $ExportCSVFile = "$($exportPath)\whereused_$(Get-Date -Format "yyyyMMddhhmmss").csv"
    $WhereusedArray | Export-Csv -Path $ExportCSVFile -NoTypeInformation
    Write-Host "The report was exported to $ExportCSVFile on $env:computername"
} catch {
    $line = $_.InvocationInfo.ScriptLineNumber
    Write-ApplicationLog -level "ERROR" -message "An unexpected error occurred: $_, line: $line"
    throw
} finally {
    Get-Module | Where-Object { $_.Name -in 'Get-Sessionid' } | Remove-Module
}
