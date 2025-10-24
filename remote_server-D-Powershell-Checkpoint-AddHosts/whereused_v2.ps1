[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$MgmtServer,

    [Parameter(Mandatory=$true)]
    [string]$IpAddress,

    [Parameter(Mandatory=$false)]
    [string]$ApiPassword
)

# Global variables
Import-Module -Name 'D:\Powershell\Checkpoint\AddHosts\Modules\Get-Sessionid.psm1'

# Main script
function Get-CheckpointIPInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,
        [Parameter(Mandatory=$true)]
        [string]$sessionID        
    )

    $retValue = @() # 2 elements array: 1-whereused, 2-object found (true/false)
    $usageTypes = @('used-directly', 'used-indirectly')
    $whereUsed = @()
    $dnsNameInfo = ''
    $dnsName = $null

    # Get host objects that partially match the IP address
    $matchingHostObjects = Invoke-CheckpointApi -endpoint "show-hosts" -body @{filter = $ipAddress} -sessionID $sessionID

    $hostObject = $null
    $hostNameFound = $null
    $natAddress = $null

    if ($matchingHostObjects.objects -and $matchingHostObjects.objects.Count -gt 0) {
        foreach ($matchingHost in $matchingHostObjects.objects) {
            # Get full info for each potential match to check for an exact IP match
            $currentHostObject = Invoke-CheckpointApi -endpoint "show-host" -body @{"name" = $matchingHost.name} -sessionID $sessionID
            if ($currentHostObject.'ipv4-address' -eq $IPAddress) {
                $hostObject = $currentHostObject
                $hostNameFound = $currentHostObject.name
                $natAddress = $hostObject.'nat-settings'.'ipv4-address'
                break
            }
        }
    }

    if ($null -ne$hostNameFound ) {
        # Object was found, now search for where it is being used
        $usageSearch = Invoke-CheckpointApi -endpoint "where-used" -body @{"name" = $hostNameFound;"indirect" = "true"} -sessionID $sessionID
    
        if ($usageSearch."$($usageTypes[0])" -or $usageSearch."$($usageTypes[1])") {            
            $dnsName = (Resolve-DnsName -Type PTR -Name $IPAddress -ErrorAction SilentlyContinue).NameHost -join ', '
            if ($null -ne $dnsName) {
                $dnsNameInfo = "DNS name:`t`t$dnsName"
            }

            Write-Host "`nIP address:`t`t" -NoNewline
            Write-Host "$($IPAddress)" -ForegroundColor Cyan -NoNewline
                if ($natAddress -and $natAddress -ne $IPAddress) {
                    Write-Host " (NAT: $($natAddress))"
                } else {
                    Write-Host }                
                Write-Host "Object name:`t$hostNameFound"
                if ($dnsNameInfo) { Write-Host $dnsNameInfo }
            foreach ($usageType in $usageTypes) {
                if ($usageSearch."$usageType") {
                    foreach ($object in $usageSearch."$usageType".objects) {
                        $whereUsed += [PSCustomObject]@{
                            IP = $ipAddress
                            NAT = $natAddress
                            ObjectName = $hostNameFound
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
                            IP = $ipAddress
                            NAT = $natAddress
                            ObjectName = $hostNameFound
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
            
            $retValue = @($whereUsed, $true, $natAddress, $hostNameFound, $dnsName)
            return $retValue

        } else {    
            # object is not used anywhere      
            $retValue = @($null, $true, $natAddress, $hostNameFound, $dnsName)
            return $retValue
        }
    } else {    
        # object was not found in database    
        $retValue = @($null, $false, "", "", "")
        return $retValue
        
    }
}

try {
    $WhereusedArray = @()

    Set-IniValue -FilePath "$env:USERPROFILE\cp_tools.ini" -Section CHECKPOINT -Key fwmgr -Value $MgmtServer # set the FW server name
    $sessionID = Get-SessionID -ApiPassword $ApiPassword

    if (-not $sessionID) {
        Write-Error "Failed to get a session ID. Halting script."
        exit 1
    }

    $ips = $IpAddress

    if ($ips.Substring($ips.Length - 3, 3) -eq 'txt') { 
        $ipArray = Get-Content $ips
    } else {
        $ipArray = $ips -split ' '
    }    

    foreach ($ipToQuery in $ipArray) {
        $Whereused = @()
        $Whereused = Get-CheckpointIPInfo -IPAddress $ipToQuery -sessionID $sessionID 

        if ($null -ne $Whereused[0] ) {
            $Whereused[0] | Select-Object Used,Type,Name,Policy,Column,Position | Format-Table -AutoSize
            $WhereusedArray += $Whereused[0]
        } else {    
            if ($Whereused[1]) { 
                $ObjectName =  $Whereused[3] 
                $message = "$($Whereused[3]): object not used" 
            } else { 
                $ObjectName = "object not found"
                $message = "$ObjectName"
            }

            $WhereusedArray += [PSCustomObject]@{
                            IP = $ipToQuery
                            NAT = $Whereused[2]
                            ObjectName = $ObjectName
                            DNSName = $Whereused[4]
                            Used = "FALSE"
                            Type = ""
                            Name = ""
                            Column = ""
                            Position = ""
                            Policy = ""
                        }

            Write-Host "IP $ipToQuery - $message" -ForegroundColor Yellow
        }
        Write-Host '------------------------------------------------------------------------------------------------'
    }

        $exportPath = "D:\Powershell\Checkpoint\AddHosts\export"
        $ExportCSVFile = "$($exportPath)\whereused_$(Get-Date -Format "yyyyMMddhhmmss").csv"
        $WhereusedArray | Export-Csv -Path $ExportCSVFile -NoTypeInformation
        Write-Host "The report was exported to $ExportCSVFile on $env:computername"
} catch {
    throw
} finally {
    Get-Module | Remove-Module
}