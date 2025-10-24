function Set-IniValue {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Parameter(Mandatory=$true)]
        [string]$Section,
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [Parameter(Mandatory=$true)]
        [string]$Value
    )
 
    # Create the file if it doesn't exist
    if (-not (Test-Path $FilePath)) {
        New-Item -Path $FilePath -ItemType File -Force | Out-Null
    }
 
    # Read the content of the file
    $content = Get-Content $FilePath -ErrorAction SilentlyContinue
 
    if ($null -eq $content) {
        $content = @()
    }
 
    # Check if the section exists
    $sectionIndex = -1
    $inSection = $false
    for ($i = 0; $i -lt $content.Count; $i++) {
        if ($content[$i] -match "^\[$Section\]$") {
            $sectionIndex = $i
            $inSection = $true
        } elseif ($inSection -and $content[$i] -match "^\[") {
            break
        } elseif ($inSection -and $content[$i] -match "^$Key\s*=") {
            $content[$i] = "$Key=$Value"
            # Ensure there's a blank line after each section
            $updatedContent = @()
            $lastSectionIndex = -1
            for ($j = 0; $j -lt $content.Count; $j++) {
                $updatedContent += $content[$j]
                if ($content[$j] -match "^\[" -and $j -ne 0) {
                    if ($updatedContent[-2] -ne "") {
                        $updatedContent = $updatedContent[0..($updatedContent.Count-2)] + "" + $updatedContent[-1]
                    }
                }
            }
            $updatedContent | Set-Content $FilePath -Force
            return
        }
    }
 
    # If the section doesn't exist, add it
    if ($sectionIndex -eq -1) {
        if ($content.Count -gt 0 -and $content[-1] -ne "") {
            $content += ""
        }
        $content += "[$Section]"
        $content += "$Key=$Value"
    } else {
        # If the section exists but the key doesn't, add the key-value pair
        $content = $content[0..$sectionIndex] + 
                   "$Key=$Value" + 
                   $content[($sectionIndex + 1)..($content.Count - 1)]
    }
 
    # Ensure there's a blank line after each section
    $updatedContent = @()
    $lastSectionIndex = -1
    for ($i = 0; $i -lt $content.Count; $i++) {
        $updatedContent += $content[$i]
        if ($content[$i] -match "^\[" -and $i -ne 0) {
            if ($updatedContent[-2] -ne "") {
                $updatedContent = $updatedContent[0..($updatedContent.Count-2)] + "" + $updatedContent[-1]
            }
        }
    }
 
    # Write the content back to the file
    $updatedContent | Set-Content $FilePath -Force
}

function Get-IniValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Parameter(Mandatory=$true)]
        [string]$Section,
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [Parameter(Mandatory=$false)]
        [string]$DefaultValue
    )
 
    # Check if the file exists
    if (-not (Test-Path $FilePath)) {
        Write-Verbose "File not found: $FilePath. Returning default value."
        return $DefaultValue
    }
 
    # Read the content of the file
    $content = Get-Content $FilePath -ErrorAction SilentlyContinue
 
    if ($null -eq $content) {
        Write-Verbose "File is empty: $FilePath. Returning default value."
        return $DefaultValue
    }
 
    # Find the section
    $sectionStart = $content | Select-String -Pattern "^\[$Section\]$" | Select-Object -First 1 -ExpandProperty LineNumber
    if (-not $sectionStart) {
        Write-Verbose "Section [$Section] not found in $FilePath. Returning default value."
        return $DefaultValue
    }
 
    # Search for the key in the section
    for ($i = $sectionStart; $i -lt $content.Count; $i++) {
        if ($content[$i] -match "^\[" -and $i -ne ($sectionStart - 1)) {
            break
        }
        if ($content[$i] -match "^$Key\s*=\s*(.*)$") {
            return $matches[1].Trim()
        }
    }
 
    Write-Verbose "Key '$Key' not found in section [$Section] of $FilePath. Returning default value."
    return $DefaultValue
}