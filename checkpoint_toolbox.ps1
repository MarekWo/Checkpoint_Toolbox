Import-Module "O:\Scripts\Powershell\Modules\checkpoint_remote.psm1" # run this line to import functions used below

# -------------RUN THIS BLOCK ONCE AT START OF YOUR DAILY ROUTINES------------
# login with A account and set initial variables
$cred = Get-Credential
$fwmgr = @{fwmgrName = "fwmgr" ; cred = $cred}; $sgar80fwmgr = @{fwmgrName = "sgar80fwmgr" ; cred = $cred}

# Change request number for this week; Make sure a csv file of this name is created before running Add-CPHosts function
$ChangeRequest = 'CHG0183652' 

# Map the network drive to see the configuration, logs and export files
$drive = 'Y'
if (-Not (Test-Path -path "$($drive):\")) { Add-RemoteDrive -servername $servername -driveletter $drive -cred $cred }
Invoke-Item "$($drive):\csv"; Invoke-Item "$($drive):\export"

# $csvFile = "$($drive):\csv\$($ChangeRequest).csv"
# $CSVHeader = [PsCustomObject]@{"IP Address" = $null; "Object_Name" = $null; "Group_Name" = $null; "Environment" = $null;"Request" = $null; "Change_Request" = $null; "Pause" = $null; "Completed" = $null; "Comment" = $null }
# if (-not (Test-Path -path $csvFile )) { $CSVHeader | Export-Csv -Path $csvFile -NoTypeInformation }

$xlsmFolder = "F:\Checkpoint\Requests\Spreadsheets"
$xlsmFile = "$($xlsmFolder)\$($ChangeRequest).xlsm"
if (-not (Test-Path -path $xlsmFile )) { Copy-Item "$($xlsmFolder)\template.xlsm" $xlsmFile }
Invoke-Item $xlsmFile

# -------------------END OF BLOCK TO RUN ONCE---------------------------------

break # To prevent from inadvertently running all lines of the script at once. 

# Run each command by selecting a block of code and hitting F8 key

# create host objects and add them to a group. Make sure a csv file with all necessary data is created. See the comment about $ChangeRequest variable
# Add-CPHosts @fwmgr -ch $changeRequest -m test
# Add-CPHosts @fwmgr -ch $changeRequest -m full

# --- NEW v7 SCRIPT INVOCATION ---
# Note: The new function requires explicit, named parameters instead of splatting
Add-CPHosts_v7 -FwmgrName $fwmgr.fwmgrName -Credential $fwmgr.cred -ChangeRequest $ChangeRequest -Mode 'test'
Add-CPHosts_v7 -FwmgrName $fwmgr.fwmgrName -Credential $fwmgr.cred -ChangeRequest $ChangeRequest -Mode 'full'

# Install selected policy
Push-CPPolicy @fwmgr -p "CSTEST-Policy"
Push-CPPolicy @fwmgr -p "CSTSTCHOKE-Policy"

# Push policy on PROD, use with caution! It can be installed on the weekends only!
# Push-CPPolicy @fwmgr -p "NewJerseyProduction"
# Push-CPPolicy @fwmgr -p "CoreSite"

# check where IP is used. It can be used either directly in a rule/group, or indirectly (via a group)
# ipToQuery can be a single IP, IP list separated with commas, a text file with a .txt extension
Get-CPWhereUsed_v2 @fwmgr -ip 3.211.82.34 -ReadOnly # object not found

Get-CPWhereUsed_v2 @fwmgr -ip test\to_cleanup.txt

# unmap the Y drive
Get-PSDrive -Name "Y" | Remove-PSDrive 

#------------------------------------------------------------
# LAB
# Add-CPHosts @sgar80fwmgr -ch $changeRequest -m test
# Add-CPHosts @sgar80fwmgr -ch $changeRequest -m full
Get-CPWhereUsed @sgar80fwmgr -ip 10.88.150.11

# Push-CPPolicy @sgar80fwmgr -p "NJHS-LAB"

# Optional - opening remote folders
# Open-RemoteFolder -folder "" -drive $drive
# Open-RemoteFolder -folder "export" -drive $drive
# Open-RemoteFolder -folder "log" -drive $drive

Get-Module | Remove-Module # it is a good practice to remove the imported modules from memory

 