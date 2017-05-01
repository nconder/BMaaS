<# 

Import JSON prams, copy UCS profile template, set UCS profile to hardware blad or rackmount, deploy node with VMM physical host profile.
Deploys a new Hyper-V Node from single JSON var file.  
The script does the following creates a new UCS profile, deploys a hyper-v node with VMM and WDS, installs drivers, 
renames nics with UCS on MAC, renames NICs from name from UCS renaming, installs windows features and roles, 
creates hyper-v switches, configures hyper-v servers settings ie livemigrations and paths, joins node to existing cluster.

Change Log:
03/16/2017 v1.8
Combinded all scripts
03/17/2017 v1.9
Added progress loging.

#>
# Handle erros 
try
{
#Import VMM module
Import-Module virtualmachinemanager
#Import PowerTool module
Import-Module ciscoUcsPs  
Import-Module FailoverClusters
$starttime = (get-date)
Function timedate (){
	get-date
}
# Log file
$log = "C:\node-build-log.txt"
timedate | Out-File $log
Add-Content $log "`n - $(timedate) - BMaaS VMM Hyper-V node automation."
# Load node configuration JSON file from web
$url = " http://SERVERNAME.cloudlab.local/UCSHyperVConfig.json"
$request = 'C:\UCSHyperVConfig.json'
#Invoke-WebRequest $request
Invoke-WebRequest -Uri $url -OutFile $request
Start-Sleep -s 2 

$JSONRaw = Get-Content -Raw -Path $request
$JSONRaw 
$jsonconfig = Get-Content -Raw $request | Out-String | ConvertFrom-Json | Select-Object -expand config
$jsonconfig
$jsonconfignodeconfig = Get-Content -Raw $request | Out-String | ConvertFrom-Json | Select-Object -expand config| Select-Object -expand nodeconfig
$jsonconfignodeconfig
$jsonnic = Get-Content  -Raw $request | Out-String | ConvertFrom-Json | Select-Object -expand config | Select-Object -expand setNicIp
$jsonnic
$jsoncluster = Get-Content  -Raw $request | Out-String | ConvertFrom-Json | Select-Object -expand config | Select-Object -expand cluster
$jsoncluster

##########################################################
#
#   Nothing below this should be changed.
#   Adjust everthing in the JSON file or above.
#
##########################################################
###################################################################
###################################################################
###################################################################
####### Start of ucs profile deployment #######

$name = $jsonconfignodeconfig.name
$fqdn = $jsonconfignodeconfig.fqdnname
$nodeip = $jsonnic.pria.ipv4
# Set UCS Credential
$user = $jsonconfignodeconfig.uscuser
$password = $jsonconfignodeconfig.uscuserpw | ConvertTo-SecureString -AsPlainText -Force
# Connect to UCS
$cred = New-Object system.Management.Automation.PSCredential($user, $password)
# Build Cisco UCS Handle
$UCSHandle = Connect-Ucs -name $jsonconfignodeconfig.ucsip -Credential $cred
# Get some data from UCS
Get-UcsOrg -Level root -Ucs $UCSHandle

# Copy UCS service profile from template
Get-UcsOrg -Level $jsonconfignodeconfig.ucsroot -Ucs $UCSHandle | Get-UcsOrg -Name $jsonconfignodeconfig.ucsorg -LimitScope | `
Get-UcsServiceProfile -Name $jsonconfignodeconfig.ucsServiecProfile -LimitScope | `
Add-UcsServiceProfileFromTemplate -NewName @($jsonconfignodeconfig.name) -DestinationOrg $jsonconfignodeconfig.ucsorgfullpath
Add-Content $log "`n - $(timedate) - Finished coping UCS profile template $($jsonconfignodeconfig.ucsServiecProfile)"
Start-Sleep -s 4
# Associate service profile to physical hw
if ($jsonconfignodeconfig.hwtype -eq "blade" -or "Blade" -or "BLADE") {
    # Blade
    $assoviateSPHW = (Get-UcsOrg -Level root -Ucs $UCSHandle | Get-UcsOrg -Name $jsonconfignodeconfig.ucsorg -LimitScope | Get-UcsServiceProfile -Name $jsonconfignodeconfig.name  | Associate-UcsServiceProfile -Force -Blade (Get-UcsBlade -Ucs $UCSHandle -ChassisId $jsonconfignodeconfig.ucsBladeId -SlotId $jsonconfignodeconfig.ucsSlotId))
    $ucsNodeIp = (Get-UcsIpPoolAddr -Ucs $UCSHandle | where {$_.AssignedToDn -like "*$jsonconfignodeconfig.name*"})
    Start-Sleep -s 365
	Add-Content $log "`n - $(timedate) - Hardware type is a Blade server. `n UCS finished Associating the new UCS profile template to the blade server and the profile name is $name"
   }
else {    
    # Rackmount
    $assoviateSPHWRack = (Get-UcsServiceProfile -Ucs $UCSHandle -Name $jsonconfignodeconfig.ucsServiecProfile | Associate-UcsServiceProfile -Force -RackUnit (Get-UcsRackUnit -Ucs $UCSHandle -ServerId $jsonconfignodeconfig.ucsServerId))
    $ucsNodeIp = (Get-UcsIpPoolAddr -Ucs $UCSHandle| where {$_.AssignedToDn -like "*$jsonconfignodeconfig.ucsServiecProfile*"})
    Start-Sleep -s 600
	Add-Content $log "`n - $(timedate) - Hardware type is a Rackmount server. `n UCS finished Associating the new UCS profile template to the rackmount server and the profile name is $name"
}

}
catch
{
    Throw $_.Exception | Out-File "C:\UCSHyperVConfig-UCSProfile-exception.txt" #| Write-EventLog -ComputerName $jsonconfignodeconfig.eventlogsvr -LogName "Azure-OnPrem" -Source "Applications" -EventID 6003 -EntryType Error -Message $_.Exception
}

###################################################################
###################################################################
###################################################################
####### Start of node deployment #######
try
{
Add-Content $log "`n - $(timedate) - Started VMM node deployment of $name"
# Clean up static IP in VMM
$ip = get-scipaddress -IPAddress $jsonnic.pria.ipv4
$ip | revoke-scipaddress
Add-Content $log "`n - $(timedate) - Cleanup any previous deployed VMM IPv4 address that where assigned to $name"
###### Deploy node with VMM, use UCS to get BMCIP, and use UCS to get MAC addr so VMM can set static ip on node. ######
# Test the connection to VMM Server
Get-SCVMMServer -ComputerName $jsonconfignodeconfig.vmmserver -SetAsDefault  | Out-Null
# Get host group name and GUID by name
Add-Content $log "`n - $(timedate) - Get hostgroup name and GUID by name from VMM"
$gethostgrp = Get-SCVMHostGroup -Name $jsonconfignodeconfig.vmmhostgrp
$gethostgrp 
$HostGroup = Get-SCVMHostGroup -ID $gethostgrp.ID -Name $gethostgrp.name 
$HostGroup
# Get IPMI run as name and GUID by name
Add-Content $log "`n - $(timedate) - Get IPMI run as name and GUID by name from VMM"
$getrunasacct = Get-SCRunAsAccount -Name $jsonconfignodeconfig.bmcrunas
$getrunasacct 
$RunAsAccount = Get-SCRunAsAccount -Name $getrunasacct.Name -ID $getrunasacct.ID
$RunAsAccount
# Get Physical computer profile and GUID by name
Add-Content $log "`n - $(timedate) - Get Physical computer profile and GUID by name from VMM"
$getphycompro = Get-SCPhysicalComputerProfile -Name $jsonconfignodeconfig.vmmphyprofilename
$getphycompro
$PhysicalComputerProfile = Get-SCPhysicalComputerProfile -ID $getphycompro.ID
$PhysicalComputerProfile
# Connect to UCS
Get-UcsOrg -Level root -Ucs $UCSHandle
# Get UCS IPMI IP and GUID by name
Add-Content $log "`n - $(timedate) - Get UCS IPMI IP and GUID by name from mainboard"
$bmcip = (Get-UcsIpPoolAddr -Ucs $UCSHandle | where {$_.AssignedToDn -like "*$name*"})
$bmcip
$bmcsmbiosguid = Find-SCComputer  -BMCAddress $bmcip.id -BMCRunAsAccount $RunAsAccount -BMCProtocol $jsonconfignodeconfig.bmcprotocol
# Get MAC address so we can set a static ip on network adapter configs for node deployment. MAC is coming from UCS profile by name
Add-Content $log "`n - $(timedate) - Get MAC address to set a static IP on network adapter configs for node deployment. MAC is coming from UCS profile by name."
$vnic1mac = (Get-UcsServiceProfile -Name $jsonconfignodeconfig.name -Ucs $UCSHandle | Get-UcsVnic | Where-Object {$_.Dn -like "*VNIC1"})
# Set static ip on frontnet management network
Add-Content $log "`n - $(timedate) - Setting static IP on FrontNet management network for VMM to use during deployment."
$NetworkAdapterConfigs = @()
$LogicalNetwork = Get-SCLogicalNetwork -ID $jsonconfignodeconfig.fnmgntlogicalid -Name $jsonconfignodeconfig.fnmgntlogicalname
$NetworkAdapterConfigs += New-SCPhysicalComputerNetworkAdapterConfig -UseStaticIPForIPConfiguration -SetAsManagementNIC -SetAsPhysicalNetworkAdapter `
-MACAddress $vnic1mac.Addr -IPv4Subnet $jsonnic.pria.subnet -LogicalNetwork $LogicalNetwork -IPv4Address $jsonnic.pria.ipv4
# Setup all of the above Vars for New-SCVMHost
Add-Content $log "`n - $(timedate) - Build VMM PS CMD to for deployment."
$VMMHostConfiguration = New-SCPhysicalComputerConfig -BMCAddress $bmcip.id -BMCPort $jsonconfignodeconfig.bmcport -BMCProtocol $jsonconfignodeconfig.bmcprotocol -BMCRunAsAccount $RunAsAccount `
-BypassADMachineAccountCheck -ComputerName $jsonconfignodeconfig.name -Description "" -SMBiosGuid $bmcsmbiosguid.SMBiosGUID -VMHostGroup $HostGroup `
-PhysicalComputerProfile $PhysicalComputerProfile -PhysicalComputerNetworkAdapterConfig $NetworkAdapterConfigs

# Deploy, install , and check
function newscvmnode () {
    New-SCVMHost -VMHostConfig $VMMHostConfiguration -RunAsynchronously -VMMServer $jsonconfignodeconfig.vmmserver
}
function checkscvmjob () {
    # Loop waiting for VMM to complete node deployment
$NewSCVMMHostJob = Get-scjob -VMMServer $jsonconfignodeconfig.vmmserver -All | where {$_.CmdletName -eq "New-SCVMHost" `
 -and $_.Name -EQ "Create a new host from physical machine" -and $_.status -match "Running" -and $_.ResultName -eq $jsonconfignodeconfig.fqdnname} 
$scvmmjobid= $NewSCVMMHostJob.ID
$CheckSCVMMHostJob = Get-scjob -VMMServer $jsonconfignodeconfig.vmmserver -All | where {$_.CmdletName -eq "New-SCVMHost" `
 -and $_.Progress -eq "100 %" -and $_.Name -EQ "Create a new host from physical machine" -and $_.status -match "Completed" `
 -and $_.ResultName -eq $jsonconfignodeconfig.fqdnname} 
While ($NewSCVMMHostJob.Status -eq "Running") {
    Write-Host "Still waiting for $name to finish building. Please stand by!"
	Add-Content $log "`n - $(timedate) - Still waiting for $name to finish building. Please stand by!"
    Start-sleep -s 60
}
Write-host "Node has finished building."
$CheckSCVMMHostJob = Get-scjob -All | where {$_.CmdletName -eq "New-SCVMHost" -and $_.Progress -eq "100 %" -and $_.Name -EQ "Create a new host from physical machine" -and `
$_.status -match "Completed" -and $_.ResultName -eq $jsonconfignodeconfig.fqdnname -and $_.ID -eq $scvmmjobid} 
If ($CheckSCVMMHostJob.ErrorInfo -like "Failed*"){
    $JobErrorInfo = $CheckSCVMMHostJob.ErrorInfo
    Write-host "$name node deployment error $JobErrorInfo"
    Add-Content $log "`n - $(timedate) - $name node deployment error $JobErrorInfo"
    Write-EventLog -ComputerName $jsonconfignodeconfig.eventlogsvr -LogName "Azure-OnPrem" -Source "Applications" -EventID 6003 -EntryType Error -Message "$JobErrorInfo "
}
else { 
    Write-host "Node has finished building successfully."
    Write-EventLog -ComputerName $jsonconfignodeconfig.eventlogsvr -LogName "Azure-OnPrem" -Source "Applications" -EventID 6000 -EntryType Success -Message "Node has finished building successfully at $(timedate)"
}
}
newscvmnode
Start-sleep -s 2
checkscvmjob
Add-Content $log "`n - $(timedate) - Finished VMM BMaaS node deployment of $name"
}
catch
{
    Throw $_.Exception | Out-File "C:\UCSHyperVConfig-Node-exception.txt" #| Write-EventLog -ComputerName $jsonconfignodeconfig.eventlogsvr -LogName "Azure-OnPrem" -Source "Applications" -EventID 6003 -EntryType Error -Message $_.Exception
}

Start-Sleep -s 2
####### END of node deployment #######
###################################################################
###################################################################
###################################################################
####### Start Cisco UCS NIC nameing standard to VICx #######
try
{
Add-Content $log "`n - $(timedate) - Started UCS NICs renaming by MAC on $name"
Get-UcsOrg -Level root -Ucs $UCSHandle
##Getting Service Profile from UUID of Server
##$uuid = (Get-WmiObject Win32_ComputerSystemProduct -ComputerName $hostname -Credential $PCCred).UUID 
# Get UCS IPMI IP and GUID by name
$getrunasacct = Get-SCRunAsAccount -Name $jsonconfignodeconfig.bmcrunas
$getrunasacct 
$RunAsAccount = Get-SCRunAsAccount -Name $getrunasacct.Name -ID $getrunasacct.ID
$RunAsAccount
$bmcip = (Get-UcsIpPoolAddr -Ucs $UCSHandle | where {$_.AssignedToDn -like "*$name*"})
$bmcip
$bmcsmbiosguid = Find-SCComputer  -BMCAddress $bmcip.id -BMCRunAsAccount $RunAsAccount -BMCProtocol $jsonconfignodeconfig.bmcprotocol
##Find the service profile that has that UUID
$serviceprofile = Get-UcsServiceProfile -Ucs $UCSHandle -Name $jsonconfignodeconfig.name 
$serviceprofile
#Begin processing the server
$spWorking = Get-UcsServiceProfile -Ucs $UCSHandle -Type instance | where {$_.name -eq $jsonconfignodeconfig.name } 
$spWorking

$winNicAdapters = $null
if (!($winNicAdapters = Get-WmiObject -ComputerName $jsonconfignodeconfig.name  -Class Win32_NetworkAdapter -ErrorAction SilentlyContinue))
	{
		Write-Output ""
		Write-Output "	Connection to Server $($hostname) failed:"
		Write-Output "    	- Check that the IP address provided matches the Service Profile name"
		Write-Output "    	- You must have administrative priviledges to the target server"
		Write-Output "		- The Windows Firewall must be disabled or WMI rule enabled on the remote server"
		Write-Output ""
		Disconnect-Ucs -ucs $UCSHandle
		Write-Output "Exiting..."
		Add-Content $log "`n - $(timedate) - The server $name is unavaiable and cannot complete UCS NICs renaming."
		exit
	}
else
	{
		Write-Output "OK...Server:$($jsonconfignodeconfig.name): Configuring Physical Nic Names...(Please Wait)"
        #Get server NIC based on MAC address in the service profile...rename.
		$ucsNics = Get-UcsVnic -Ucs $UCSHandle -ServiceProfile $spWorking
		foreach ($ucsNicIn in $ucsNics)
			{	
				$winNicIn = $winNicAdapters | where {($_.MACAddress -eq $ucsNicIn.Addr) -and ($_.ServiceName -ne "VMSMP")}
				$newName = [string]::Format('{0}',$ucsNicIn.Name)
				if ($winNicIn)
					{
						if ($newName -ne $winNicIn.NetConnectionID) 
							{	
								$winNicIn.NetConnectionID = $NewName
								$winNicIn.Put() | Out-Null
							}
					}
				else
					{
						Write-Output ""
						Write-Output "		- Could not find a match for $($ucsNicIn.Name)."
					}
			}
				Write-Output "	Completed checing $name"
}
#Get UCS NICS
$ucsNics = Get-UcsVnic -Ucs $UCSHandle -ServiceProfile $spWorking
#Get Hyper-V NICs
$HyperVNics = GET-WMIOBJECT -ComputerName $jsonconfignodeconfig.name -class Win32_NetworkAdapter -ErrorAction SilentlyContinue | where {$_.PhysicalAdapter -ieq "TRUE" -and $_.MacAddress -ne "" -and $_.ProductName -eq "Hyper-V Virtual Ethernet Adapter"}
foreach ($ucsNicIn in $ucsNics)
	{	
		$HyperVNicIn = $HyperVNics | where {($_.MACAddress -eq $ucsNicIn.Addr) -and ($_.PhysicalAdapter -ieq "TRUE") -and ($_.ProductName -eq "Hyper-V Virtual Ethernet Adapter")}
		$newName = [string]::Format('{0}','Hyper-V vSwitch('+$ucsNicIn.Name+')')
		if ($HypervNics)
			{
				if ($newName -ne $HyperVNicIn.NetConnectionID) 
					{	
						$HyperVNicIn.NetConnectionID = $NewName
						$HyperVNicIn.Put() | Out-Null
					}
			}
	}
Write-Output "	Completed UCS NIC renaming"
Add-Content $log "`n - $(timedate) - Finished UCS NIC renaming on $name"
}
catch
{
    Throw $_.Exception | Out-File "C:\UCS-NICRename-exception.txt" # Write-EventLog -ComputerName $jsonconfignodeconfig.eventlogsvr -LogName "Azure-OnPrem" -Source "Applications" -EventID 6003 -EntryType Error -Message $_.Exception
}

start-sleep -s 3
####### END Cisco UCS NIC nameing standard to VICx #######
###################################################################
###################################################################
###################################################################
####### Start Hyper-V Server Configurations #######
# Handle erros test JSON for errors
try
{
Add-Content $log "`n - $(timedate) - Using CredSSP to establishing a remote connection. Starting Hyper-V server configurations on $name"
# Configure windows basics
Invoke-Command -ComputerName $jsonconfignodeconfig.fqdnname -ScriptBlock {
Function timedate (){
	get-date
}
$starttime = (get-date)
# Log file
$log = "C:\node-build-log.txt"
timedate | Out-File $log

Add-Content $log "`n - $(timedate) - Starting Hyper-V server configurations on $name"   
# Copy JSON file to local Computer remotly
$url = " http://AZCLMGMTAPP01.cloudlab.local/UCSHyperVConfig.json"
$request = 'C:\UCSHyperVConfig.json'
#Invoke-WebRequest $request
Invoke-WebRequest -Uri $url -OutFile $request
Start-Sleep -s 2

# Retest JSON file
$request = 'C:\UCSHyperVConfig.json' 
$JSONRaw = Get-Content -Raw -Path $request
$JSONRaw 
$jsonconfig = Get-Content -Raw $request | Out-String | ConvertFrom-Json | Select-Object -expand config
$jsonconfig
$jsonconfignodeconfig = Get-Content -Raw $request | Out-String | ConvertFrom-Json | Select-Object -expand config| Select-Object -expand nodeconfig
$jsonconfignodeconfig
$jsonconfigrenamenics = Get-Content -Raw $request | Out-String | ConvertFrom-Json | Select-Object -expand config | Select-Object -expand renamenics
$jsonconfigrenamenics
$jsonconfignewhvsw = Get-Content  -Raw $request | Out-String | ConvertFrom-Json | Select-Object -expand config | Select-Object -expand newhvsw
$jsonconfignewhvsw
$jsonnic = Get-Content  -Raw $request | Out-String | ConvertFrom-Json | Select-Object -expand config | Select-Object -expand setNicIp
$jsoncluster = Get-Content  -Raw $request | Out-String | ConvertFrom-Json | Select-Object -expand config | Select-Object -expand cluster
$jsoncluster

# Var name size reduction
$eventlogsvr = $jsonconfignodeconfig.eventlogsvr
$PrimaryA = $jsonconfigrenamenics.nicPAname
$PrimaryB = $jsonconfigrenamenics.nicPBname
$FrontnetA = $jsonconfigrenamenics.nicFNAname
$FrontnetB = $jsonconfigrenamenics.nicFNBname
$BacknetA = $jsonconfigrenamenics.nicBNAname
$BacknetB = $jsonconfigrenamenics.nicBNBname
$LiveMigrationA = $jsonconfigrenamenics.nicLMAname
$LiveMigrationB = $jsonconfigrenamenics.nicLMBname
$hvswFrontNet = $jsonconfignewhvsw.swchFNname
$hvswBackNet = $jsonconfignewhvsw.swchBNname

# Rename NICs
$nicPrimaryA = (Get-NetAdapter -name "VNIC1" | Rename-NetAdapter -NewName $PrimaryA)
$nicPrimaryB = (Get-NetAdapter -name "VNIC2" | Rename-NetAdapter -NewName $PrimaryB)
$nicFrontnetA = (Get-NetAdapter -name "VNIC3" | Rename-NetAdapter -NewName $FrontnetA)
$nicFrontnetB = (Get-NetAdapter -name "VNIC4" | Rename-NetAdapter -NewName $FrontnetB)
$nicLiveMigrationA = (Get-NetAdapter -name "VNIC5" | Rename-NetAdapter -NewName $LiveMigrationA)
$nicLiveMigrationB = (Get-NetAdapter -name "VNIC6" | Rename-NetAdapter -NewName $LiveMigrationB)
$nicBacknetA = (Get-NetAdapter -name "VNIC7" | Rename-NetAdapter -NewName $BacknetA)
$nicBacknetB = (Get-NetAdapter -name "VNIC8" | Rename-NetAdapter -NewName $BacknetB)
Add-Content $log "`n - $(timedate) - Finished renameing NICs to legacy TWC naming standards fron UCS VIC standards on $name"
Add-Content $log "`n - $(timedate) - Starting basic OS configurations...."
Add-Content $log "`n - $(timedate) - ....Sync time, install features and roles, setup CredSSP and RDP, $name"
# Make sure time is synced
w32tm.exe /resync /force
# Install roles
Get-WindowsFeature -name "Hyper-V","Hyper-V-PowerShell", "Hyper-V-Tools", "Failover-Clustering", "Multipath-IO"
install-WindowsFeature –Name "Hyper-V","Hyper-V-PowerShell", "Hyper-V-Tools", "Failover-Clustering", "Multipath-IO" -IncludeManagementTools
Add-Content $log "`n - $(timedate) - Windows features have been added."
# Enable remote desktop
set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup “Remote Desktop”
set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name “UserAuthentication” -Value 1  
Add-Content $log "`n - $(timedate) - Windows Remote Desktop has been enabled and allowed through the firewall." 
# Make sure CredSSP is enabled
#Enable-WSManCredSSP -Role client -DelegateComputer * -force
Enable-WSManCredSSP -Role Server -force
Set-ExecutionPolicy Unrestricted -force
Add-Content $log "`n - $(timedate) - CredSSP and Execution Policy have been set."
Start-Sleep -Seconds 2

# Create New Hyper-V Switchs
New-VMSwitch -name $hvswFrontNet -NetAdapterName $FrontnetA -AllowManagementOS $false
New-VMSwitch -name $hvswBackNet  -NetAdapterName $BacknetA -AllowManagementOS $false
Add-Content $log "`n - $(timedate) - Finished creating Hyper-V switches on $name"
Start-Sleep -Seconds 4

# Set IP Address and DNS
New-NetIPAddress –InterfaceAlias $PrimaryA -IPAddress $jsonnic.pria.ipv4 –PrefixLength $jsonnic.pria.mask -DefaultGateway $jsonnic.pria.gateway
    Set-DnsClientServerAddress -InterfaceAlias $PrimaryA -ServerAddresses $jsonnic.pria.dns1, $jsonnic.pria.dns2
New-NetIPAddress –InterfaceAlias $PrimaryB -IPAddress $jsonnic.prib.ipv4 –PrefixLength $jsonnic.prib.mask 
    #Set-DnsClientServerAddress -InterfaceAlias $PrimaryB -ServerAddresses $jsonnic.prib.dns1, $jsonnic.prib.dns2
New-NetIPAddress –InterfaceAlias $LiveMigrationA -IPAddress $jsonnic.livea.ipv4 –PrefixLength $jsonnic.livea.mask
    #Set-DnsClientServerAddress -InterfaceAlias $LiveMigrationA -ServerAddresses $jsonnic.livea.dns1, $jsonnic.livea.dns2
New-NetIPAddress –InterfaceAlias $LiveMigrationB -IPAddress $jsonnic.liveb.ipv4 –PrefixLength $jsonnic.liveb.mask 
    #Set-DnsClientServerAddress -InterfaceAlias $LiveMigrationB -ServerAddresses $jsonnic.liveb.dns1, $jsonnic.liveb.dns2    
Add-Content $log "`n - $(timedate) - Finished setting static IP's on $name"
# Configure Hyper-V default settings
SET-VMHOST –computername $jsonconfignodeconfig.fqdnname –virtualharddiskpath $jsonconfignodeconfig.hvvhdpath –virtualmachinepath $jsonconfignodeconfig.hvvmpath
Set-VMHost -MaximumVirtualMachineMigrations $jsonconfignodeconfig.hvmaxvmmigrations -MaximumStorageMigrations $jsonconfignodeconfig.hvmaxstormigrations
Add-Content $log "`n - $(timedate) - Finished configuring networking on $name"
Add-Content $log "`n - $(timedate) - Finished with $name Hyper-V server configurations."
}
}
catch
{
    Throw $_.Exception | Out-File "C:\HyperVConfig-Run-exception.txt" # Write-EventLog -ComputerName $jsonconfignodeconfig.eventlogsvr -LogName "Azure-OnPrem" -Source "Applications" -EventID 6003 -EntryType Error -Message $_.Exception
}

try
{
Start-Sleep -Seconds 2
# Join node to existing Hyper-v Cluster
Get-Cluster  $jsoncluster.clustername | Add-ClusterNode -name $jsonconfignodeconfig.fqdnname
Start-Sleep -Seconds 6
$clustname = $jsoncluster.clustername
$getclusterstatus = get-clusternode -Cluster $jsoncluster.clustername# | Out-File "C:\HyperVConfig-Cluster-status.txt"
$getclusterstatus
Add-Content $log "`n - $(timedate) - Joining $name to the $clustname cluster."
Write-EventLog -ComputerName $jsonconfignodeconfig.eventlogsvr -LogName "Azure-OnPrem" -Source "Applications" -EventID 7000 -EntryType Information -Message "The node $name has been fully build and added to the $clustname cluster. Members of the cluster is $getclusterstatus"
Write-Host "The node $name has been fully built and has been added to the $clustname cluster. Members of the cluster are $getclusterstatus"
Add-Content $log "`n - $(timedate) - Finished joining $name to the $clustname cluster. Members of the cluster is $getclusterstatus"
Add-Content $log "`n - $(timedate) - $name has been fully built. You may now login to the server."
}
catch
{
    Throw $_.Exception | Out-File "C:\HyperVConfig-Cluster-exception.txt" # Write-EventLog -ComputerName $jsonconfignodeconfig.eventlogsvr -LogName "Azure-OnPrem" -Source "Applications" -EventID 6003 -EntryType Error -Message $_.Exception
}
# Disconnect UCS Handle
Disconnect-Ucs -ucs $UCSHandle
Add-Content $log "`n - $(timedate) - BMaaS has been brought to you by VMM, WDS, Hyper-V, Clustering, Cisco UCS, EMC, and Brocade"
$endtime = (get-date)
"Elapsed Time: $(($endtime-$starttime).totalseconds / 60) minutes and seconds"
Add-Content $log "`n - Total BMaaS run time was $(($endtime-$starttime).totalseconds / 60) minutes and seconds"

$EmailTo = "yourr@email.com"
$EmailFrom = "noreply-BMaaS@email.com"
$Subject = "BMaaS Node Completed"
$Body = "BMaaS has complted building $fqdn wtih IP $nodeip and is ready for login and load."
$SMTPServer = "mailrelay.email.com"
$filenameAndPath = $log
$SMTPMessage = New-Object System.Net.Mail.MailMessage($EmailFrom,$EmailTo,$Subject,$Body)
$attachment = New-Object System.Net.Mail.Attachment($filenameAndPath)
$SMTPMessage.Attachments.Add($attachment)
$SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 25) 
$SMTPClient.EnableSsl = $false 
$SMTPClient.Credentials = New-Object System.Net.NetworkCredential("Anonymous", ""); 
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
$SMTPClient.Send($SMTPMessage)

###################################################################
###################################################################
###################################################################
<#
Work that needs to be done is checking for ucs profile copy status, 
validation of node and cluster after join.
#>
