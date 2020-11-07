#======1.1======
#region - Name Computer RUN ON DC1

Rename-Computer -NewName DC1
Restart-Computer -Wait
#endregion
#======1.2======
#region - Set IP

#static ip instellen

#volgende 2 lijnen voor moest ip al gebruikt worden
#Remove-NetIPAddress -InterfaceAlias "Ethernet0"
#Remove-NetRoute -InterfaceAlias "Ethernet0"

New-NetIPAddress -IPAddress 192.168.1.2 `-PrefixLength 24 `-DefaultGateway 192.168.1.1 `-InterfaceAlias Ethernet0Disable-NetAdapterBinding -Name "Ethernet0" -ComponentID ms_tcpip6
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddress "192.168.1.2"
#endregion
#======1.3======
#region Install AD & DNS

       #Install ADDS Role and Mgt Tools
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
       ##Import ADDSDeployment Module
        Import-Module ADDSDeployment
       ##Install a new AD Forest
        Install-ADDSForest `
	        -CreateDnsDelegation:$false `
	        -DatabasePath "C:\Windows\NTDS" `
	        -DomainMode "WinThreshold" `
	        -DomainName "intranet.mijnschool.be" `
	        -DomainNetbiosName "MIJNSCHOOL" `
	        -ForestMode "WinThreshold" `
	        -InstallDns:$true `
	        -LogPath "C:\Windows\NTDS" `
	        -NoRebootOnCompletion:$false `
	        -SysvolPath "C:\Windows\SYSVOL" `
	        -Force:$true
#endregion
#======1.4======
#region - Set DNS


#Set DNS Forwarder
Set-DnsServerForwarder -IPAddress 172.20.0.2,172.20.0.3 -ComputerName DC1
#creating Reverse Lookup for 192.168.1.0
Add-DnsServerPrimaryZone `    -ComputerName DC1 `    -NetworkId "192.168.1.0/24" `    -ReplicationScope "Forest" -Verbose


#endregion
#======1.6======
#region - UPN suffix

#checks for upn's
Get-ADForest | Format-List UPNSuffixes

#Iedere gebruiker dient te kunnen inloggen op het windows domain met zijn emailadres:
Get-ADForest | Set-ADForest -UPNSuffixes @{add="mijnschool.be"}


#List all AD Users
Get-ADUser -Filter * | Sort-Object Name | Format-Table Name, UserPrincipalName
#Change the UPN for all these users
#$LocalUsers = Get-ADUser -Filter {UserPrincipalName -like '*intranet.mijnschool.be'} -Properties userPrincipalName -ResultSetSize $null
#$LocalUsers | foreach {$newUpn = $_.UserPrincipalName.Replace("intranet.mijnschool.be","mijnschool.be"); $_ | Set-ADUser -UserPrincipalName $newUpn}

#change upn suffix for every user in file
Import-Module ActiveDirectory
$oldSuffix = "intranet.mijnschool.be"
$newSuffix = "mijnschool.be"
Get-Content "C:\files\users.txt" | Get-ADUser | ForEach-Object {
$newUpn = $_.UserPrincipalName.Replace($oldSuffix,$newSuffix)
#$_ | Set-ADUser -UserPrincipalName $newUpn
}

#change upn suffix for every user in ou
Import-Module ActiveDirectory
$oldSuffix2 = "intranet.mijnschool.be"
$newSuffix2 = "mijnschool.be"
$ou = "CN=Users,DC=intranet,DC=mijnschool,DC=be"
Get-ADUser -SearchBase $ou -filter * | ForEach-Object {
$newUpn2 = $_.UserPrincipalName.Replace($oldSuffix2,$newSuffix2)
$_ | Set-ADUser -UserPrincipalName $newUpn2
}


#endregion
#======1.7======
#region Install DHCP


#Install DHCP
Install-WindowsFeature -computerName DC1 -name DHCP -IncludeManagementTools
#Complete Post Configuration
    #Create DHCP Groups (nodig?)
    netsh dhcp add securitygroups

    #Add server into Active Directory
    Add-DhcpServerInDC -IPAddress 192.168.1.2 -DnsName dc1.intranet.mijnschool.be

#Create Initial Scope for 192.168.1.0 subnet
        Add-DhcpServerv4Scope -Name 'First Scope' `
            -ComputerName DC1.intranet.mijnschool.be `
            -StartRange 192.168.1.100 `
            -EndRange 192.168.1.200 `
            -SubnetMask 255.255.255.0 `
            -LeaseDuration 08:00:00
		set-DhcpServerv4OptionValue `
            -ScopeId 192.168.1.0 `
            -ComputerName DC1.intranet.mijnschool.be `
            -DnsDomain intranet.mijnschool.be `
            -router 192.168.1.1 `
            -DnsServer 192.168.1.2

#Create a reservation for DHCP scope (eerste via mac, of tweed ip-ragne excluden)
Add-DhcpServerV4Reservation -ScopeId 192.168.1.0 -IPAddress 192.168.1.8 -ClientId "b8-e9-37-3e-55-86" -Description "Reservation for printer"
Add-Dhcpserverv4ExclusionRange -ScopeId 192.168.1.0 -StartRange 192.168.1.1 -EndRange 192.168.1.10

#Site creatie
New-ADReplicationSite "Kortrijk"
#Eerst site maken op DC2
New-ADReplicationSiteLink -Name "SiteLink" -SitesIncluded Kortrijk #@{Add="Kortrijk"}
New-ADReplicationSubnet -Name "192.168.1.0/24" -Site "Kortrijk"

#Test je werk
Get-ADReplicationSiteLink -Filter *
Get-ADReplicationSubnet -Filter *



#endregion
#======1.8 9 10 11======
#region Adding Users en OU's

#test code

#hoe parameter meegeven, ous.csv veranderen door $FileCSV
#param([parameter(Mandatory=$true)] [String]$FileCSV)

$listOU=Import-CSV ".\OUs.csv" -Delimiter ";"
ForEach($OU in $listOU)
{

try{
$OUName = $OU.Name
$OUDisplayName = $OU.DisplayName
$OUDescription = $OU.Description
$OUPath = $OU.Path

Write-Host -ForegroundColor Yellow $OUName $OUPath

New-ADOrganizationalUnit -Name $OUName -DisplayName $OUDisplayName -Description $OUDescription -Path $OUPath

Write-Host -ForegroundColor Green "OU $OUName created"
}catch{
Write-Host $Error[0].Exception.Message}}
#einde test code

#Maak OU's met CSV bestand
$OUNames = Import-Csv ".\OUs.csv" -Delimiter ";"
 
Foreach ($OU in $OUNames)
{ 
	$Name = $OU.Name
	$DisplayName = $OU.DisplayName
	$Description = $OU.Description
	$Path = $OU.Path

	New-ADOrganizationalUnit -Name $Name -DisplayName $DisplayName  -Description $Description -Path $Path
} 


#Maak Users met CSV bestand
$UserNames = Import-Csv "UserAccounts.csv" -Delimiter ";"

Foreach ($User in $UserNames)
{
    $Name = $User.DisplayName
    $SamAccountName = $User.SamAccountName
    $DisplayName = $User.DisplayName
	$GivenName = $User.DisplayName
	$SurName = $User.SurName
    $HomeDirectory = "\\"+$HomeServer+"\"+$HomeShare+"\"+$User.DisplayName
    $ScriptPath = 'login.bat'
	$Path = $User.DistinguishedName
    $UPName = $User.UserPrincipalName
    $AccountPassword = "P@ssw0rd"

    $AccountPassword = ConvertTo-SecureString $AccountPassword -AsPlainText -force

    New-ADUser -Name $Name -SamAccountName $SamAccountName -DisplayName $DisplayName -GivenName $GivenName -Surname $SurName -HomeDrive $HomeDrive -HomeDirectory $HomeDirectory -ScriptPath $ScriptPath -Path $Path -UserPrincipalName $UPName -AccountPassword $AccountPassword -Enabled:$true
	New-Item -Path $HomeDirectory -type directory -Force
	$acl = Get-Acl $HomeDirectory
	$acl.SetAccessRuleProtection($False, $False)
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($User.SamAccountName,"Modify", "ContainerInherit, ObjectInherit", "None", "Allow")
	$acl.AddAccessRule($rule)
	Set-Acl $HomeDirectory $acl
}

#
# making a share remotely
# - name : homedirs
# - share perms : everyone - full control
# - NTFS perms : Administrators - full control and Authenticated Users - ReadAndExecute on this folder only 
#

$FileServer="MS.local"
$Share="C$"
$Drive="C:"
$Dir="Homedir"
$LocalPath=$Drive+"\"+$Dir
$Path="\\"+$FileServer+"\"+$Share+"\"+$Dir

New-Item -Path $Path -type directory -Force
New-SmbShare -CimSession $FileServer -name $Dir -Path $LocalPath -FullAccess Everyone

$acl = Get-Acl $Path
$acl.SetAccessRuleProtection($True, $False)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)

$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users","ReadAndExecute", "None", "NoPropagateInherit", "Allow")
$acl.AddAccessRule($rule)

Set-Acl $Path $acl

$HomeServer=$FileServer
$HomeShare=$Dir




#endregion
#======2.1 2======
#region MS configuration

#sysprep
Start-Process -FilePath C:\Windows\System32\Sysprep\Sysprep.exe -ArgumentList '/generalize /oobe /shutdown /quiet'
#Name
Rename-Computer -NewName MS
Restart-computer -Force

#Adding to domain
Add-Computer -domainname intranet.mijnschool.be -Credential MIJNSCHOOL\Administrator -restart -Force

#statisch ip
New-netIPAddress -IPAddress 192.168.1.4 `
        -PrefixLength 24 `                    
        -DefaultGateway 192.168.1.1 `
        -InterfaceAlias Ethernet0 
		Disable-NetAdapterBinding -Name "Ethernet0" -ComponentID ms_tcpip6
		Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddress "192.168.1.2"


#share staat puntje hierboven

#endregion
#======3======
#region DC2 configuration

#DC2 configuration
#Sysprep
Start-Process -FilePath C:\Windows\System32\Sysprep\Sysprep.exe -ArgumentList '/generalize /oobe /shutdown /quiet'

#Name
Rename-Computer -NewName DC2
Restart-computer -Force

#Adding to domain
Add-Computer -domainname intranet.mijnschool.be -Credential MIJNSCHOOL\Administrator -restart -Force

#Set IP Address
        New-netIPAddress -IPAddress 192.168.1.3 `
        -PrefixLength 24 `      
			#wordt soms niet goed gedaan
        -DefaultGateway 192.168.1.1 `
        -InterfaceAlias Ethernet0 
		Disable-NetAdapterBinding -Name "Ethernet0" -ComponentID ms_tcpip6
		Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddress "192.168.1.2"

#Configure as secondary DC
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSDomainController -DomainName "intranet.mijnschool.be" -credential $(get-credential)
Set-ADObject "CN=NTDS Settings,CN=DC2,CN=Servers,CN=Kortrijk,CN=Sites,CN=Configuration,DC=mijnschool,DC=local" -Replace@{options='1'}
Set-ADObject -Identity (Get-ADDomainController DC2).ntdssettingsobjectdn -Replace @{options='1'}

#Configure DHCP + replication
Install-WindowsFeature -ComputerName DC2 -name DHCP -IncludeManagementTools
    #On DC1
    Add-DhcpServerInDC -DnsName "DC2.intranet.mijnschool.be" -IPAddress 192.168.1.3
    #Can't be done remotely
    Add-DhcpServerv4Failover -Name "Example_Failover" -ScopeId 192.168.1.0 -PartnerServer DC2 -ComputerName DC1 -LoadBalancePercent 50 -SharedSecret "P@ssw0rd"
#endregion

#github link
#https://github.com/TiboLouagie/Windows-Powershell