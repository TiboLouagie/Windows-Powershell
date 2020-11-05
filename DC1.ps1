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

New-NetIPAddress -IPAddress 192.168.1.89 `-PrefixLength 24 `-DefaultGateway 192.168.1.1 `-InterfaceAlias Ethernet0Disable-NetAdapterBinding -Name "Ethernet0" -ComponentID ms_tcpip6
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddress "192.168.1.89"
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
            -DnsDomain mijnschool.local `
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
#======1.8======
#region Users en OU's toevoegen

#Maak OU's met CSV bestand



#endregion