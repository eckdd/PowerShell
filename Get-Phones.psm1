function Get-Phones {
<#
 .SYNOPSIS
Creates CSV containing information from multiple Cisco IP phone web interfaces.
 .DESCRIPTION
This cmdlet will query the web interface on Cisco IP Phones and create a CSV that contains teh IP address, whether DHCP is enabled, MAC Address, Hostname, Domain Name, Phone Number, Serial Number, mOdel, Sofware Version, and Timezone

This cmdlet can operate on several phoens at once.
 .EXAMPLE
# Scans the 192.168.64/26 network 30 devices at a time and outputs the information to the file Phones.csv 
Get-Phones -NetworkID 192.168.1.64 -PrefixLength 26 -OutFile Phones.csv -MaxConnections 30

# Scans the 192.168.1.0/24 network 10 phones at a time and outputs the information to varialbe $Phones
 .PARAMETER NetworkID
Network ID of the subnet to be scanned
 .PARAMETER PrefixLenght
Subnet mask in prefix notation for the network to be scanned (Default is /24). Must be between 24-32.
 .PARAMETER OutFile
Path/File name of the output csv, if desired.
 .PARAMETER MaxConnections
Maximum number of concurrent phones to query (Default is 10).
/#>


    param
    (
        [parameter(Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true
        )]
        [string]$NetworkID,
        [int]$PrefixLength=24,
        [string]$OutFile,
        [int]$MaxConnections=10
    )
    
    process {
    
    $Network            = $NetworkID -split ".", 0, "simplematch"
    [int]$PrefixLength  = 32 - $Prefixlength
    [int]$Oct1          = $Network[0]
    [int]$Oct2          = $Network[1]
    [int]$Oct3          = $Network[2]
    [int]$Oct4          = $Network[3]
    [int]$StartIP       = $Oct4
    [int]$EndIP         = $StartIP + ([math]::Pow( 2, $PrefixLenght )) - 2
    
        $ErrorActionPreference = "SilentlyContinue"
        Get-Job | Remove-Job
        $Range  = $StartIP..$EndIP
        $Range  = foreach {
        
            $RunningJobs = (Get-Job -State Running | measure).Count
            while ( $RunningJobs -ge $MaxConnections ) {
                Start-Sleep -Seconds 4
                $RunningJobs = (Get-Job -State Running | measure).Count
                }
                
            $html       = @()
            $dhcp       = @()
            $MACAddr    = @()
            $HostName   = @()
            $DName      = @()
            $PhoneDN    = @()
            $Serial     = @()
            $Model      = @()
            $Version    = @()
            $TimeZone   = @()
            $IPAddr     = @()
            
            [int]$Oct4 = [int]$Oct4 -replace "$Oct4",$_
            $IPAddr    = "$Oct1.$Oct2.$Oct3.$Oct4"
            Start-Job -ScriptBlock {
                $client = New-Object System.Net.WebClient
                $IPAddr = $args[0]
                
                $html   = $client.DownloadString("http://$IPAddr")
                $html   = $html -replace "<[^>*?|<[^>]*>", ","
                $html   = $html -split ', '
                $html   = $html -replace ',,,,,', ''
                
                $MACAddr    = $html | Select-String -Pattern "MAC Address"
                $HostName   = $html | Select-String -Pattern "Host Name"
                $PhoneDN    = $html | Select-String -Pattern "Phone DN"
                $Serial     = $html | Select-String -Pattern "Serial Number"
                $Model      = $html | Select-String -Pattern "Model Number"
                $Version    = $html | Select-String -Pattern "Version"
                $TimeZone   = $html | Select-String -Pattern "Time Zone"
                
                $MACAddr    = $MACAddr  -replace "MAC Address,",""
                $HostName   = $HostName -replace "Host Name,",""
                $PhoneDN    = $PhoneDN  -replace "Phone DN,",""
                $Serial     = $serial   -replace "Serial Number,",""
                $Model      = $Model    -replace "Model Number,",""
                $Version    = $Version  -replace "Version,",""
                $TimeZone   = $TimeZone -replace "Time Zone,",""
                
                $html   = $client.DownloadString("http://$IPAddr/CGI/Java/Serviceability?adapter=device.statistics.configuration")
                $html   = $html -replace "<[^>*?|<[^>]*>", ","
                $html   = $html -split ', '
                $html   = $html -replace ',,,,,', ''
                
                $DName  = $html | Select-String -Pattern "Domain Name",""
                $Dhcp   = $html | Select-String -Pattern "DHCP,",""
                
                $DName  = $DName    -replace "Domain Name,",""
                $Dhcp   = $Dhcp     -replace "DHCP,",""
                
                $Phone = New-Object -TypeName PSObject
                $Phone | Add-Member -MemberType NoteProperty -Name IPAddr       -Value $IPAddr
                $Phone | Add-Member -MemberType NoteProperty -Name DHCP         -Value $Dhcp
                $Phone | Add-Member -MemberType NoteProperty -Name MACAddr      -Value $MACAddr
                $Phone | Add-Member -MemberType NoteProperty -Name HostName     -Value $HostName
                $Phone | Add-Member -MemberType NoteProperty -Name DomainName   -Value $DName
                $Phone | Add-Member -MemberType NoteProperty -Name PhoneDN      -Value $PhoneDN
                $Phone | Add-Member -MemberType NoteProperty -Name Serial       -Value $Serial
                $Phone | Add-Member -MemberType NoteProperty -Name Model        -Value $Model
                $Phone | Add-Member -MemberType NoteProperty -Name Version      -Value $Version
                $Phone | Add-Member -MemberType NoteProperty -Name TimeZone     -Value $TimeZone
                
                $Phone
                } -ArgumentList $IPAddr
            Write-Progress -Activity "Running Jobs" -Status $IPAddr
            } | Out-Null
            Get-Job | Wait-Job | Out-Null
            $Phones = Get-Job -State Completed | Receive-Job
            $Phones = $Phones | select IPAddr,DHCP,MACAddr,DomainName,HostName,PhoneDN,Serial,Model,Version,TimeZone | sort
            $Phones | Export-Csv -Path $OutFile -NoClobber -NoTypeInformation -Force
            $Phones
            Get-Job | Stop-Job |Out-Null
        }
}
