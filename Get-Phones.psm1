function Get-Phones {
<#
 .SYNOPSIS
Scans a network containing Cisco IP Phones with the built-in web interface enabled and outputs information about the endpoint accessible from the phone's web page.
 .DESCRIPTION
This cmdlet will query the web interface on Cisco IP Phones and outputs to ether the console or a CSV the following information: IP address, whether DHCP is enabled, MAC Address, Hostname, Domain Name, Phone Number, Serial Number, model, Software Version, and Time zone

This cmdlet can operate on several phones at once.
 .EXAMPLE
# Scans the 192.168.1.64/26 network 30 devices at a time and outputs the information to the file Phones.csv 
Get-Phones -NetworkID 192.168.1.64 -PrefixLength 26 -OutFile Phones.csv -MaxConnections 30

# Scans the 192.168.1.0/24 network 10 phones at a time and outputs the information to variable $Phones
$Phones = Get-Phones -NetworkID 192.168.1.0 -SecureWeb

# Scans the 192.168.0.128/25 network using HTTPS and outputs to the console.
Get-Phones -NetworkID 192.168.0.128 -SubnetMask 255.255.255.128 -SecureWeb

 .PARAMETER NetworkID
Network ID of the subnet to be scanned
 .PARAMETER PrefixLength
Subnet mask in prefix notation for the network to be scanned. 
 .PARAMETER SubnetMask
Subnet mask in dotted-decimal format for the network to be scanned. If both the SubnetMask and PrefixLength parameter are omitted, the Subnet Mask is 255.255.255.0 (/24).
 .PARAMETER SecureWeb
Specifies that the scan to use HTTPS when connecting to phone endpoints.
 .PARAMETER OutFile
Path/File name of the output csv, if desired. If omitted, output is directed to the console.
 .PARAMETER MaxConnections
Maximum number of concurrent phones to query at a time (Default is 10).
/#>



    param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
            [Net.IPAddress]$NetworkID,
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
            [string]$OutFile,
            [int]$MaxConnections=10,
            [int]$PrefixLength,
            [Net.IPAddress]$SubnetMask="255.255.255.0",
            [switch]$SecureWeb
    )
    
    process {
        if ($Prefixlength -ge 32)
        {
            $m4 = 255
        } else
            {
                $m4 = 256 - ([math]::Pow(2,((32 - $Prefixlength))))
            }
    if ($Prefixlength -ge 24)
        {
            $m3 = 255
        } else
            {
                $m3 = 256 - ([math]::Pow(2,((24 - $Prefixlength))))
                $m4 = 0
            }
    if ($Prefixlength -ge 16)
        {
            $m2 = 255
        } else
            {
                $m2 = 256 - ([math]::Pow(2,((16 - $Prefixlength))))
                $m3 = 0
                $m4 = 0
            }
    if ($Prefixlength -ge 8)
        {
            $m1 = 255
        } else
            {
                $m1 = 256 - ([math]::Pow(2,((8 - $Prefixlength))))
                $m2 = 0
                $m3 = 0
                $m4 = 0
            }
            
    [Net.IPAddress]$prefSubnetMask="$m1.$m2.$m3.$m4" 
    if ($prefSubnetMask.ToString() -eq "0.0.0.0") { 
        $SubnetMask = $SubnetMask
            } else { $SubnetMask = $prefSubnetMask }

    [int]$ipOct1          = $NetworkID.GetAddressBytes()[0]
    [int]$ipOct2          = $NetworkID.GetAddressBytes()[1]
    [int]$ipOct3          = $NetworkID.GetAddressBytes()[2]
    [int]$ipOct4          = $NetworkID.GetAddressBytes()[3]
    
    [int]$nmOct1          = $SubnetMask.GetAddressBytes()[0]
    [int]$nmOct2          = $SubnetMask.GetAddressBytes()[1]
    [int]$nmOct3          = $SubnetMask.GetAddressBytes()[2]
    [int]$nmOct4          = $SubnetMask.GetAddressBytes()[3]
    
    $ipList = @()
    $ipOct1..($ipOct1+(255-$nmOct1)) | foreach {
        $a = $_ 
        $ipOct2..($ipOct2+(255-$nmOct2)) | foreach {
            $b = $_
            $ipOct3..($ipOct3+(255-$nmOct3)) | foreach {
                $c = $_
                    $ipOct4..($ipOct4+(255-$nmOct4)) | foreach {
                    $d = $_
                    $ipList += "$a.$b.$c.$d"
    }
        }
            }
                } 
        $WebProt = "HTTP"        
        if ($SecureWeb) { $WebProt = "HTTPS" }
        $ErrorActionPreference = "SilentlyContinue"
        Get-Job | Remove-Job
        $ipList  | foreach {
        
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
            
            $IPAddr    = $_
            Start-Job -ScriptBlock {
                $client = New-Object System.Net.WebClient
                $IPAddr = $args[0]
                $WebProt= $args[1]
                $html   = $client.DownloadString("$WebProt`://$IPAddr")
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
                
                $html   = $client.DownloadString("$WebProt`://$IPAddr/CGI/Java/Serviceability?adapter=device.statistics.configuration")
                $html   = $html -replace "<[^>*?|<[^>]*>", ","
                $html   = $html -split ', '
                $html   = $html -replace ',,,,,', ''
                
                $DName  = $html | Select-String -Pattern "Domain Name,"
                $Dhcp   = $html | Select-String -Pattern "DHCP,"
                
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
                } -ArgumentList $IPAddr,$WebProt
            Write-Progress -Activity "Running Jobs" -Status $IPAddr
            } | Out-Null
            Get-Job | Wait-Job | Out-Null
            $Phones = Get-Job -State Completed | Receive-Job
            $Phones = $Phones | select IPAddr,DHCP,MACAddr,DomainName,HostName,PhoneDN,Serial,Model,Version,TimeZone | sort
            if ($OutFile) { $Phones | Export-Csv -Path $OutFile -NoClobber -NoTypeInformation -Force } 
             else { $Phones }
            Get-Job | Stop-Job |Out-Null
        }
}
