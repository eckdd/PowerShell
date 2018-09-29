

function Get-FMCNetworkObjects {
<#
 .SYNOPSIS
Displays network objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networks

This cmdlet can operate on several phoens at once.
 .EXAMPLE
# Get-FMCNetworkObjects -fmcHost "https://fmcrestapisandbox.cisco.com" -username 'davdecke' -password $password

 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER username
REST account username
 .PARAMETER password
REST account password

/#>


    param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
            [string]$fmcHost,
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
            [string]$username,
            [string]$password
    )

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$credPair = "$($username):$($password)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$uri = "$fmcHost/api/fmc_platform/v1/auth/generatetoken"
$headers = @{ Authorization = "Basic $encodedCredentials" }
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'

$AuthResponse = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post

$DOMAIN_UUID =  $AuthResponse.Headers.Item('DOMAIN_UUID')
$AuthAccessToken = $AuthResponse.Headers.Item('X-auth-access-token')

$uri = "$fmcHost/api/fmc_config/v1/domain/$DOMAIN_UUID/object/networks"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }

$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$NetObjects = @()
$response.items.links.self | foreach {
    $NetObjects += Invoke-RestMethod -Method Get -Uri $_ -Headers $headers

        }
$NetObjects | select type,name,value,description | fl

}

function New-FMCNetworkObject {
<#
 .SYNOPSIS
Create network objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networks

This cmdlet can operate on several phoens at once.
 .EXAMPLE
# New-FMCNetworkObject -fmcHost $fmcHost -username davdecke -password $password -name 'PowerFMC_172.21.33.0/24' -Network "172.21.33.0" -Prefix 24 -description "Test Object for PowerFMC 2"

 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER username
REST account username
 .PARAMETER password
REST account password
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Network
The network or host dotted-decimal IP
 .PARAMETER Prefix
Prefix length for network (32 for host)
/#>


    param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
            [string]$fmcHost,
            [string]$name,
            [Net.IPAddress]$Network,
            [ValidateRange(0,32)] 
            [int]$Prefix,
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
            [string]$username,
            [string]$password,
            [string]$description,
            [string]$overridable="false",
            [string]$type="network"
    )

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$credPair = "$($username):$($password)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$uri = "$fmcHost/api/fmc_platform/v1/auth/generatetoken"
$headers = @{ Authorization = "Basic $encodedCredentials" }
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'

$AuthResponse = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post

$DOMAIN_UUID =  $AuthResponse.Headers.Item('DOMAIN_UUID')
$AuthAccessToken = $AuthResponse.Headers.Item('X-auth-access-token')

$uri = "$fmcHost/api/fmc_config/v1/domain/$DOMAIN_UUID/object/networks"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }

$value = "$Network/$Prefix"
$name = $name -replace '(\\|\/|\s)','_'

$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name name        -Value $name
$body | Add-Member -MemberType NoteProperty -name value       -Value "$Network/$Prefix"
$body | Add-Member -MemberType NoteProperty -name overridable -Value $overridable
$body | Add-Member -MemberType NoteProperty -name description -Value "$description"
$body | Add-Member -MemberType NoteProperty -name type        -Value $type
 
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
$response
}
