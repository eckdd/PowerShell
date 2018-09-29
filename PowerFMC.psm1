

function Get-FMCNetworkObjects {
<#
 .SYNOPSIS
Displays network objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networks

This cmdlet can operate on several phoens at once.
 .EXAMPLE
# Get-FMCNetworkObjects -fmcHost "https://fmcrestapisandbox.cisco.com" -username 'davdecke' -password 'xxxxxx'

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
