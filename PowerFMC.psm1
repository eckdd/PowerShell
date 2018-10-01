#############################################################################################################
#############################################################################################################
#############################################################################################################

function Get-FMCAuthToken {
<#
 .SYNOPSIS
Obtains Domain UUID and X-auth-access-token
 .DESCRIPTION
This cmdlet will invoke a REST post against the FMC API, authenticate, and provide an X-auth-access-token and
Domain UUID for use in other functions

 .EXAMPLE
# Get-FMCAuthToken -fmcHost 'https://fmcrestapisandbox.cisco.com' -username 'davdecke' -password 'YDgQ7CBR'

 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER username
REST account username
 .PARAMETER password
REST account password

/#>

    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$fmcHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$username,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$password

    )
Begin {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
     }
Process {
$credPair = "$($username):$($password)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$uri = "$fmcHost/api/fmc_platform/v1/auth/generatetoken"
$headers = @{ Authorization = "Basic $encodedCredentials" }

$AuthResponse = Invoke-WebRequest -Uri $uri -Headers $headers -Method Post

$Domain =  $AuthResponse.Headers.Item('DOMAIN_UUID')
$AuthAccessToken = $AuthResponse.Headers.Item('X-auth-access-token')
        }
End {
$output = New-Object -TypeName psobject
$output | Add-Member -MemberType NoteProperty -Name fmcHost         -Value $fmcHost
$output | Add-Member -MemberType NoteProperty -Name Domain          -Value $Domain
$output | Add-Member -MemberType NoteProperty -Name AuthAccessToken -Value $AuthAccessToken
$output
    }
}

#############################################################################################################
#############################################################################################################
#############################################################################################################

function Get-FMCNetworkObjects {
<#
 .SYNOPSIS
Displays network objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networks
 .EXAMPLE
# Get-FMCNetworkObjects -fmcHost "https://fmcrestapisandbox.cisco.com" -username 'davdecke' -password 'xxxxxx'

 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
/#>

    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$fmcHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain
    )
Begin {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
      }
Process {
$uri = "$fmcHost/api/fmc_config/v1/domain/$Domain/object/networks"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$NetObjects = @()
$response.items.links.self | foreach {
    $NetObjects += Invoke-RestMethod -Method Get -Uri $_ -Headers $headers
                                     }
        }
End {
$NetObjects 
    }
}

#############################################################################################################
###################5##########################################################################################
#############################################################################################################

function New-FMCNetworkObject {
<#
 .SYNOPSIS
Create network objects in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networks
 .EXAMPLE
# $fmcHost = 'https://fmcrestapisandbox.cisco.com'
# $a = Get-FMCAuthToken -fmcHost $fmcHost -username 'davdecke' -password 'xxxxxx'
# $a | New-FMCNetworkObject -fmcHost $fmcHost -name 'PowerFMC_172.21.33.0/24' -Network "172.21.33.0" -Prefix 24 -description "Test Object for PowerFMC 2"

 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Network
The network or host dotted-decimal IP
 .PARAMETER Prefix
Prefix length for network (32 for host)
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$fmcHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$name,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$overridable="false",
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("network","host","range")]
            [string]$type="network",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Network
    )
Begin {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
$uri = "$fmcHost/api/fmc_config/v1/domain/$Domain/object/networks"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
$name = $name -replace '(\\|\/|\s)','_'

$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name name        -Value $name
$body | Add-Member -MemberType NoteProperty -name value       -Value "$Network"
$body | Add-Member -MemberType NoteProperty -name overridable -Value $overridable
$body | Add-Member -MemberType NoteProperty -name description -Value "$description"
$body | Add-Member -MemberType NoteProperty -name type        -Value $type
 
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
$response
        }
End {}
}

#############################################################################################################
#############################################################################################################
#############################################################################################################

function Get-FMCNetworkGroups {
<#
 .SYNOPSIS
Displays network groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and retrieve items under /object/networkgroups
 .EXAMPLE
# Get-FMCNetworkObjects -fmcHost "https://fmcrestapisandbox.cisco.com" -AuthAccessToken 'e276abec-e0f2-11e3-8169-6d9ed49b625f' -Domain '618846ea-6e3e-4d69-8f30-55f31b52ca3e'

 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
/#>

    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$fmcHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain
    )
Begin {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
      }
Process {
$uri = "$fmcHost/api/fmc_config/v1/domain/$Domain/object/networkgroups"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" }
$response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
$NetObjects = @()
$response.items.links.self | foreach {
    $NetObjects += Invoke-RestMethod -Method Get -Uri $_ -Headers $headers

        }
$NetObjects
}

End {}
}

#############################################################################################################
#############################################################################################################
#############################################################################################################

function New-FMCNetworkGroup {
<#
 .SYNOPSIS
Create network groups in FMC
 .DESCRIPTION
This cmdlet will invoke a REST request against the FMC API and create Network Groups
 .EXAMPLE
# $fmcHost = 'https://fmcrestapisandbox.cisco.com'
# $a = Get-FMCAuthToken -fmcHost $fmcHost -username 'davdecke' -password 'xxxxxx'
# $a | New-FMCNetworkGroup -fmcHost $fmcHost -name 'PowerFMC_TestGroup' -members 'PowerFMC_TestObj1,PowerFMC_TestObj2,PowerFMC_TestObj3' -description "Group for PowerFMC"

 .PARAMETER fmcHost
Base URL of FMC
 .PARAMETER AuthAccessToken
X-auth-accesss-token 
 .PARAMETER Domain
Domain UUID 
 .PARAMETER name
Name of the rule. Illegal characters (/,\,whitespaces) are automatically replaced with underscrores 
 .PARAMETER Network
The network or host dotted-decimal IP
 .PARAMETER Prefix
Prefix length for network (32 for host)
/#>
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$name,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$members,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$description,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [string]$overridable="false",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$fmcHost,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$Domain,
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$AuthAccessToken

    )
Begin {
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
[System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'
        }
Process {
$uri = "$fmcHost/api/fmc_config/v1/domain/$Domain/object/networkgroups"
$headers = @{ "X-auth-access-token" = "$AuthAccessToken" ;'Content-Type' = 'application/json' }
$name = $name -replace '(\\|\/|\s)','_'
$members = $members -split ','
$literals = @()
$members | foreach {
    $literal = New-Object -TypeName psobject
    $literal | Add-Member -MemberType NoteProperty -Name value -Value $_
    $literals += $literal
                    }

$body = New-Object -TypeName psobject
$body | Add-Member -MemberType NoteProperty -name type        -Value "NetworkGroup"
$body | Add-Member -MemberType NoteProperty -name literals    -Value $literals
$body | Add-Member -MemberType NoteProperty -name overridable -Value $overridable
$body | Add-Member -MemberType NoteProperty -name description -Value "$description"
$body | Add-Member -MemberType NoteProperty -name name       -Value  "$name"
 
$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body ($body | ConvertTo-Json)
$response
        }
End {}
}

#############################################################################################################
#############################################################################################################
#############################################################################################################



