<#
.SYNOPSIS
Checks certificates on multiple hosts, outputs details to a csv. 

.DESCRIPTION
Connects to multiple hosts and parses the certificate. Writes the result to a .csv file.  

Thanks to the Research Council of Norway for allowing me to Open Source this project and continue to work on it. 

Inspired by https://stackoverflow.com/questions/39253055/powershell-script-to-get-certificate-expiry-for-a-website-remotely-for-multiple

.EXAMPLE
.\CertificateScanner.ps1 -targets 10.0.0.1

.EXAMPLE
.\CertificateScanner.ps1 -targets 10.0.0.1,10.0.0.2 -ports 443,8443 -timeout 500

.EXAMPLE
.\CertificateScanner.ps1 -targets .\servers.txt -ports 443,8443 -output certs.csv -timeout 500

#>

[CmdletBinding()]Param
(
    #Target servers, input is either separated by comma, or provided as a file.
    [Parameter(Mandatory=$True)]
    [string[]]$targets,
    #Target ports, separated by comma. Defaults to 443. 
    [Parameter(Mandatory=$False)]
    [string[]]$ports = 443,
    #Timeout in milliseconds. Defaults to 200.
    [Parameter(Mandatory=$False)]
    [int]$timeout = 200,
    #Outputfilename. Defaults to results.csv
    [Parameter(Mandatory=$False)]
    [string]$output = "results.csv"
)

$results = @()

[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::ssl3 -bor [Net.SecurityProtocolType]::ssl2;

function Get-Certificate
{
    Param
    (
        [String]$server,
        [String]$timeout
    )

    $req = [Net.HttpWebRequest]::Create($server)
    $req.Timeout = $timeout
    $req.AllowAutoRedirect = $false
    
    try 
    {
        $req.GetResponse() | Out-Null
    } 
    catch {
        #Write-Host Exception while retrieving cert from $server`:$port $_ -f Red
    }

    return $req
}

function Get-CertificateData
{
    Param
    (
        [Net.HttpWebRequest]$request
    )

    try {
        $certExpires = $request.ServicePoint.Certificate.GetExpirationDateString()
        $certName = $request.ServicePoint.Certificate.GetName().Split()
        $certPublicKeyString = $request.ServicePoint.Certificate.GetPublicKeyString()
        $certSerialNumber = $request.ServicePoint.Certificate.GetSerialNumberString()
        $certThumbprint = $request.ServicePoint.Certificate.GetCertHashString()
        $certEffectiveDate = $request.ServicePoint.Certificate.GetEffectiveDateString()
        $certIssuer = $request.ServicePoint.Certificate.GetIssuerName()
    }
    catch {
        #Write-Host Exception while parsing cert from $server`: $_ -f Red
    }

    try 
    {
        $dnsname = [System.Net.Dns]::GetHostEntry($server).HostName
    }
    catch
    {
        $dnsname = ""
        #Write-Host Setting Hostname to blank.
        #Write-Host Exception while retrieving hostname from $server`: $_ -f Red
    }

    $isExpired = $false
    $expirationDate = $certExpires.Split()
    try {
        if ((Get-Date $expirationDate[0].ToDateTime()) -lt (Get-Date)) {
            $isExpired = $true
        }
    }
    catch {
        Write-Host Exception while parsing checking if cert is expired for $server`: $_ -f Red               
    }

    if ($certName) 
    {
        $details =[ordered] @{            
            Host = $server
            Port = $port
            Hostname = $dnsname       
            CommonName = [system.String]::Join(" ", $certName -match "CN=") -replace ".*CN="
            Issuer = $certIssuer
            Creation = $certEffectiveDate
            Expiration = $certExpires
            Thumbprint = $certThumbprint
            Serialnumber = $certSerialNumber
            #IsExpired = $isExpired 
            PublicKey = $certPublicKeyString
        }
        return $details
    }
}

# Check if the $targets parameter is a file
if (Test-Path $targets[0])
{
    $servers = Get-Content $targets
}
else
{
    $servers = $targets
}

foreach ($server in $servers)
{
    foreach ($port in $ports)
    {
        Write-Progress -Activity "Checking certificates" -status "Checking $server`:$port" -percentComplete ($servers.IndexOf($server) / ($servers.count)*100)

        # Make sure that we have cleared out all the variables
        $details = $targetserver = $dnsname = $certExpires = $certName = $certPublicKeyString = $certSerialNumber = $certThumbprint = $certEffectiveDate = $certIssuer = $null
        
        $targetserver = "https://" + $server + ":" + $port
        
        $req = Get-Certificate -server $targetserver -timeout $timeout

        $details = Get-CertificateData -req $req
        
        if ($details)
        {
            $results += New-Object PSObject -Property $details
            $details  
        }
    }
}

$results | Export-Csv -Path $output -NoTypeInformation