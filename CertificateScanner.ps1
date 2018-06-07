<#
.SYNOPSIS
Checks certificates on multiple servers

.DESCRIPTION
Lorem Ipsum

Based on https://stackoverflow.com/questions/39253055/powershell-script-to-get-certificate-expiry-for-a-website-remotely-for-multiple

.EXAMPLE
Lorem Ipsum

#>

Param
(
    $minimumCertAgeDays = 60,
    $timeoutMilliseconds = 200,
    [string[]]$ports = (443,8834),
    [string[]]$urls = (get-content .\servers.txt)
)

$results = @()

[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::ssl3;

function Get-Certificate
{
    Param
    (
        [String]$url,
        [String]$timeoutMilliseconds
    )

    $req = [Net.HttpWebRequest]::Create($url)
    $req.Timeout = $timeoutMilliseconds
    $req.AllowAutoRedirect = $false
    
    try 
    {
        $req.GetResponse() |Out-Null
    } 
    catch {
        #Write-Host Exception while checking URL $url`:$port $_ -f Red
    }

    return $req
}

function Parse-Certificate
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
            #Write-Host Exception while parsing cert $url`: $_ -f Red
        }

        if ($certName) 
        {
            try 
            {
                #Write-Host Getting hostname
                $dnsname = [System.Net.Dns]::GetHostEntry($url).HostName       
            }
            catch
            {
                $dnsname = ""
            }
        }

        if ($certName) 
        {
            $details =[ordered] @{            
                Host = $url
                Port = $port
                Hostname = $dnsname       
                CommonName = [system.String]::Join(" ", $certName -match "CN=") -replace ".*CN="
                Issuer = $certIssuer
                Creation = $certEffectiveDate
                Expiration = $certExpires
                Thumbprint = $certThumbprint
                Serialnumber = $certSerialNumber
            }
            return $details
        }
}

foreach ($url in $urls)
{
    Write-Progress -Activity "Checking certificates" -status "Checking $url" -percentComplete ($urls.IndexOf($url) / $urls.count*100)

    foreach ($port in $ports)
    {
        # Make sure that we have cleared out all the variables
        $details = $dnsname = $certExpires = $certName = $certPublicKeyString = $certSerialNumber = $certThumbprint = $certEffectiveDate = $certIssuer = $null
        
        $targetUrl = "https://" + $url + ":" + $port
        
        $req = Get-Certificate -url $targetUrl -timeoutMilliseconds $timeoutMilliseconds

        $details = Parse-Certificate -req $req
        
        try
        #if ($req.ServicePoint.Certificate.GetCertHashString())
        {
            $results += New-Object PSObject -Property $details
            $details  
        }
        catch 
        {
            # We did not receive any data. 
        }
    }
}

$results | export-csv -Path ./results.csv -NoTypeInformation