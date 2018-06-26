<#
.SYNOPSIS
Certificate Scanner v1.0 

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

.EXAMPLE
.\CertificateScanner.ps1 -targets .\servers.txt -ports 443,8443 -notify smtp -smtpFrom ripley@weyland.com -smtpTo bishop@weyland.com -smtpServer smtp.weyland.com

#>

[CmdletBinding()]Param (
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
    [string]$output = "results.csv",
    [String]$notify,
    [String]$smtpFrom,
    [String]$smtpTo,
    [String]$smtpServer
)

# A container for the certs
$results = @()

# Set some TLS connection settings
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::ssl3;

# Get start time.
$startTime = Get-Date

function Get-Certificate {
    Param (
        [String]$server,
        [String]$timeout
    )

    $req = [Net.HttpWebRequest]::Create($server)
    $req.Timeout = $timeout
    $req.AllowAutoRedirect = $false
    
    Write-Verbose "Checking Cert at $server."

    try {
        $req.GetResponse() | Out-Null
    } 
    catch {
        Write-Verbose "Exception while retrieving cert from $server`:$port $_"
    }

    return $req
}

function Get-CertificateData {
    Param (
        [Net.HttpWebRequest]$request
    )

    try {
        $certExpires = $request.ServicePoint.Certificate.GetExpirationDateString()
        $certName = $request.ServicePoint.Certificate.GetName().Split()
        #$certPublicKeyString = $request.ServicePoint.Certificate.GetPublicKeyString()
        $certSerialNumber = $request.ServicePoint.Certificate.GetSerialNumberString()
        $certThumbprint = $request.ServicePoint.Certificate.GetCertHashString()
        $certEffectiveDate = $request.ServicePoint.Certificate.GetEffectiveDateString()
        $certIssuer = $request.ServicePoint.Certificate.GetIssuerName()
    }
    catch {
        Write-Verbose "Exception while parsing cert from $server`: $_"
    }

    try {
        $dnsname = [System.Net.Dns]::GetHostEntry($server).HostName
    }
    catch {
        $dnsname = ""
        Write-Verbose "Setting Hostname to blank."
        Write-Verbose "Exception while retrieving hostname from $server`: $_"
    }

    $isExpired = $false
    try {
        if ([System.DateTime]::Parse($certExpires) -lt (Get-Date)) {
            $isExpired = $true
        }
    }
    catch {
        Write-Verbose "Exception while parsing checking if cert is expired for $server`: $_"              
    }

    if ($certName) {
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
            IsExpired = $isExpired 
            #PublicKey = $certPublicKeyString
        }
        return $details
    }
}

# Check if the $targets parameter is a file
if (Test-Path $targets[0]) {
    $servers = Get-Content $targets
}
else {
    $servers = $targets
}

foreach ($server in $servers) {
    if($server -match ":") {
        Write-Progress -Activity "Checking certificates" -status "Checking $server" -percentComplete ($servers.IndexOf($server) / ($servers.count)*100)

        # Make sure that we have cleared out all the variables
        $details = $targetserver = $dnsname = $certExpires = $certName =  $certSerialNumber = $certThumbprint = $certEffectiveDate = $certIssuer = $null
        
        $targetserver = "https://" + $server
        
        $req = Get-Certificate -server $targetserver -timeout $timeout

        $details = Get-CertificateData -req $req
        
        if ($details) {
            $results += New-Object PSObject -Property $details
            #$details  
        }
    }
    else {
        foreach ($port in $ports) {
            Write-Progress -Activity "Checking certificates" -status "Checking $server`:$port" -percentComplete ($servers.IndexOf($server) / ($servers.count)*100)

            # Make sure that we have cleared out all the variables
            $details = $targetserver = $dnsname = $certExpires = $certName =  $certSerialNumber = $certThumbprint = $certEffectiveDate = $certIssuer = $null
            
            $targetserver = "https://" + $server + ":" + $port
            
            $req = Get-Certificate -server $targetserver -timeout $timeout

            $details = Get-CertificateData -req $req
            
            if ($details) {
                $results += New-Object PSObject -Property $details
                #$details  
            }
        }
    }
}

$stopTime = Get-Date

$results | Export-Csv -Path $output -NoTypeInformation

switch ($notify){
    smtp {
        if ((!$smtpFrom) -and (!$smtpTo) -and (!$smtpServer)) { Write-Warning "> Cannot send email, requires smtpTo, smtpFrom and smtpServer."; break}
        $count = ($results  | measure).Count
        $notifySubject = "Certificate Scanner has finished."
        $notifyBody = "<p>Scan started: `t$startTime</p><p>Scan finished: `t$stopTime</p><p>The scan has finished, it found $count certificates. See attached report."
        Write-Verbose "> Sending Email alert to $smtpTo from $smtpFrom through $smtpServer." 
        Send-Mailmessage -to $smtpTo -from $smtpFrom -subject $notifySubject -BodyAsHtml $notifyBody -smtpserver $smtpServer -Attachments $output
    }
}