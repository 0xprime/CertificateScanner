# Certificate Scanner

Connects to multiple hosts and parses the certificate. Writes the result to a .csv file.  

Thanks to the Research Council of Norway for allowing me to Open Source this project and continue to work on it. 

## Examples
`.\CertificateScanner -urls 10.0.0.1,10.0.0.2 -ports 443,8443 -timeout 500`

Runs with default variables for -filepath, -outputfilename and -reportname.

## Inspired by:
https://stackoverflow.com/questions/39253055/powershell-script-to-get-certificate-expiry-for-a-website-remotely-for-multiple