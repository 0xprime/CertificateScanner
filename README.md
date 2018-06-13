# Certificate Scanner

Connects to multiple hosts and parses the certificate, then writes the result to a .csv file.  

Thanks to the Research Council of Norway for allowing me to Open Source this project and continue to work on it. 

## Todo
- Clean up code.
- Add support for ip range as targets.
- Add notification on finished run.
- Improve efficiency. 

## Examples
`.\CertificateScanner.ps1 -targets 10.0.0.1`

`.\CertificateScanner.ps1 -targets 10.0.0.1,10.0.0.2 -ports 443,8443 -timeout 500`

`.\CertificateScanner.ps1 -targets .\servers.txt -ports 443,8443 -output certs.csv -timeout 500`

## Inspired by:
https://stackoverflow.com/questions/39253055/powershell-script-to-get-certificate-expiry-for-a-website-remotely-for-multiple
