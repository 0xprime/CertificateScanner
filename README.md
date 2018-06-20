# Certificate Scanner
Connects to multiple hosts and parses the certificate, then writes the result to a .csv file.  

Thanks to the Research Council of Norway for allowing me to Open Source this project and continue to work on it. 

Version 1.0

## Todo
- Clean up code.
- Add support for ip range as targets.
- ~~Add support for target file containing IP:PORT pairs.~~ Done
- ~~Add notification on finished run.~~ Done
- Provide more details in notification. 
- Improve efficiency. 

## Use case

Set a scheduled task to run the script every month, using the notification feature to to send an email to the person or group responsible for certificates in your organization after each run.

## Usage
`.\CertificateScanner.ps1 -targets 10.0.0.1`

`.\CertificateScanner.ps1 -targets 10.0.0.1,10.0.0.2 -ports 443,8443 -timeout 500`

`.\CertificateScanner.ps1 -targets .\servers.txt -ports 443,8443 -output certs.csv -timeout 500`

`.\CertificateScanner.ps1 -targets .\servers.txt -ports 443,8443 -notify smtp -smtpFrom ripley@weyland.com -smtpTo bishop@weyland.com -smtpServer smtp.weyland.com`

The "Targets" parameter can be either a file containing IPs and hostnames, or a list of IPs or hostnames separated by commas. The script will check each server and port pair in sequence, except where the target is a HOST:PORT pair. In that case, only that combination will be checked.

### Example
`.\CertificateScanner.ps1 -targets 10.0.0.1,10.0.0.2,github.com:4444 -ports 443,8443`

This will result in the following tests: 

https://10.0.0.1:443

https://10.0.0.1:8443

https://10.0.0.2:443

https://10.0.0.2:8443

https://github.com:4444


## Inspired by:
https://stackoverflow.com/questions/39253055/powershell-script-to-get-certificate-expiry-for-a-website-remotely-for-multiple
