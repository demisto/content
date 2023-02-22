The SSLVerifierV2 automation provides the core functionality for the [SSL Certificates](https://cortex.marketplace.pan.dev/marketplace/details/SSLCertificates/) content pack. 

This automation must be executed against at least a single IP/FQDN before !SSLVerifierV2_ParseOutput or !SSLVerifierV2_GenerateEmailBody can be used.

This automation uses the following definitions for certificates in a GOOD, WARNING, or EXPIRING state:

**Good**: Expiring in > 180 days
**Warning**: Expiring within 91 to 180 days
**Expiring**: Expiring in 90 days or less

**Parameters for the automation:**

**URL**: The URL, IP Address, or FQDN to poll the certificate status for
**PORT**: The port to use when polling for the SSL Certificate status. Uses port 443 by default

**Outputs for the automation:**

**SSLVerifierV2.Certificate.ExpirationDate**: The expiration date for the certificate in the format: YYYY/MM/DD - HH:MM:SS
**SSLVerifierV2.Certificate.Site**: The IP or FQDN of the certificate being checked
**SSLVerifierV2.Certificate.TimeToExpiration**: The number of days until certificate expiration

**Sample Command Input - Single Host **
!SSLVerifierV2 URL=www.google.com Port=443

**Sample Context Output**
{
    "Domain": "www.google.com",
    "ExpirationDate": "2023/04/26 - 19:43:58",
    "TimeToExpiration": "68"
}

**Sample Command Input - Array of IP/FQDNs**
**NOTE**: By default, the !createArray automation outputs to the "*array*" context key. This can be customized in the command string using the "*contextKey*" parameter.

!createArray arrayData="www.domain1.com, www.domain2.com, www.domain3.com"
!SSLVerifierV2 URL=${array} Port=443

**Sample Context Output**
{
    "Domain": "www.google.com",
    "ExpirationDate": "2023/04/26 - 19:43:58",
    "TimeToExpiration": "68"
}
