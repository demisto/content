# GetDomainCertificate

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | certificate, domain |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| domain | The domain to retrieve the certificate for. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Subject | The subject of the certificate | String |
| Issuer | The issuer of the certificate | String |
| Version | The version of the certificate | Number |
| SerialNumber | The serial number of the certificate | String |
| NotBefore | The start date of the certificate validity | Date |
| NotAfter | The expiration date of the certificate | Date |
| SubjectAlternativeName | The Subject Alternative Name (SAN) of the certificate | String |

## Description
---
This script retrieves the SSL/TLS certificate for a given domain and returns its details.

## Script Example
```!GetDomainCertificate domain="example.com"```

## Human Readable Output
### Certificate Details for example.com
| Field | Value |
| --- | --- |
| Subject | CN=example.com |
| Issuer | CN=Let's Encrypt Authority X3,O=Let's Encrypt,C=US |
| Version | 3 |
| Serial Number | 03:45:8E:86:47:A1:27:D8:55:FF:66:A8:CA:9C:E5:C6:7F:F5 |
| Not Before | 2023-05-01 12:34:56 |
| Not After | 2023-07-30 12:34:56 |
| Subject Alternative Name | DNS:example.com, DNS:www.example.com |
