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
| domains | The domains to retrieve the certificate for. |
| verbose | if true attaches the complete certificate under "full_certificate". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SSLInfo.domain | The domain name. | String |
| SSLInfo.issuer_country | The country of the certificate issuer. | String |
| SSLInfo.issuer_organization | The organization of the certificate issuer. | String |
| SSLInfo.issuer_common_name | The common name of the certificate issuer. | String |
| SSLInfo.subject_country | The country of the certificate subject. | String |
| SSLInfo.subject_organization | The organization of the certificate subject. | String |
| SSLInfo.version | The SSL/TLS version. | String |
| SSLInfo.issue_date | The date the certificate was issued. | Date |
| SSLInfo.expiry_date | The date the certificate expires. | Date |
| SSLInfo.error | Error message if certificate verification fails. | String |
| SSLInfo.full_certificate | Full certificate details in PEM format. | String |

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
