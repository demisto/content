Enriches the given IP address or domain with metadata, malware, or osint.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | passive-total, server, threat-intel |


## Dependencies
---
This script uses the following commands and scripts.
* pt-osint
* pt-malware
* pt-enrichment
* pt-get-subdomains
* pt-ssl-cert
* pt-whois
* pt-passive-dns

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | The IP address or domain to enrich. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| subdomains | The list of subdomains as strings. | Unknown |
| Domain.Name | The name of the queries domain. | Unknown |
| Domain.DNS.Address | The resolved address of the domain. | Unknown |
| passivetotal.whois.email | The contact email for the queried domain. | Unknown |
| passivetotal.resolves | The various resolves from the passive DNS collection. | Unknown |
| IP.Address | The bad IP addresses found during enrichment. | Unknown |
| IP.Malicious.Vendor | The vendor that made the decision that the IP addresses are malicious.  | Unknown |
| IP.Malicious.Description | The reason that the vendor decided that the IP addresses were malicious. | Unknown |
| Domain.Name | The bad domains found during the enrichment. | Unknown |
| Domain.Malicious.Vendor | The vendor that made the decision that the domains are malicious. | Unknown |
| Domain.Malicious.Description | The reason that the vendor decided that the domains were malicious. | Unknown |
| File.MD5 | The bad MD5 hash of teh file. | Unknown |
| File.SHA1 | The bad SHA1 hash of the file. | Unknown |
| File.SHA256 | The bad SHA256 hash of the file. | Unknown |
| File.Malicious.Vendor | The vendor that made the decision that the files are malicious. | Unknown |
| File.Malicious.Description | The bad SHA256 hash of the file. | Unknown |
| DBotScore.Indicator | The indicator that was tested. | Unknown |
| DBotScore.Type | The type of the indicator. | Unknown |
| DBotScore.Vendor | The vendor used to calculate the score. | Unknown |
| DBotScore.Score | The actual score. | Unknown |
