The playbooks process a variety of indicators by parsing and storing them as arrays under newly created context keys.
The playbook outputs can then be used to improve the efficiency of various threat hunting playbooks.

Note that multiple search values should be separated by commas only (without spaces or any special characters). 

The following IOCs are included in the playbook:
MD5
SHA1
SHA256
IP Address
URLDomain
Registry Value
Registry Key
Registry Hives
Command Line
File Name
Process Name
HTTP Request Methods
User Agent
Port Number
File Path
Geolocation
Email Address
CIDR
URI
Ja3
FileType 

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | A single or multiple MD5 file hashes to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| SHA1 | A single or multiple SHA1 file hashes to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| SHA256 | A single or multiple SHA256 file hashes to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| IPAddress | A single or multiple IP addresses to parse and set for future use within hunting playbooks. Used for both source and destination IP addresses.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| URLDomain | Single or multiple URLs and/or domains to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| RegistryValue | A single or multiple registry values to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| RegistryKey | A single or multiple registry keys to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| RegistryHives | Only relevant for hunting on Windows hosts.<br/>A single or multiple registry hives to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| CommandLine | A single or multiple command lines to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| FileName | A single or multiple file names to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| ProcessName | A single or multiple process names to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| HTTPRequestMethods | A single or multiple HTTP requests methods to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| UserAgent | A single or multiple user agents to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| PortNumber | A single or multiple IP addresses to parse and set for future use within hunting playbooks. Used for both source and destination ports.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| FilePath | A single or multiple file paths to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| Geolocation | A single or multiple country names or codes to parse and set for future use within hunting playbooks. Used for both source and destination geolocations.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| EmailAddress | A single or multiple email addresses to parse and set for future use within hunting playbooks. Used for both sender and recipient email addresses.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| CIDR | A single or multiple IP ranges to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| URI | A single or multiple URIs to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| Ja3 | JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence.<br/>A single or multiple Ja3's to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| FileType | A single or multiple file types to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| Application | A single or multiple applications name to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |
| CVE_ID | Hunt for assets with a given CVE using available tools.<br/>A single or multiple CVE IDs to parse and set for future use within hunting playbooks.<br/><br/>Separate multiple search values by commas only \(without spaces or any special characters\). |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RegistryKeyParsed | An array of parsed registry key indicators. | string |
| ProcessNameParsed | An array of parsed process name indicators. | string |
| CommandLineParsed | An array of parsed CommandLine indicators. | string |
| RegistryHivesParsed | An array of parsed registry hives indicators. | string |
| RegistryValueParsed | An array of parsed registry value indicators. | string |
| HTTPRequestMethodsParsed | An array of parsed HTTP request methods indicators. | string |
| Ja3Parsed | An array of parsed Ja3 indicators. | string |
| UserAgentParsed | An array of parsed user agent indicators. | string |
| URIParsed | An array of parsed URI indicators. | string |
| FilePathParsed | An array of parsed file paths indicators. | string |
| SHA1Parsed | An array of parsed SHA1 indicators. | string |
| SHA256Parsed | An array of parsed SHA256 indicators. | string |
| MD5Parsed | An array of parsed MD5 indicators. | string |
| FileNameParsed | An array of parsed file names indicators. | string |
| FileTypeParsed | An array of parsed file types indicators. | string |
| IPAddressParsed | An array of parsed IP addresses indicators. | string |
| URLDomainParsed | An array of parsed URLDomain indicators. | string |
| CIDRParsed | An array of parsed CIDR indicators. | string |
| EmailAddressParsed | An array of parsed email addresses indicators. | string |
| PortNumberParsed | An array of parsed port numbers indicators. | string |
| GeolocationParsed | An array of parsed geolocation indicators. | string |
| ApplicationParsed | An array of parsed application indicators. | string |
| CVE_IDParsed | An array of parsed CVE IDs | string |

## Playbook Image
---
![Threat Hunting - Set Indicators](../doc_files/Threat_Hunting_-_Set_Indicators.png)