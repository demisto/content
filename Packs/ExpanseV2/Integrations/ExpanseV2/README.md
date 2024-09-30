The Cortex Xpanse (previously **Expanse v2**) integration for Cortex XSOAR leverages the Expander API to create incidents from Xpanse issues. It also leverages Xpanse's unparalleled view of the Internet to enrich IPs, domains and certificates using information from assets discovered by Cortex Xpanse Expander.

This integration was developed and tested with Xpanse Expander.

Cortex Xpanse is a Palo Alto Networks company.

Supported Cortex XSOAR versions: 6.0.0 and later.

## Configure Cortex Xpanse in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Your server URL | True |
| apikey | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| first_fetch | First fetch time | False |
| priority | Fetch Xpanse issues with Priority | False |
| activity_status | Fetch Xpanse issues with Activity Status | False |
| progress_status | Fetch Xpanse issues with Progress Status | False |
| business_unit | Fetch issues with Business Units \(comma separated string\) | False |
| tag | Fetch issues with Tags \(comma separated string\) | False |
| issue_type | Fetch issue with Types \(comma separated string\) | False |
| mirror_direction | Incident Mirroring Direction | False |
| sync_owners | Sync Incident Owners | False |
| incoming_tags | Tag\(s\) for mirrored comments | False |
| sync_tags | Mirror out Entries with tag\(s\) | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### expanse-get-issues

***
Retrieve issues


#### Base Command

`expanse-get-issues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of issues to retrieve. | Optional | 
| content_search | Returns only results whose contents match the given query. | Optional | 
| provider | Returns only results that were found on the given providers (comma separated string). | Optional | 
| business_unit | Returns only results with a business unit whose name falls in the provided list (comma separated string). | Optional | 
| assignee | Returns only results whose assignee's username matches one of the given usernames. Use "Unassigned" to fetch issues that are not assigned to any user. | Optional | 
| issue_type | Returns only results whose issue type name matches one of the given types (comma separated string). | Optional | 
| inet_search | Returns results whose identifier includes an IP matching the query. Search for results in a given IP/CIDR block using a single IP (d.d.d.d), a dashed IP range (d.d.d.d-d.d.d.d), a CIDR block (d.d.d.d/m), a partial CIDR (d.d.), or a wildcard (d.d.*.d). | Optional | 
| domain_search | Returns results whose identifier includes a domain matching the query. | Optional | 
| port_number | Returns only results whose identifier includes one of the given port numbers (comma separated list). | Optional | 
| priority | Returns only results whose priority matches one of the given values (comma separated string, options are 'Low', 'Medium', 'High', 'Critical'). | Optional | 
| progress_status | Returns only results whose progress status matches one of the given values (comma separated string, options are 'New', 'Investigating', 'InProgress', 'AcceptableRisk', 'Resolved'). | Optional | 
| activity_status | Returns only results whose activity status matches one of the given values. Possible values are: Active, Inactive. | Optional | 
| tag | Returns only results that are associated with the provided tag names (comma separated string). | Optional | 
| created_before | Returns only results created before the provided timestamp (ISO8601 format YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| created_after | Returns only results created after the provided timestamp (ISO8601 format YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| modified_before | Returns only results modified before the provided timestamp (ISO8601 format YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| modified_after | Returns only results modified after the provided timestamp (ISO8601 format YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| sort | Sort by specified properties. Possible values are: created, -created, modified, -modified, activityStatus, -assigneeUsername, priority, -priority, progressStatus, -progressStatus, activityStatus, -activityStatus, headline, -headline. Default is created. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Issue.activityStatus | String | Activity status of issue, whether the issue is active or inactive | 
| Expanse.Issue.annotations.tags.id | String | The Internal Xpanse tag id of the customer added tag | 
| Expanse.Issue.annotations.tags.name | String | The tag name of the customer added tag | 
| Expanse.Issue.assets.assetKey | String | Key used to access the asset in the respective Xpanse asset API | 
| Expanse.Issue.assets.assetType | String | The type of asset the issue primarily relates to | 
| Expanse.Issue.assets.displayName | String | A friendly name for the asset | 
| Expanse.Issue.assets.id | String | Internal Xpanse ID the asset | 
| Expanse.Issue.assigneeUsername | String | The username of the user that has been assigned to the issue | 
| Expanse.Issue.businessUnits.id | String | The internal Xpanse ID for the business unit the affected asset belongs to | 
| Expanse.Issue.businessUnits.name | String | The name of the business unit the affected asset belongs to | 
| Expanse.Issue.category | String | The general category of the issue | 
| Expanse.Issue.certificate.formattedIssuerOrg | String | The formatted issuer org in the certificate | 
| Expanse.Issue.certificate.id | String | The Internal Xpanse certificate ID | 
| Expanse.Issue.certificate.issuer | String | The issuer in the certificate | 
| Expanse.Issue.certificate.issuerAlternativeNames | String | The issuer alternative names in the certificate | 
| Expanse.Issue.certificate.issuerCountry | String | The issuer country in the certificate | 
| Expanse.Issue.certificate.issuerEmail | String | The issuer email in the certificate | 
| Expanse.Issue.certificate.issuerLocality | String | The issuer locality in the certificate | 
| Expanse.Issue.certificate.issuerName | String | The issuer name in the certificate | 
| Expanse.Issue.certificate.issuerOrg | String | The issuer org in the certificate | 
| Expanse.Issue.certificate.issuerOrgUnit | String | The issuer org unit in the certificate | 
| Expanse.Issue.certificate.issuerState | String | The issuer state in the certificate | 
| Expanse.Issue.certificate.md5Hash | String | The md5hash in the certificate | 
| Expanse.Issue.certificate.pemSha1 | String | The pemSha1 in the certificate | 
| Expanse.Issue.certificate.pemSha256 | String | The pemSha256 in the certificate | 
| Expanse.Issue.certificate.publicKey | String | The public key in the certificate | 
| Expanse.Issue.certificate.publicKeyAlgorithm | String | The public key algorithm in the certificate | 
| Expanse.Issue.certificate.publicKeyBits | Number | The public key bits in the certificate | 
| Expanse.Issue.certificate.publicKeyModulus | String | The public key modulus in the certificate | 
| Expanse.Issue.certificate.publicKeyRsaExponent | Number | The public key RSA exponent in the certificate | 
| Expanse.Issue.certificate.publicKeySpki | String | The public key Spki in the certificate | 
| Expanse.Issue.certificate.serialNumber | String | The serial number in the certificate | 
| Expanse.Issue.certificate.signatureAlgorithm | String | The signature algorithm in the certificate | 
| Expanse.Issue.certificate.subject | String | The subject in the certificate | 
| Expanse.Issue.certificate.subjectAlternativeNames | String | The subject alternative names in the certificate | 
| Expanse.Issue.certificate.subjectCountry | String | The subject country in the certificate | 
| Expanse.Issue.certificate.subjectEmail | String | The subject email in the certificate | 
| Expanse.Issue.certificate.subjectLocality | String | The subject locality in the certificate | 
| Expanse.Issue.certificate.subjectName | String | The subject name in the certificate | 
| Expanse.Issue.certificate.subjectOrg | String | The subject org in the certificate | 
| Expanse.Issue.certificate.subjectOrgUnit | String | The subject org unit in the certificate | 
| Expanse.Issue.certificate.subjectState | String | The subject state in the certificate | 
| Expanse.Issue.certificate.validNotAfter | Date | The valid not after date in the certificate | 
| Expanse.Issue.certificate.validNotBefore | Date | The valid not before date in the certificate | 
| Expanse.Issue.certificate.version | String | The version in the certificate |
| Expanse.Issue.cloudManagementStatus.id | String | The ID of the cloud management status |
| Expanse.Issue.cloudManagementStatus.name | String | The friendly name of the cloud management status |
| Expanse.Issue.created | Date | When the issue instance was created | 
| Expanse.Issue.domain | String | Domain name of the issue | 
| Expanse.Issue.headline | String | A brief summary of the issue | 
| Expanse.Issue.helpText | String | Why Xpanse this type of issue should be avoided | 
| Expanse.Issue.id | String | The internal Xpanse ID of the issue | 
| Expanse.Issue.initialEvidence.certificate.formattedIssuerOrg | String | The formatted issuer org in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.id | String | The Internal Xpanse certificate ID in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuer | String | The issuer in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerAlternativeNames | String | The issuer alternative names in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerCountry | String | The issuer country in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerEmail | String | The issuer email in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerLocality | String | The issuer locality in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerName | String | The issuer name in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerOrg | String | The issuer org in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerOrgUnit | String | The issuer org unit in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerState | String | The issuer state in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.md5Hash | String | The md5hash in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.pemSha1 | String | The pemSha1 in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.pemSha256 | String | The pemSha256 in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKey | String | The public key in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKeyAlgorithm | String | The public key algorithm in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKeyBits | Number | The public key bits in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKeyModulus | String | The public key modulus in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKeyRsaExponent | Number | The public key RSA exponent in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKeySpki | String | The public key Spki in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.serialNumber | String | The serial number in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.signatureAlgorithm | String | The signature algorithm in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subject | String | The subject in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectAlternativeNames | String | The subject alternative names in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectCountry | String | The subject country in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectEmail | String | The subject email in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectLocality | String | The subject locality in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectName | String | The subject name in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectOrg | String | The subject org in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectOrgUnit | String | The subject org unit in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectState | String | The subject state in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.validNotAfter | Date | The valid not after date in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.validNotBefore | Date | The valid not before date in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.version | String | The version in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.cipherSuite | String | The cipher suite in the initial observation | 
| Expanse.Issue.initialEvidence.configuration._type | String | The type of configuration data in the initial observation | 
| Expanse.Issue.initialEvidence.configuration.validWhenScanned | Boolean | Whether the configuration was valid in the initial observation | 
| Expanse.Issue.initialEvidence.discoveryType | String | The discovery type in the initial observation | 
| Expanse.Issue.initialEvidence.domain | String | The domain name in the initial observation | 
| Expanse.Issue.initialEvidence.evidenceType | String | The evidence type of the initial observation | 
| Expanse.Issue.initialEvidence.exposureId | String | The exposure ID in the initial observation | 
| Expanse.Issue.initialEvidence.exposureType | String | The exposure type in the initial observation | 
| Expanse.Issue.initialEvidence.geolocation.latitude | Number | The latitude in the initial observation | 
| Expanse.Issue.initialEvidence.geolocation.longitude | Number | The longitude in the initial observation | 
| Expanse.Issue.initialEvidence.geolocation.city | String | The city name in the initial observation | 
| Expanse.Issue.initialEvidence.geolocation.regionCode | String | The region code in the initial observation | 
| Expanse.Issue.initialEvidence.geolocation.countryCode | String | The country code in the initial observation | 
| Expanse.Issue.initialEvidence.ip | String | The IPv4 address in the initial observation | 
| Expanse.Issue.initialEvidence.portNumber | Number | The port number in the initial observation | 
| Expanse.Issue.initialEvidence.portProtocol | String | The port protocol in the initial observation | 
| Expanse.Issue.initialEvidence.serviceId | String | The Service ID in the initial observation | 
| Expanse.Issue.initialEvidence.serviceProperties.serviceProperties.name | String | The service property name in the initial observation | 
| Expanse.Issue.initialEvidence.serviceProperties.serviceProperties.reason | String | The service property reason in the initial observation | 
| Expanse.Issue.initialEvidence.timestamp | Date | The timestamp of the initial observation | 
| Expanse.Issue.initialEvidence.tlsVersion | String | The TLS version found in the initial observation | 
| Expanse.Issue.ip | String | The IPv4 address last associated with the issue | 
| Expanse.Issue.issueType.archived | Boolean | Whether the issue type is archived | 
| Expanse.Issue.issueType.id | String | The ID of the issue type | 
| Expanse.Issue.issueType.name | String | The name of the issue type | 
| Expanse.Issue.latestEvidence.certificate.formattedIssuerOrg | String | The formatted issuer org in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.id | String | The Internal Xpanse certificate ID in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuer | String | The issuer in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerAlternativeNames | String | The issuer alternative names in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerCountry | String | The issuer country in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerEmail | String | The issuer email in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerLocality | String | The issuer locality in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerName | String | The issuer name in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerOrg | String | The issuer org in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerOrgUnit | String | The issuer org unit in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerState | String | The issuer state in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.md5Hash | String | The md5hash in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.pemSha1 | String | The pemSha1 in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.pemSha256 | String | The pemSha256 in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKey | String | The public key in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKeyAlgorithm | String | The public key algorithm in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKeyBits | Number | The public key bits in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKeyModulus | String | The public key modulus in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKeyRsaExponent | Number | The public key RSA exponent in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKeySpki | String | The public key Spki in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.serialNumber | String | The serial number in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.signatureAlgorithm | String | The signature algorithm in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subject | String | The subject in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectAlternativeNames | String | The subject alternative names in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectCountry | String | The subject country in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectEmail | String | The subject email in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectLocality | String | The subject locality in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectName | String | The subject name in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectOrg | String | The subject org in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectOrgUnit | String | The subject org unit in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectState | String | The subject state in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.validNotAfter | Date | The valid not after date in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.validNotBefore | Date | The valid not before date in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.version | String | The version in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.cipherSuite | String | The cipher suite detected during the most recent observation | 
| Expanse.Issue.latestEvidence.configuration._type | String | The type of configuration data in the most recent observation | 
| Expanse.Issue.latestEvidence.configuration.validWhenScanned | Boolean | Whether the configuration was valid in the most recent observation | 
| Expanse.Issue.latestEvidence.discoveryType | String | The discovery type in the most recent observation | 
| Expanse.Issue.latestEvidence.domain | String | The domain name in the most recent observation | 
| Expanse.Issue.latestEvidence.evidenceType | String | The evidence type of the most recent observation | 
| Expanse.Issue.latestEvidence.exposureId | String | The exposure ID in the most recent observation | 
| Expanse.Issue.latestEvidence.exposureType | String | The exposure type in the most recent observation | 
| Expanse.Issue.latestEvidence.geolocation.latitude | Number | The latitude in the most recent observation | 
| Expanse.Issue.latestEvidence.geolocation.longitude | Number | The latitude in the most recent observation | 
| Expanse.Issue.latestEvidence.geolocation.city | String | The city name in the most recent observation | 
| Expanse.Issue.latestEvidence.geolocation.regionCode | String | The region code in the most recent observation | 
| Expanse.Issue.latestEvidence.geolocation.countryCode | String | The country code in the most recent observation | 
| Expanse.Issue.latestEvidence.ip | String | The IPv4 address in the most recent observation | 
| Expanse.Issue.latestEvidence.portNumber | Number | The port number in the most recent observation | 
| Expanse.Issue.latestEvidence.portProtocol | String | The port protocol in the most recent observation | 
| Expanse.Issue.latestEvidence.serviceId | String | The Service ID in the most recent observation | 
| Expanse.Issue.latestEvidence.serviceProperties.serviceProperties.name | String | The service property name in the most recent observation | 
| Expanse.Issue.latestEvidence.serviceProperties.serviceProperties.reason | String | The service property reason in the most recent observation | 
| Expanse.Issue.latestEvidence.timestamp | Date | The timestamp of the most recent observation | 
| Expanse.Issue.latestEvidence.tlsVersion | String | The TLS version found in the most recent observation | 
| Expanse.Issue.modified | Date | The timestamp of when the issue was last modified | 
| Expanse.Issue.portNumber | Number | The port number the issue was detected on | 
| Expanse.Issue.portProtocol | String | The port protocol the issue was detected on | 
| Expanse.Issue.priority | String | The priority of the issue | 
| Expanse.Issue.progressStatus | String | The progress status of the issue | 
| Expanse.Issue.providers.id | String | The ID of the provider the issue was detected on | 
| Expanse.Issue.providers.name | String | The name of the provider the issue was detected on | 


#### Command Example

```!expanse-get-issues limit="1" provider="Amazon Web Services" sort="-created"```

#### Context Example

```json
{
    "Expanse": {
        "Issue": {
            "activityStatus": "Active",
            "annotations": {
                "tags": []
            },
            "assets": [
                {
                    "assetKey": "gdRHmkxmGwWpaUtAuge6IQ==",
                    "assetType": "Certificate",
                    "displayName": "*.thespeedyou.com",
                    "id": "724a1137-ee3f-381f-95f2-ea0441db22d0"
                }
            ],
            "assigneeUsername": "Unassigned",
            "businessUnits": [
                {
                    "id": "f738ace6-f451-4f31-898d-a12afa204b2a",
                    "name": "PANW VanDelay Dev"
                }
            ],
            "category": "Attack Surface Reduction",
            "certificate": {
                "formattedIssuerOrg": "GeoTrust",
                "id": "81d4479a-4c66-3b05-a969-4b40ba07ba21",
                "issuer": "C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3",
                "issuerAlternativeNames": "",
                "issuerCountry": "US",
                "issuerEmail": null,
                "issuerLocality": null,
                "issuerName": "GeoTrust SSL CA - G3",
                "issuerOrg": "GeoTrust Inc.",
                "issuerOrgUnit": null,
                "issuerState": null,
                "md5Hash": "gdRHmkxmGwWpaUtAuge6IQ==",
                "pemSha1": "p0y_sHlFdp5rPOw8aWrH2Qc331Q=",
                "pemSha256": "w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=",
                "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB",
                "publicKeyAlgorithm": "RSA",
                "publicKeyBits": 2048,
                "publicKeyModulus": "bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d",
                "publicKeyRsaExponent": 65537,
                "publicKeySpki": "5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA=",
                "serialNumber": "34287766128589078095374161204025316200",
                "signatureAlgorithm": "SHA256withRSA",
                "subject": "C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com",
                "subjectAlternativeNames": "*.thespeedyou.com thespeedyou.com",
                "subjectCountry": "IN",
                "subjectEmail": null,
                "subjectLocality": "Pune",
                "subjectName": "*.thespeedyou.com",
                "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.",
                "subjectOrgUnit": "Management Services",
                "subjectState": "Maharashtra",
                "validNotAfter": "2017-01-18T23:59:59Z",
                "validNotBefore": "2015-01-19T00:00:00Z",
                "version": "3"
            },
            "created": "2020-09-23T01:44:37.415249Z",
            "domain": null,
            "headline": "Insecure TLS at 52.6.192.223:443",
            "helpText": "This service should not be visible on the public Internet.",
            "id": "2b0ea80c-2277-34dd-9c55-005922ba640a",
            "initialEvidence": {
                "certificate": {
                    "formattedIssuerOrg": null,
                    "id": "81d4479a-4c66-3b05-a969-4b40ba07ba21",
                    "issuer": "C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3",
                    "issuerAlternativeNames": "",
                    "issuerCountry": "US",
                    "issuerEmail": null,
                    "issuerLocality": null,
                    "issuerName": "GeoTrust SSL CA - G3",
                    "issuerOrg": "GeoTrust Inc.",
                    "issuerOrgUnit": null,
                    "issuerState": null,
                    "md5Hash": "gdRHmkxmGwWpaUtAuge6IQ==",
                    "pemSha1": "p0y_sHlFdp5rPOw8aWrH2Qc331Q=",
                    "pemSha256": "w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=",
                    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB",
                    "publicKeyAlgorithm": "RSA",
                    "publicKeyBits": 2048,
                    "publicKeyModulus": "bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d",
                    "publicKeyRsaExponent": 65537,
                    "publicKeySpki": "5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA=",
                    "serialNumber": "34287766128589078095374161204025316200",
                    "signatureAlgorithm": "SHA256withRSA",
                    "subject": "C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com",
                    "subjectAlternativeNames": "*.thespeedyou.com thespeedyou.com",
                    "subjectCountry": "IN",
                    "subjectEmail": null,
                    "subjectLocality": "Pune",
                    "subjectName": "*.thespeedyou.com",
                    "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.",
                    "subjectOrgUnit": "Management Services",
                    "subjectState": "Maharashtra",
                    "validNotAfter": "2017-01-18T23:59:59Z",
                    "validNotBefore": "2015-01-19T00:00:00Z",
                    "version": "3"
                },
                "cipherSuite": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
                "configuration": {
                    "_type": "WebServerConfiguration",
                    "applicationServerSoftware": "",
                    "certificateId": "74K3sPuBY6wi7US9poLZdg==",
                    "hasApplicationServerSoftware": false,
                    "hasServerSoftware": true,
                    "hasUnencryptedLogin": false,
                    "htmlPasswordAction": "",
                    "htmlPasswordField": "",
                    "httpAuthenticationMethod": "",
                    "httpAuthenticationRealm": "",
                    "httpHeaders": [
                        {
                            "name": "Set-Cookie",
                            "value": "JSESSIONID=6E9656EFE98ED2DD7447C779504A4994; Path=/; Secure; HttpOnly"
                        },
                        {
                            "name": "X-FRAME-OPTIONS",
                            "value": "DENY"
                        },
                        {
                            "name": "Content-Type",
                            "value": "text/html;charset=UTF-8"
                        },
                        {
                            "name": "Content-Language",
                            "value": "en-US"
                        },
                        {
                            "name": "Transfer-Encoding",
                            "value": "chunked"
                        },
                        {
                            "name": "Vary",
                            "value": "Accept-Encoding"
                        },
                        {
                            "name": "Date",
                            "value": "xxxxxxxxxx"
                        },
                        {
                            "name": "Server",
                            "value": "WSO2 Carbon Server"
                        }
                    ],
                    "httpStatusCode": "200",
                    "isLoadBalancer": false,
                    "loadBalancer": "",
                    "loadBalancerPool": "",
                    "serverSoftware": "WSO2 Carbon Server"
                },
                "discoveryType": "DirectlyDiscovered",
                "domain": null,
                "evidenceType": "ScanEvidence",
                "exposureId": "af2672a7-cf47-3a6d-9ecd-8c356d57d250",
                "exposureType": "HTTP_SERVER",
                "geolocation": null,
                "ip": "52.6.192.223",
                "portNumber": 443,
                "portProtocol": "TCP",
                "serviceId": "355452a1-a39b-369e-9aad-4ca129ec9422",
                "serviceProperties": {
                    "serviceProperties": [
                        {
                            "name": "ExpiredWhenScannedCertificate",
                            "reason": "{\"validWhenScanned\":false}"
                        },
                        {
                            "name": "MissingCacheControlHeader",
                            "reason": null
                        },
                        {
                            "name": "MissingContentSecurityPolicyHeader",
                            "reason": null
                        },
                        {
                            "name": "MissingPublicKeyPinsHeader",
                            "reason": null
                        },
                        {
                            "name": "MissingStrictTransportSecurityHeader",
                            "reason": null
                        },
                        {
                            "name": "MissingXContentTypeOptionsHeader",
                            "reason": null
                        },
                        {
                            "name": "MissingXXssProtectionHeader",
                            "reason": null
                        },
                        {
                            "name": "ServerSoftware",
                            "reason": "{\"serverSoftware\":\"WSO2 Carbon Server\"}"
                        },
                        {
                            "name": "WildcardCertificate",
                            "reason": "{\"validWhenScanned\":false}"
                        }
                    ]
                },
                "timestamp": "2020-08-24T00:00:00Z",
                "tlsVersion": "TLS 1.2"
            },
            "ip": "52.6.192.223",
            "issueType": {
                "archived": null,
                "id": "InsecureTLS",
                "name": "Insecure TLS"
            },
            "latestEvidence": {
                "certificate": {
                    "formattedIssuerOrg": null,
                    "id": "81d4479a-4c66-3b05-a969-4b40ba07ba21",
                    "issuer": "C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3",
                    "issuerAlternativeNames": "",
                    "issuerCountry": "US",
                    "issuerEmail": null,
                    "issuerLocality": null,
                    "issuerName": "GeoTrust SSL CA - G3",
                    "issuerOrg": "GeoTrust Inc.",
                    "issuerOrgUnit": null,
                    "issuerState": null,
                    "md5Hash": "gdRHmkxmGwWpaUtAuge6IQ==",
                    "pemSha1": "p0y_sHlFdp5rPOw8aWrH2Qc331Q=",
                    "pemSha256": "w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=",
                    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB",
                    "publicKeyAlgorithm": "RSA",
                    "publicKeyBits": 2048,
                    "publicKeyModulus": "bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d",
                    "publicKeyRsaExponent": 65537,
                    "publicKeySpki": "5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA=",
                    "serialNumber": "34287766128589078095374161204025316200",
                    "signatureAlgorithm": "SHA256withRSA",
                    "subject": "C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com",
                    "subjectAlternativeNames": "*.thespeedyou.com thespeedyou.com",
                    "subjectCountry": "IN",
                    "subjectEmail": null,
                    "subjectLocality": "Pune",
                    "subjectName": "*.thespeedyou.com",
                    "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.",
                    "subjectOrgUnit": "Management Services",
                    "subjectState": "Maharashtra",
                    "validNotAfter": "2017-01-18T23:59:59Z",
                    "validNotBefore": "2015-01-19T00:00:00Z",
                    "version": "3"
                },
                "cipherSuite": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
                "configuration": {
                    "_type": "WebServerConfiguration",
                    "applicationServerSoftware": "",
                    "certificateId": "74K3sPuBY6wi7US9poLZdg==",
                    "hasApplicationServerSoftware": false,
                    "hasServerSoftware": true,
                    "hasUnencryptedLogin": false,
                    "htmlPasswordAction": "",
                    "htmlPasswordField": "",
                    "httpAuthenticationMethod": "",
                    "httpAuthenticationRealm": "",
                    "httpHeaders": [
                        {
                            "name": "Set-Cookie",
                            "value": "JSESSIONID=E5948E498E58CFB6413087A3D3D2908C; Path=/; Secure; HttpOnly"
                        },
                        {
                            "name": "Location",
                            "value": "https://52.6.192.223/carbon/admin/index.jsp"
                        },
                        {
                            "name": "Content-Type",
                            "value": "text/html;charset=UTF-8"
                        },
                        {
                            "name": "Content-Length",
                            "value": "0"
                        },
                        {
                            "name": "Date",
                            "value": "xxxxxxxxxx"
                        },
                        {
                            "name": "Server",
                            "value": "WSO2 Carbon Server"
                        }
                    ],
                    "httpStatusCode": "302",
                    "isLoadBalancer": false,
                    "loadBalancer": "",
                    "loadBalancerPool": "",
                    "serverSoftware": "WSO2 Carbon Server"
                },
                "discoveryType": "DirectlyDiscovered",
                "domain": null,
                "evidenceType": "ScanEvidence",
                "exposureId": "af2672a7-cf47-3a6d-9ecd-8c356d57d250",
                "exposureType": "HTTP_SERVER",
                "geolocation": null,
                "ip": "52.6.192.223",
                "portNumber": 443,
                "portProtocol": "TCP",
                "serviceId": "355452a1-a39b-369e-9aad-4ca129ec9422",
                "serviceProperties": {
                    "serviceProperties": [
                        {
                            "name": "ExpiredWhenScannedCertificate",
                            "reason": "{\"validWhenScanned\":false}"
                        },
                        {
                            "name": "ServerSoftware",
                            "reason": "{\"serverSoftware\":\"WSO2 Carbon Server\"}"
                        },
                        {
                            "name": "WildcardCertificate",
                            "reason": "{\"validWhenScanned\":false}"
                        }
                    ]
                },
                "timestamp": "2020-09-22T00:00:00Z",
                "tlsVersion": "TLS 1.2"
            },
            "modified": "2020-12-18T18:11:18.399257Z",
            "portNumber": 443,
            "portProtocol": "TCP",
            "priority": "Medium",
            "progressStatus": "InProgress",
            "providers": [
                {
                    "id": "AWS",
                    "name": "Amazon Web Services"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Expanse Issues
>
>|Id|Headline|Issue Type|Category|Ip|Port Protocol|Port Number|Domain|Certificate|Priority|Progress Status|Activity Status|Providers|Assignee Username|Business Units|Created|Modified|Annotations|Assets|Help Text|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2b0ea80c-2277-34dd-9c55-005922ba640a | Insecure TLS at 52.6.192.223:443 | id: InsecureTLS<br/>name: Insecure TLS<br/>archived: null | Attack Surface Reduction | 52.6.192.223 | TCP | 443 |  | id: 81d4479a-4c66-3b05-a969-4b40ba07ba21<br/>md5Hash: gdRHmkxmGwWpaUtAuge6IQ==<br/>issuer: C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3<br/>issuerAlternativeNames: <br/>issuerCountry: US<br/>issuerEmail: null<br/>issuerLocality: null<br/>issuerName: GeoTrust SSL CA - G3<br/>issuerOrg: GeoTrust Inc.<br/>formattedIssuerOrg: GeoTrust<br/>issuerOrgUnit: null<br/>issuerState: null<br/>publicKey: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB<br/>publicKeyAlgorithm: RSA<br/>publicKeyRsaExponent: 65537<br/>signatureAlgorithm: SHA256withRSA<br/>subject: C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com<br/>subjectAlternativeNames: *.thespeedyou.com thespeedyou.com<br/>subjectCountry: IN<br/>subjectEmail: null<br/>subjectLocality: Pune<br/>subjectName: *.thespeedyou.com<br/>subjectOrg: Sears IT and Management Services India Pvt. Ltd.<br/>subjectOrgUnit: Management Services<br/>subjectState: Maharashtra<br/>serialNumber: 34287766128589078095374161204025316200<br/>validNotBefore: 2015-01-19T00:00:00Z<br/>validNotAfter: 2017-01-18T23:59:59Z<br/>version: 3<br/>publicKeyBits: 2048<br/>pemSha256: w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=<br/>pemSha1: p0y_sHlFdp5rPOw8aWrH2Qc331Q=<br/>publicKeyModulus: bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d<br/>publicKeySpki: 5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA= | Medium | InProgress | Active | {'id': 'AWS', 'name': 'Amazon Web Services'} | Unassigned | {'id': 'f738ace6-f451-4f31-898d-a12afa204b2a', 'name': 'PANW VanDelay Dev'} | 2020-09-23T01:44:37.415249Z | 2020-12-18T18:11:18.399257Z | tags:  | {'id': '724a1137-ee3f-381f-95f2-ea0441db22d0', 'assetKey': 'gdRHmkxmGwWpaUtAuge6IQ==', 'assetType': 'Certificate', 'displayName': '*.thespeedyou.com'} | This service should not be visible on the public Internet. |


### expanse-get-issue-updates

***
Retrieve updates for an Xpanse issue.


#### Base Command

`expanse-get-issue-updates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Xpanse issue ID to retrieve updates for. | Required | 
| update_types | Update types to retrieve (comma separated string. Valid options are 'Assignee', 'Comment', 'Priority', 'ProgressStatus', 'ActivityStatus'). | Optional | 
| created_after | Returns only updates created after the provided timestamp (ISO8601 format YYYY-MM-DDTHH:MM:SSZ). | Optional | 
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IssueUpdate.created | Date | The timestamp of when the Issue update occurred | 
| Expanse.IssueUpdate.id | String | The unique ID of the issue update event | 
| Expanse.IssueUpdate.issue_id | String | The unique ID of the issue that was updated | 
| Expanse.IssueUpdate.previousValue | String | The previous value of the field that was updated | 
| Expanse.IssueUpdate.updateType | String | The type of update that occurred, valid types are ProgressStatus, ActivityStatus, Priority, Assignee, and Comment | 
| Expanse.IssueUpdate.user.username | String | The username of the user who made the update | 
| Expanse.IssueUpdate.value | String | The new value of the field that was updated | 


#### Command Example

```!expanse-get-issue-updates issue_id="2b0ea80c-2277-34dd-9c55-005922ba640a" update_types="Comment,ProgressStatus" created_after="2020-12-07T09:34:36.20917328Z" limit="2"```

#### Context Example

```json
{
    "Expanse": {
        "IssueUpdate": [
            {
                "created": "2020-12-18T18:13:21.301817Z",
                "id": "b3825b75-97c5-488b-bc1e-e6347fa8ff23",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-18T18:13:24.311442Z",
                "id": "2577ff9b-43bf-4472-b2a5-c4eaec79a5ce",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": "InProgress",
                "updateType": "ProgressStatus",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "InProgress"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>
>|created|id|issueId|previousValue|updateType|user|value|
>|---|---|---|---|---|---|---|
>| 2020-12-18T18:13:21.301817Z | b3825b75-97c5-488b-bc1e-e6347fa8ff23 | 2b0ea80c-2277-34dd-9c55-005922ba640a |  | Comment | username: <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment |
>| 2020-12-18T18:13:24.311442Z | 2577ff9b-43bf-4472-b2a5-c4eaec79a5ce | 2b0ea80c-2277-34dd-9c55-005922ba640a | InProgress | ProgressStatus | username: <demo+api.external.vandelay+panw@expanseinc.com> | InProgress |


### expanse-get-issue-comments

***
Retrieve issue comments (subset of updates)


#### Base Command

`expanse-get-issue-comments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Xpanse issue ID to retrieve updates for. | Required | 
| created_after | Returns only comments created after the provided timestamp (ISO8601 format YYYY-MM-DDTHH:MM:SSZ). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IssueComment.created | Date | The timestamp of when the Issue update occurred | 
| Expanse.IssueComment.id | String | The unique ID of the issue update event | 
| Expanse.IssueComment.issue_id | String | The unique ID of the issue that was updated | 
| Expanse.IssueComment.previousValue | String | The previous value of the field that was updated | 
| Expanse.IssueComment.updateType | String | The type of update that occurred, valid types are ProgressStatus, ActivityStatus, Priority, Assignee, and Comment | 
| Expanse.IssueComment.user.username | String | The username of the user who made the update | 
| Expanse.IssueComment.value | String | The new value of the field that was updated | 


#### Command Example

```!expanse-get-issue-comments issue_id="2b0ea80c-2277-34dd-9c55-005922ba640a" created_after="2020-12-07T09:34:36.20917328Z"```

#### Context Example

```json
{
    "Expanse": {
        "IssueComment": [
            {
                "created": "2020-12-07T10:53:31.168649Z",
                "id": "4f764ed5-1a51-413c-94b4-ec50cae9b8ba",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": "demo+api.external.vandelay+panw@expanseinc.com",
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-07T11:03:05.724596Z",
                "id": "b51b0312-e2c0-41f3-b59c-fe5da4167ebd",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": "demo+api.external.vandelay+panw@expanseinc.com",
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-07T12:02:37.202021Z",
                "id": "faf8840f-c41a-4049-9fd4-58e6bd039fc7",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": "demo+api.external.vandelay+panw@expanseinc.com",
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-07T12:17:31.781217Z",
                "id": "dcf95534-851b-432b-afe6-8898f89043b2",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": "demo+api.external.vandelay+panw@expanseinc.com",
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-14T18:31:39.117534Z",
                "id": "f246ed63-9ae2-4d12-88aa-2e8ec383c56f",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": "demo+api.external.vandelay+panw@expanseinc.com",
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-18T18:03:30.331013Z",
                "id": "97a5e56c-2363-4aaa-a869-d007f74de97a",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": "demo+api.external.vandelay+panw@expanseinc.com",
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-18T18:04:06.920178Z",
                "id": "58c76133-70a0-40f0-b1af-11abbd51ae46",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": "demo+api.external.vandelay+panw@expanseinc.com",
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-18T18:08:11.503224Z",
                "id": "9ccac6c8-1a15-4f79-8de2-0e068713d3b4",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": "demo+api.external.vandelay+panw@expanseinc.com",
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-18T18:11:15.311531Z",
                "id": "60e0f9af-a622-49d2-a394-7ec28e349eb0",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": "demo+api.external.vandelay+panw@expanseinc.com",
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-18T18:13:21.301817Z",
                "id": "b3825b75-97c5-488b-bc1e-e6347fa8ff23",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": "demo+api.external.vandelay+panw@expanseinc.com",
                "value": "XSOAR Test Playbook Comment"
            }
        ]
    }
}
```

#### Human Readable Output

>### Expanse Issue Comments
>
>|User|Value|Created|
>|---|---|---|
>| <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment | 2020-12-07T10:53:31.168649Z |
>| <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment | 2020-12-07T11:03:05.724596Z |
>| <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment | 2020-12-07T12:02:37.202021Z |
>| <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment | 2020-12-07T12:17:31.781217Z |
>| <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment | 2020-12-14T18:31:39.117534Z |
>| <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment | 2020-12-18T18:03:30.331013Z |
>| <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment | 2020-12-18T18:04:06.920178Z |
>| <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment | 2020-12-18T18:08:11.503224Z |
>| <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment | 2020-12-18T18:11:15.311531Z |
>| <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment | 2020-12-18T18:13:21.301817Z |


### expanse-update-issue

***
Update a property of an Xpanse issue.


#### Base Command

`expanse-update-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Xpanse issue ID to update. | Required | 
| update_type | Type of update. Possible values are: Assignee, Comment, Priority, ProgressStatus. | Required | 
| value | Updated value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IssueUpdate.created | Date | The timestamp of when the Issue update occurred | 
| Expanse.IssueUpdate.id | String | The unique ID of the issue update event | 
| Expanse.IssueUpdate.issue_id | String | The unique ID of the issue that was updated | 
| Expanse.IssueUpdate.previousValue | String | The previous value of the field that was updated | 
| Expanse.IssueUpdate.updateType | String | The type of update that occurred, valid types are ProgressStatus, ActivityStatus, Priority, Assignee, and Comment | 
| Expanse.IssueUpdate.user.username | String | The username of the user who made the update | 
| Expanse.IssueUpdate.value | String | The new value of the field that was updated | 


#### Command Example

```!expanse-update-issue issue_id="2b0ea80c-2277-34dd-9c55-005922ba640a" update_type="Comment" value="XSOAR Test Playbook Comment"```

#### Context Example

```json
{
    "Expanse": {
        "IssueUpdate": {
            "created": "2020-12-18T18:13:21.301817Z",
            "id": "b3825b75-97c5-488b-bc1e-e6347fa8ff23",
            "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
            "previousValue": null,
            "updateType": "Comment",
            "user": {
                "username": "demo+api.external.vandelay+panw@expanseinc.com"
            },
            "value": "XSOAR Test Playbook Comment"
        }
    }
}
```

#### Human Readable Output

>### Results
>
>|created|id|issueId|previousValue|updateType|user|value|
>|---|---|---|---|---|---|---|
>| 2020-12-18T18:13:21.301817Z | b3825b75-97c5-488b-bc1e-e6347fa8ff23 | 2b0ea80c-2277-34dd-9c55-005922ba640a |  | Comment | username: <demo+api.external.vandelay+panw@expanseinc.com> | XSOAR Test Playbook Comment |


### expanse-get-issue

***
Retrieve Xpanse issue by issue ID.


#### Base Command

`expanse-get-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | ID of the Xpanse issue to retrieve. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Issue.activityStatus | String | Activity status of issue, whether the issue is active or inactive | 
| Expanse.Issue.annotations.tags.id | String | The Internal Xpanse tag id of the customer added tag | 
| Expanse.Issue.annotations.tags.name | String | The tag name of the customer added tag | 
| Expanse.Issue.assets.assetKey | String | Key used to access the asset in the respective Xpanse asset API | 
| Expanse.Issue.assets.assetType | String | The type of asset the issue primarily relates to | 
| Expanse.Issue.assets.displayName | String | A friendly name for the asset | 
| Expanse.Issue.assets.id | String | Internal Xpanse ID the asset | 
| Expanse.Issue.assigneeUsername | String | The username of the user that has been assigned to the issue | 
| Expanse.Issue.businessUnits.id | String | The internal Xpanse ID for the business unit the affected asset belongs to | 
| Expanse.Issue.businessUnits.name | String | The name of the business unit the affected asset belongs to | 
| Expanse.Issue.category | String | The general category of the issue | 
| Expanse.Issue.certificate.formattedIssuerOrg | String | The formatted issuer org in the certificate | 
| Expanse.Issue.certificate.id | String | The Internal Xpanse certificate ID | 
| Expanse.Issue.certificate.issuer | String | The issuer in the certificate | 
| Expanse.Issue.certificate.issuerAlternativeNames | String | The issuer alternative names in the certificate | 
| Expanse.Issue.certificate.issuerCountry | String | The issuer country in the certificate | 
| Expanse.Issue.certificate.issuerEmail | String | The issuer email in the certificate | 
| Expanse.Issue.certificate.issuerLocality | String | The issuer locality in the certificate | 
| Expanse.Issue.certificate.issuerName | String | The issuer name in the certificate | 
| Expanse.Issue.certificate.issuerOrg | String | The issuer org in the certificate | 
| Expanse.Issue.certificate.issuerOrgUnit | String | The issuer org unit in the certificate | 
| Expanse.Issue.certificate.issuerState | String | The issuer state in the certificate | 
| Expanse.Issue.certificate.md5Hash | String | The md5hash in the certificate | 
| Expanse.Issue.certificate.pemSha1 | String | The pemSha1 in the certificate | 
| Expanse.Issue.certificate.pemSha256 | String | The pemSha256 in the certificate | 
| Expanse.Issue.certificate.publicKey | String | The public key in the certificate | 
| Expanse.Issue.certificate.publicKeyAlgorithm | String | The public key algorithm in the certificate | 
| Expanse.Issue.certificate.publicKeyBits | Number | The public key bits in the certificate | 
| Expanse.Issue.certificate.publicKeyModulus | String | The public key modulus in the certificate | 
| Expanse.Issue.certificate.publicKeyRsaExponent | Number | The public key RSA exponent in the certificate | 
| Expanse.Issue.certificate.publicKeySpki | String | The public key Spki in the certificate | 
| Expanse.Issue.certificate.serialNumber | String | The serial number in the certificate | 
| Expanse.Issue.certificate.signatureAlgorithm | String | The signature algorithm in the certificate | 
| Expanse.Issue.certificate.subject | String | The subject in the certificate | 
| Expanse.Issue.certificate.subjectAlternativeNames | String | The subject alternative names in the certificate | 
| Expanse.Issue.certificate.subjectCountry | String | The subject country in the certificate | 
| Expanse.Issue.certificate.subjectEmail | String | The subject email in the certificate | 
| Expanse.Issue.certificate.subjectLocality | String | The subject locality in the certificate | 
| Expanse.Issue.certificate.subjectName | String | The subject name in the certificate | 
| Expanse.Issue.certificate.subjectOrg | String | The subject org in the certificate | 
| Expanse.Issue.certificate.subjectOrgUnit | String | The subject org unit in the certificate | 
| Expanse.Issue.certificate.subjectState | String | The subject state in the certificate | 
| Expanse.Issue.certificate.validNotAfter | Date | The valid not after date in the certificate | 
| Expanse.Issue.certificate.validNotBefore | Date | The valid not before date in the certificate | 
| Expanse.Issue.certificate.version | String | The version in the certificate | 
| Expanse.Issue.cloudManagementStatus.id | String | The ID of the cloud management status |
| Expanse.Issue.cloudManagementStatus.name | String | The friendly name of the cloud management status |
| Expanse.Issue.created | Date | When the issue instance was created | 
| Expanse.Issue.domain | String | Domain name of the issue | 
| Expanse.Issue.headline | String | A brief summary of the issue | 
| Expanse.Issue.helpText | String | Why Xpanse this type of issue should be avoided | 
| Expanse.Issue.id | String | The internal Xpanse ID of the issue | 
| Expanse.Issue.initialEvidence.certificate.formattedIssuerOrg | String | The formatted issuer org in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.id | String | The Internal Xpanse certificate ID in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuer | String | The issuer in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerAlternativeNames | String | The issuer alternative names in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerCountry | String | The issuer country in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerEmail | String | The issuer email in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerLocality | String | The issuer locality in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerName | String | The issuer name in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerOrg | String | The issuer org in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerOrgUnit | String | The issuer org unit in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.issuerState | String | The issuer state in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.md5Hash | String | The md5hash in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.pemSha1 | String | The pemSha1 in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.pemSha256 | String | The pemSha256 in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKey | String | The public key in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKeyAlgorithm | String | The public key algorithm in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKeyBits | Number | The public key bits in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKeyModulus | String | The public key modulus in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKeyRsaExponent | Number | The public key RSA exponent in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.publicKeySpki | String | The public key Spki in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.serialNumber | String | The serial number in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.signatureAlgorithm | String | The signature algorithm in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subject | String | The subject in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectAlternativeNames | String | The subject alternative names in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectCountry | String | The subject country in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectEmail | String | The subject email in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectLocality | String | The subject locality in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectName | String | The subject name in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectOrg | String | The subject org in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectOrgUnit | String | The subject org unit in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.subjectState | String | The subject state in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.validNotAfter | Date | The valid not after date in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.validNotBefore | Date | The valid not before date in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.certificate.version | String | The version in the certificate in the initial observation | 
| Expanse.Issue.initialEvidence.cipherSuite | String | The cipher suite in the initial observation | 
| Expanse.Issue.initialEvidence.configuration._type | String | The type of configuration data in the initial observation | 
| Expanse.Issue.initialEvidence.configuration.validWhenScanned | Boolean | Whether the configuration was valid in the initial observation | 
| Expanse.Issue.initialEvidence.discoveryType | String | The discovery type in the initial observation | 
| Expanse.Issue.initialEvidence.domain | String | The domain name in the initial observation | 
| Expanse.Issue.initialEvidence.evidenceType | String | The evidence type of the initial observation | 
| Expanse.Issue.initialEvidence.exposureId | String | The exposure ID in the initial observation | 
| Expanse.Issue.initialEvidence.exposureType | String | The exposure type in the initial observation | 
| Expanse.Issue.initialEvidence.geolocation.latitude | Number | The latitude in the initial observation | 
| Expanse.Issue.initialEvidence.geolocation.longitude | Number | The longitude in the initial observation | 
| Expanse.Issue.initialEvidence.geolocation.city | String | The city name in the initial observation | 
| Expanse.Issue.initialEvidence.geolocation.regionCode | String | The region code in the initial observation | 
| Expanse.Issue.initialEvidence.geolocation.countryCode | String | The country code in the initial observation | 
| Expanse.Issue.initialEvidence.ip | String | The IPv4 address in the initial observation | 
| Expanse.Issue.initialEvidence.portNumber | Number | The port number in the initial observation | 
| Expanse.Issue.initialEvidence.portProtocol | String | The port protocol in the initial observation | 
| Expanse.Issue.initialEvidence.serviceId | String | The Service ID in the initial observation | 
| Expanse.Issue.initialEvidence.serviceProperties.serviceProperties.name | String | The service property name in the initial observation | 
| Expanse.Issue.initialEvidence.serviceProperties.serviceProperties.reason | String | The service property reason in the initial observation | 
| Expanse.Issue.initialEvidence.timestamp | Date | The timestamp of the initial observation | 
| Expanse.Issue.initialEvidence.tlsVersion | String | The TLS version found in the initial observation | 
| Expanse.Issue.ip | String | The IPv4 address last associated with the issue | 
| Expanse.Issue.issueType.archived | Boolean | Whether the issue type is archived | 
| Expanse.Issue.issueType.id | String | The ID of the issue type | 
| Expanse.Issue.issueType.name | String | The name of the issue type | 
| Expanse.Issue.latestEvidence.certificate.formattedIssuerOrg | String | The formatted issuer org in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.id | String | The Internal Xpanse certificate ID in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuer | String | The issuer in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerAlternativeNames | String | The issuer alternative names in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerCountry | String | The issuer country in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerEmail | String | The issuer email in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerLocality | String | The issuer locality in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerName | String | The issuer name in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerOrg | String | The issuer org in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerOrgUnit | String | The issuer org unit in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.issuerState | String | The issuer state in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.md5Hash | String | The md5hash in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.pemSha1 | String | The pemSha1 in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.pemSha256 | String | The pemSha256 in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKey | String | The public key in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKeyAlgorithm | String | The public key algorithm in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKeyBits | Number | The public key bits in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKeyModulus | String | The public key modulus in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKeyRsaExponent | Number | The public key RSA exponent in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.publicKeySpki | String | The public key Spki in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.serialNumber | String | The serial number in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.signatureAlgorithm | String | The signature algorithm in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subject | String | The subject in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectAlternativeNames | String | The subject alternative names in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectCountry | String | The subject country in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectEmail | String | The subject email in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectLocality | String | The subject locality in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectName | String | The subject name in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectOrg | String | The subject org in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectOrgUnit | String | The subject org unit in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.subjectState | String | The subject state in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.validNotAfter | Date | The valid not after date in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.validNotBefore | Date | The valid not before date in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.certificate.version | String | The version in the certificate in the most recent observation | 
| Expanse.Issue.latestEvidence.cipherSuite | String | The cipher suite detected during the most recent observation | 
| Expanse.Issue.latestEvidence.configuration._type | String | The type of configuration data in the most recent observation | 
| Expanse.Issue.latestEvidence.configuration.validWhenScanned | Boolean | Whether the configuration was valid in the most recent observation | 
| Expanse.Issue.latestEvidence.discoveryType | String | The discovery type in the most recent observation | 
| Expanse.Issue.latestEvidence.domain | String | The domain name in the most recent observation | 
| Expanse.Issue.latestEvidence.evidenceType | String | The evidence type of the most recent observation | 
| Expanse.Issue.latestEvidence.exposureId | String | The exposure ID in the most recent observation | 
| Expanse.Issue.latestEvidence.exposureType | String | The exposure type in the most recent observation | 
| Expanse.Issue.latestEvidence.geolocation.latitude | Number | The latitude in the most recent observation | 
| Expanse.Issue.latestEvidence.geolocation.longitude | Number | The latitude in the most recent observation | 
| Expanse.Issue.latestEvidence.geolocation.city | String | The city name in the most recent observation | 
| Expanse.Issue.latestEvidence.geolocation.regionCode | String | The region code in the most recent observation | 
| Expanse.Issue.latestEvidence.geolocation.countryCode | String | The country code in the most recent observation | 
| Expanse.Issue.latestEvidence.ip | String | The IPv4 address in the most recent observation | 
| Expanse.Issue.latestEvidence.portNumber | Number | The port number in the most recent observation | 
| Expanse.Issue.latestEvidence.portProtocol | String | The port protocol in the most recent observation | 
| Expanse.Issue.latestEvidence.serviceId | String | The Service ID in the most recent observation | 
| Expanse.Issue.latestEvidence.serviceProperties.serviceProperties.name | String | The service property name in the most recent observation | 
| Expanse.Issue.latestEvidence.serviceProperties.serviceProperties.reason | String | The service property reason in the most recent observation | 
| Expanse.Issue.latestEvidence.timestamp | Date | The timestamp of the most recent observation | 
| Expanse.Issue.latestEvidence.tlsVersion | String | The TLS version found in the most recent observation | 
| Expanse.Issue.modified | Date | The timestamp of when the issue was last modified | 
| Expanse.Issue.portNumber | Number | The port number the issue was detected on | 
| Expanse.Issue.portProtocol | String | The port protocol the issue was detected on | 
| Expanse.Issue.priority | String | The priority of the issue | 
| Expanse.Issue.progressStatus | String | The progress status of the issue | 
| Expanse.Issue.providers.id | String | The ID of the provider the issue was detected on | 
| Expanse.Issue.providers.name | String | The name of the provider the issue was detected on | 


#### Command Example

```!expanse-get-issue issue_id="2b0ea80c-2277-34dd-9c55-005922ba640a"```

#### Context Example

```json
{
    "Expanse": {
        "Issue": {
            "activityStatus": "Active",
            "annotations": {
                "tags": []
            },
            "assets": [
                {
                    "assetKey": "gdRHmkxmGwWpaUtAuge6IQ==",
                    "assetType": "Certificate",
                    "displayName": "*.thespeedyou.com",
                    "id": "724a1137-ee3f-381f-95f2-ea0441db22d0"
                }
            ],
            "assigneeUsername": "Unassigned",
            "businessUnits": [
                {
                    "id": "f738ace6-f451-4f31-898d-a12afa204b2a",
                    "name": "PANW VanDelay Dev"
                }
            ],
            "category": "Attack Surface Reduction",
            "certificate": {
                "formattedIssuerOrg": "GeoTrust",
                "id": "81d4479a-4c66-3b05-a969-4b40ba07ba21",
                "issuer": "C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3",
                "issuerAlternativeNames": "",
                "issuerCountry": "US",
                "issuerEmail": null,
                "issuerLocality": null,
                "issuerName": "GeoTrust SSL CA - G3",
                "issuerOrg": "GeoTrust Inc.",
                "issuerOrgUnit": null,
                "issuerState": null,
                "md5Hash": "gdRHmkxmGwWpaUtAuge6IQ==",
                "pemSha1": "p0y_sHlFdp5rPOw8aWrH2Qc331Q=",
                "pemSha256": "w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=",
                "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB",
                "publicKeyAlgorithm": "RSA",
                "publicKeyBits": 2048,
                "publicKeyModulus": "bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d",
                "publicKeyRsaExponent": 65537,
                "publicKeySpki": "5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA=",
                "serialNumber": "34287766128589078095374161204025316200",
                "signatureAlgorithm": "SHA256withRSA",
                "subject": "C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com",
                "subjectAlternativeNames": "*.thespeedyou.com thespeedyou.com",
                "subjectCountry": "IN",
                "subjectEmail": null,
                "subjectLocality": "Pune",
                "subjectName": "*.thespeedyou.com",
                "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.",
                "subjectOrgUnit": "Management Services",
                "subjectState": "Maharashtra",
                "validNotAfter": "2017-01-18T23:59:59Z",
                "validNotBefore": "2015-01-19T00:00:00Z",
                "version": "3"
            },
            "created": "2020-09-23T01:44:37.415249Z",
            "domain": null,
            "headline": "Insecure TLS at 52.6.192.223:443",
            "helpText": "This service should not be visible on the public Internet.",
            "id": "2b0ea80c-2277-34dd-9c55-005922ba640a",
            "initialEvidence": {
                "certificate": {
                    "formattedIssuerOrg": null,
                    "id": "81d4479a-4c66-3b05-a969-4b40ba07ba21",
                    "issuer": "C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3",
                    "issuerAlternativeNames": "",
                    "issuerCountry": "US",
                    "issuerEmail": null,
                    "issuerLocality": null,
                    "issuerName": "GeoTrust SSL CA - G3",
                    "issuerOrg": "GeoTrust Inc.",
                    "issuerOrgUnit": null,
                    "issuerState": null,
                    "md5Hash": "gdRHmkxmGwWpaUtAuge6IQ==",
                    "pemSha1": "p0y_sHlFdp5rPOw8aWrH2Qc331Q=",
                    "pemSha256": "w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=",
                    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB",
                    "publicKeyAlgorithm": "RSA",
                    "publicKeyBits": 2048,
                    "publicKeyModulus": "bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d",
                    "publicKeyRsaExponent": 65537,
                    "publicKeySpki": "5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA=",
                    "serialNumber": "34287766128589078095374161204025316200",
                    "signatureAlgorithm": "SHA256withRSA",
                    "subject": "C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com",
                    "subjectAlternativeNames": "*.thespeedyou.com thespeedyou.com",
                    "subjectCountry": "IN",
                    "subjectEmail": null,
                    "subjectLocality": "Pune",
                    "subjectName": "*.thespeedyou.com",
                    "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.",
                    "subjectOrgUnit": "Management Services",
                    "subjectState": "Maharashtra",
                    "validNotAfter": "2017-01-18T23:59:59Z",
                    "validNotBefore": "2015-01-19T00:00:00Z",
                    "version": "3"
                },
                "cipherSuite": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
                "configuration": {
                    "_type": "WebServerConfiguration",
                    "applicationServerSoftware": "",
                    "certificateId": "74K3sPuBY6wi7US9poLZdg==",
                    "hasApplicationServerSoftware": false,
                    "hasServerSoftware": true,
                    "hasUnencryptedLogin": false,
                    "htmlPasswordAction": "",
                    "htmlPasswordField": "",
                    "httpAuthenticationMethod": "",
                    "httpAuthenticationRealm": "",
                    "httpHeaders": [
                        {
                            "name": "Set-Cookie",
                            "value": "JSESSIONID=6E9656EFE98ED2DD7447C779504A4994; Path=/; Secure; HttpOnly"
                        },
                        {
                            "name": "X-FRAME-OPTIONS",
                            "value": "DENY"
                        },
                        {
                            "name": "Content-Type",
                            "value": "text/html;charset=UTF-8"
                        },
                        {
                            "name": "Content-Language",
                            "value": "en-US"
                        },
                        {
                            "name": "Transfer-Encoding",
                            "value": "chunked"
                        },
                        {
                            "name": "Vary",
                            "value": "Accept-Encoding"
                        },
                        {
                            "name": "Date",
                            "value": "xxxxxxxxxx"
                        },
                        {
                            "name": "Server",
                            "value": "WSO2 Carbon Server"
                        }
                    ],
                    "httpStatusCode": "200",
                    "isLoadBalancer": false,
                    "loadBalancer": "",
                    "loadBalancerPool": "",
                    "serverSoftware": "WSO2 Carbon Server"
                },
                "discoveryType": "DirectlyDiscovered",
                "domain": null,
                "evidenceType": "ScanEvidence",
                "exposureId": "af2672a7-cf47-3a6d-9ecd-8c356d57d250",
                "exposureType": "HTTP_SERVER",
                "geolocation": null,
                "ip": "52.6.192.223",
                "portNumber": 443,
                "portProtocol": "TCP",
                "serviceId": "355452a1-a39b-369e-9aad-4ca129ec9422",
                "serviceProperties": {
                    "serviceProperties": [
                        {
                            "name": "ExpiredWhenScannedCertificate",
                            "reason": "{\"validWhenScanned\":false}"
                        },
                        {
                            "name": "MissingCacheControlHeader",
                            "reason": null
                        },
                        {
                            "name": "MissingContentSecurityPolicyHeader",
                            "reason": null
                        },
                        {
                            "name": "MissingPublicKeyPinsHeader",
                            "reason": null
                        },
                        {
                            "name": "MissingStrictTransportSecurityHeader",
                            "reason": null
                        },
                        {
                            "name": "MissingXContentTypeOptionsHeader",
                            "reason": null
                        },
                        {
                            "name": "MissingXXssProtectionHeader",
                            "reason": null
                        },
                        {
                            "name": "ServerSoftware",
                            "reason": "{\"serverSoftware\":\"WSO2 Carbon Server\"}"
                        },
                        {
                            "name": "WildcardCertificate",
                            "reason": "{\"validWhenScanned\":false}"
                        }
                    ]
                },
                "timestamp": "2020-08-24T00:00:00Z",
                "tlsVersion": "TLS 1.2"
            },
            "ip": "52.6.192.223",
            "issueType": {
                "archived": null,
                "id": "InsecureTLS",
                "name": "Insecure TLS"
            },
            "latestEvidence": {
                "certificate": {
                    "formattedIssuerOrg": null,
                    "id": "81d4479a-4c66-3b05-a969-4b40ba07ba21",
                    "issuer": "C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3",
                    "issuerAlternativeNames": "",
                    "issuerCountry": "US",
                    "issuerEmail": null,
                    "issuerLocality": null,
                    "issuerName": "GeoTrust SSL CA - G3",
                    "issuerOrg": "GeoTrust Inc.",
                    "issuerOrgUnit": null,
                    "issuerState": null,
                    "md5Hash": "gdRHmkxmGwWpaUtAuge6IQ==",
                    "pemSha1": "p0y_sHlFdp5rPOw8aWrH2Qc331Q=",
                    "pemSha256": "w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=",
                    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB",
                    "publicKeyAlgorithm": "RSA",
                    "publicKeyBits": 2048,
                    "publicKeyModulus": "bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d",
                    "publicKeyRsaExponent": 65537,
                    "publicKeySpki": "5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA=",
                    "serialNumber": "34287766128589078095374161204025316200",
                    "signatureAlgorithm": "SHA256withRSA",
                    "subject": "C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com",
                    "subjectAlternativeNames": "*.thespeedyou.com thespeedyou.com",
                    "subjectCountry": "IN",
                    "subjectEmail": null,
                    "subjectLocality": "Pune",
                    "subjectName": "*.thespeedyou.com",
                    "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.",
                    "subjectOrgUnit": "Management Services",
                    "subjectState": "Maharashtra",
                    "validNotAfter": "2017-01-18T23:59:59Z",
                    "validNotBefore": "2015-01-19T00:00:00Z",
                    "version": "3"
                },
                "cipherSuite": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
                "configuration": {
                    "_type": "WebServerConfiguration",
                    "applicationServerSoftware": "",
                    "certificateId": "74K3sPuBY6wi7US9poLZdg==",
                    "hasApplicationServerSoftware": false,
                    "hasServerSoftware": true,
                    "hasUnencryptedLogin": false,
                    "htmlPasswordAction": "",
                    "htmlPasswordField": "",
                    "httpAuthenticationMethod": "",
                    "httpAuthenticationRealm": "",
                    "httpHeaders": [
                        {
                            "name": "Set-Cookie",
                            "value": "JSESSIONID=E5948E498E58CFB6413087A3D3D2908C; Path=/; Secure; HttpOnly"
                        },
                        {
                            "name": "Location",
                            "value": "https://52.6.192.223/carbon/admin/index.jsp"
                        },
                        {
                            "name": "Content-Type",
                            "value": "text/html;charset=UTF-8"
                        },
                        {
                            "name": "Content-Length",
                            "value": "0"
                        },
                        {
                            "name": "Date",
                            "value": "xxxxxxxxxx"
                        },
                        {
                            "name": "Server",
                            "value": "WSO2 Carbon Server"
                        }
                    ],
                    "httpStatusCode": "302",
                    "isLoadBalancer": false,
                    "loadBalancer": "",
                    "loadBalancerPool": "",
                    "serverSoftware": "WSO2 Carbon Server"
                },
                "discoveryType": "DirectlyDiscovered",
                "domain": null,
                "evidenceType": "ScanEvidence",
                "exposureId": "af2672a7-cf47-3a6d-9ecd-8c356d57d250",
                "exposureType": "HTTP_SERVER",
                "geolocation": null,
                "ip": "52.6.192.223",
                "portNumber": 443,
                "portProtocol": "TCP",
                "serviceId": "355452a1-a39b-369e-9aad-4ca129ec9422",
                "serviceProperties": {
                    "serviceProperties": [
                        {
                            "name": "ExpiredWhenScannedCertificate",
                            "reason": "{\"validWhenScanned\":false}"
                        },
                        {
                            "name": "ServerSoftware",
                            "reason": "{\"serverSoftware\":\"WSO2 Carbon Server\"}"
                        },
                        {
                            "name": "WildcardCertificate",
                            "reason": "{\"validWhenScanned\":false}"
                        }
                    ]
                },
                "timestamp": "2020-09-22T00:00:00Z",
                "tlsVersion": "TLS 1.2"
            },
            "modified": "2020-12-18T18:13:24.311442Z",
            "portNumber": 443,
            "portProtocol": "TCP",
            "priority": "Medium",
            "progressStatus": "InProgress",
            "providers": [
                {
                    "id": "AWS",
                    "name": "Amazon Web Services"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Expanse Issues
>
>|Id|Headline|Issue Type|Category|Ip|Port Protocol|Port Number|Domain|Certificate|Priority|Progress Status|Activity Status|Providers|Assignee Username|Business Units|Created|Modified|Annotations|Assets|Help Text|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2b0ea80c-2277-34dd-9c55-005922ba640a | Insecure TLS at 52.6.192.223:443 | id: InsecureTLS<br/>name: Insecure TLS<br/>archived: null | Attack Surface Reduction | 52.6.192.223 | TCP | 443 |  | id: 81d4479a-4c66-3b05-a969-4b40ba07ba21<br/>md5Hash: gdRHmkxmGwWpaUtAuge6IQ==<br/>issuer: C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3<br/>issuerAlternativeNames: <br/>issuerCountry: US<br/>issuerEmail: null<br/>issuerLocality: null<br/>issuerName: GeoTrust SSL CA - G3<br/>issuerOrg: GeoTrust Inc.<br/>formattedIssuerOrg: GeoTrust<br/>issuerOrgUnit: null<br/>issuerState: null<br/>publicKey: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB<br/>publicKeyAlgorithm: RSA<br/>publicKeyRsaExponent: 65537<br/>signatureAlgorithm: SHA256withRSA<br/>subject: C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com<br/>subjectAlternativeNames: *.thespeedyou.com thespeedyou.com<br/>subjectCountry: IN<br/>subjectEmail: null<br/>subjectLocality: Pune<br/>subjectName: *.thespeedyou.com<br/>subjectOrg: Sears IT and Management Services India Pvt. Ltd.<br/>subjectOrgUnit: Management Services<br/>subjectState: Maharashtra<br/>serialNumber: 34287766128589078095374161204025316200<br/>validNotBefore: 2015-01-19T00:00:00Z<br/>validNotAfter: 2017-01-18T23:59:59Z<br/>version: 3<br/>publicKeyBits: 2048<br/>pemSha256: w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=<br/>pemSha1: p0y_sHlFdp5rPOw8aWrH2Qc331Q=<br/>publicKeyModulus: bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d<br/>publicKeySpki: 5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA= | Medium | InProgress | Active | {'id': 'AWS', 'name': 'Amazon Web Services'} | Unassigned | {'id': 'f738ace6-f451-4f31-898d-a12afa204b2a', 'name': 'PANW VanDelay Dev'} | 2020-09-23T01:44:37.415249Z | 2020-12-18T18:13:24.311442Z | tags:  | {'id': '724a1137-ee3f-381f-95f2-ea0441db22d0', 'assetKey': 'gdRHmkxmGwWpaUtAuge6IQ==', 'assetType': 'Certificate', 'displayName': '*.thespeedyou.com'} | This service should not be visible on the public Internet. |

### expanse-get-service

***
Retrieve Xpanse issue by service ID.


#### Base Command

`expanse-get-service`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | ID of the Xpanse service to retrieve. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Service.activityStatus | String | Activity status of service, whether the service is active or inactive | 
| Expanse.Service.annotations.tags.id | String | The Internal Xpanse tag id of the customer added tag | 
| Expanse.Service.annotations.tags.name | String | The tag name of the customer added tag | 
| Expanse.Service.assets.assetKey | String | Key used to access the asset in the respective Xpanse asset API | 
| Expanse.Service.assets.assetType | String | The type of asset the issue primarily relates to | 
| Expanse.Service.assets.displayName | String | A friendly name for the asset | 
| Expanse.Service.assets.id | String | Internal Xpanse ID the asset | 
| Expanse.Service.assets.referenceReason.id | String | ID for asset reference type | 
| Expanse.Service.assets.referenceReason.name | String | Description for asset reference reason | 
| Expanse.Service.businessUnits.id | String | The internal Xpanse ID for the business unit the affected asset belongs to | 
| Expanse.Service.businessUnits.name | String | The name of the business unit the affected asset belongs to | 
| Expanse.Service.certificates.assetId | String | Internal Asset ID of certificate | 
| Expanse.Service.certificates.firstObserved | Date | First observation of certificate | 
| Expanse.Service.certificates.lastObserved | Date | Most recent observation of certificate | 
| Expanse.Service.certificates.certificate.formattedIssuerOrg | String | The formatted issuer org in the certificate | 
| Expanse.Service.certificates.certificate.id | String | The Internal Xpanse certificate ID | 
| Expanse.Service.certificates.certificate.issuer | String | The issuer in the certificate | 
| Expanse.Service.certificates.certificate.issuerAlternativeNames | String | The issuer alternative names in the certificate | 
| Expanse.Service.certificates.certificate.issuerCountry | String | The issuer country in the certificate | 
| Expanse.Service.certificates.certificate.issuerEmail | String | The issuer email in the certificate | 
| Expanse.Service.certificates.certificate.issuerLocality | String | The issuer locality in the certificate | 
| Expanse.Service.certificates.certificate.issuerName | String | The issuer name in the certificate | 
| Expanse.Service.certificates.certificate.issuerOrg | String | The issuer org in the certificate | 
| Expanse.Service.certificates.certificate.issuerOrgUnit | String | The issuer org unit in the certificate | 
| Expanse.Service.certificates.certificate.issuerState | String | The issuer state in the certificate | 
| Expanse.Service.certificates.certificate.md5Hash | String | The md5hash in the certificate | 
| Expanse.Service.certificates.certificate.pemSha1 | String | The pemSha1 in the certificate | 
| Expanse.Service.certificates.certificate.pemSha256 | String | The pemSha256 in the certificate | 
| Expanse.Service.certificates.certificate.publicKey | String | The public key in the certificate | 
| Expanse.Service.certificates.certificate.publicKeyAlgorithm | String | The public key algorithm in the certificate | 
| Expanse.Service.certificates.certificate.publicKeyBits | Number | The public key bits in the certificate | 
| Expanse.Service.certificates.certificate.publicKeyModulus | String | The public key modulus in the certificate | 
| Expanse.Service.certificates.certificate.publicKeyRsaExponent | Number | The public key RSA exponent in the certificate | 
| Expanse.Service.certificates.certificate.publicKeySpki | String | The public key Spki in the certificate | 
| Expanse.Service.certificates.certificate.serialNumber | String | The serial number in the certificate | 
| Expanse.Service.certificates.certificate.signatureAlgorithm | String | The signature algorithm in the certificate | 
| Expanse.Service.certificates.certificate.subject | String | The subject in the certificate | 
| Expanse.Service.certificates.certificate.subjectAlternativeNames | String | The subject alternative names in the certificate | 
| Expanse.Service.certificates.certificate.subjectCountry | String | The subject country in the certificate | 
| Expanse.Service.certificates.certificate.subjectEmail | String | The subject email in the certificate | 
| Expanse.Service.certificates.certificate.subjectLocality | String | The subject locality in the certificate | 
| Expanse.Service.certificates.certificate.subjectName | String | The subject name in the certificate | 
| Expanse.Service.certificates.certificate.subjectOrg | String | The subject org in the certificate | 
| Expanse.Service.certificates.certificate.subjectOrgUnit | String | The subject org unit in the certificate | 
| Expanse.Service.certificates.certificate.subjectState | String | The subject state in the certificate | 
| Expanse.Service.certificates.certificate.validNotAfter | Date | The valid not after date in the certificate | 
| Expanse.Service.certificates.certificate.validNotBefore | Date | The valid not before date in the certificate | 
| Expanse.Service.certificates.certificate.version | String | The version in the certificate | 
| Expanse.Service.classifications.details.firstObserved | Date | When the service instance was first observed | 
| Expanse.Service.classifications.details.lastObserved | Date | When the service instance was last observed | 
| Expanse.Service.classifications.details.value.applicationServerSoftware | String | Application Server Software value of the service classification | 
| Expanse.Service.classifications.details.value.bgpOpenResponse | String | BGP Open value of the service classification | 
| Expanse.Service.classifications.details.value.bgpNotificationResponse.data | String | BGP Notification Data value of the service classification | 
| Expanse.Service.classifications.details.value.bgpNotificationResponse.errorCode | String | BGP Notification Error Code value of the service classification | 
| Expanse.Service.classifications.details.value.bgpNotificationResponse.errorSubCode | String | BGP Notification Sub-Error Code value of the service classification | 
| Expanse.Service.classifications.details.value.bindVersions | String | Bind version value of the service classification | 
| Expanse.Service.classifications.details.value.certificateId | String | Certificate Id value of the service classification | 
| Expanse.Service.classifications.details.value.connectResponse.statusCode | String | Connect Response Status Code value of the service classification | 
| Expanse.Service.classifications.details.value.connectResponse.responseLines | String | Connect Response Response value of the service classification | 
| Expanse.Service.classifications.details.value.credSspProtocol | Boolean | Cred SSP Protocol of the service classification | 
| Expanse.Service.classifications.details.value.exchanges.request.arguments | String | Exchange Request Arguments value of the service classification | 
| Expanse.Service.classifications.details.value.exchanges.request.command | String | Exchange Request Command value of the service classification | 
| Expanse.Service.classifications.details.value.exchanges.response.statusCode | String | Connect Response Status Code value of the service classification | 
| Expanse.Service.classifications.details.value.exchanges.response.responseLines | String | Connect Response Response value of the service classification | 
| Expanse.Service.classifications.details.value.extraInfo | String | Extra Info about the service classification | 
| Expanse.Service.classifications.details.value.htmlPasswordAction | String | HTML Password Action value of the service classification | 
| Expanse.Service.classifications.details.value.htmlPasswordField | String | HTML Password Field value of the service classification | 
| Expanse.Service.classifications.details.value.htmlPasswordAction | String | HTML Password Action value of the service classification | 
| Expanse.Service.classifications.details.value.httpAuthenticationMethods | String | HTTP Authentication Methods value of the service classification | 
| Expanse.Service.classifications.details.value.httpAuthenticationRealm | String | HTTP Authentication Realm value of the service classification | 
| Expanse.Service.classifications.details.value.httpHeaders.name | String | HTTP Header name included in the service classification | 
| Expanse.Service.classifications.details.value.httpHeaders.value | String | HTTP Header value included in the service classification | 
| Expanse.Service.classifications.details.value.httpStatusCode | String | HTTP Status code of the service classification | 
| Expanse.Service.classifications.details.value.isEncrypted | Boolean | Is Encrypted service classification | 
| Expanse.Service.classifications.details.value.isImplicit | Boolean | Is Implicit service classification | 
| Expanse.Service.classifications.details.value.loadBalancer | String | Load Balancer value of the service classification | 
| Expanse.Service.classifications.details.value.loadBalancerPool | String | Load Balancer Pool value of the service classification | 
| Expanse.Service.classifications.details.value.nativeRdpAlgorithms | String | Native RDP Algorithms of the service classification | 
| Expanse.Service.classifications.details.value.nativeRdpProtocol | Boolean | Native RDP Algorithms of the service classification | 
| Expanse.Service.classifications.details.value.serverSoftware | String | Detected Server Software the service classification | 
| Expanse.Service.classifications.details.value.serverVersion | String | Server Version details for the service classification | 
| Expanse.Service.classifications.details.value.sslProtocol | Boolean | SSL Protocol for the service classification | 
| Expanse.Service.classifications.details.value.validWhenScanned | Boolean | Whether a certificate on the service was valid at scan time | 
| Expanse.Service.classifications.details.value.version | String | Version details for the service classification | 
| Expanse.Service.classifications.firstObserved | Date | First observation of the service classification | 
| Expanse.Service.classifications.id | String | Service classification ID | 
| Expanse.Service.classifications.lastObserved | Date | Last observation of the service classification | 
| Expanse.Service.classifications.name | String | Service classification name | 
| Expanse.Service.cloudManagementStatus.id | String | The Internal ID of the cloud management status | 
| Expanse.Service.cloudManagementStatus.name | String | Name of the cloud management status | 
| Expanse.Service.domain.assetId | String | The Internal Asset ID of the domain related to the service | 
| Expanse.Service.domain.domain | String | The domain name related to the service | 
| Expanse.Service.domain.firstObserved | Date | The first observation of a domain related to the service | 
| Expanse.Service.domain.lastObserved | Date | The last observation of a domain related to the service | 
| Expanse.Service.discoveryInfo.type | String | Whether the service was directly discovered or colocated | 
| Expanse.Service.firstObserved | Date | First observation of the service | 
| Expanse.Service.id | String | The internal Xpanse ID of the service | 
| Expanse.Service.ips.assetId | String | The Internal Asset ID of the ip related to the service | 
| Expanse.Service.ips.firstObserved | Date | First observation of the ip related to the service | 
| Expanse.Service.ips.geolocation.city | String | Geolocation city of the ip related to the service | 
| Expanse.Service.ips.geolocation.countryCode | String | Geolocation country of the ip related to the service | 
| Expanse.Service.ips.geolocation.latitude | Number | Geolocation latitude of the ip related to the service | 
| Expanse.Service.ips.geolocation.longitude | Number | Geolocation longitude of the ip related to the service | 
| Expanse.Service.ips.geolocation.regionCode | String | Geolocation region of the ip related to the service | 
| Expanse.Service.ips.geolocation.timeZone | String | Geolocation timeZone of the ip related to the service | 
| Expanse.Service.ips.ip | String | IPv4 Address of the ip related to the service | 
| Expanse.Service.ips.lastObserved | Date | Last observation of the ip related to the service | 
| Expanse.Service.ips.provider.id | String | Provider ID of the ip related to the service | 
| Expanse.Service.ips.provider.name | String | provider name of the ip related to the service | 
| Expanse.Service.ips.transportProtocol | String | Transport protocol of the ip related to the service | 
| Expanse.Service.lastObserved | Date | Last observation of the service | 
| Expanse.Service.name | String | Summary of the service observation | 
| Expanse.Service.portNumber | Number | Summary of the service observation | 
| Expanse.Service.tlsVersions.cipherSuite | String | Cipher suite of the TLS version observed on the service | 
| Expanse.Service.tlsVersions.firstObserved | Date | First observation of the TLS version observed on the service | 
| Expanse.Service.tlsVersions.lastObserved | Date | Last observation of the TLS version observed on the service | 
| Expanse.Service.tlsVersions.tlsVersion | String | TLS version observed on the service | 


#### Command Example

```!expanse-get-service service_id="99ea2dce-248a-3adb-937b-b46841825581"```

#### Context Example

```json
{
    "Expanse": {
        "Service": {
            "activityStatus": "Active",
            "annotations": {
                "tags": []
            },
            "assets": [
                {
                    "assetKey": "2c156327-522e-33ef-aa15-fc8549b2446f",
                    "assetType": "IpRange",
                    "displayName": "198.51.100.220-198.51.100.232",
                    "id": "f58ccbb6-33df-3332-a2da-7e1f01d93af5",
                    "referenceReason": {
                        "id": "WithinOwnedIpRange",
                        "name": "The IP Range this service is running on is attributed to your organization."
                    }
                }
            ],
            "businessUnits": [
                {
                    "id": "a1f0f39b-f358-3c8c-947b-926887871b88",
                    "name": "VanDelay Import-Export"
                }
            ],
            "certificates": [],
            "classifications": [
                {
                    "details": [
                        {
                            "firstObserved": "2020-08-29T09:21:34Z",
                            "lastObserved": "2021-03-23T05:07:51Z",
                            "value": {
                                "bindVersions": [
                                    "Forbidden"
                                ]
                            }
                        }
                    ],
                    "firstObserved": "2020-07-03T02:13:39Z",
                    "id": "DnsServer",
                    "lastObserved": "2021-03-23T05:07:51Z",
                    "name": "DNS Server"
                }
            ],
            "cloudManagementStatus": {
                "id": "NotApplicable",
                "name": ""
            },
            "discoveryInfo": {
                "details": [],
                "type": "DirectlyDiscovered"
            },
            "domains": [],
            "firstObserved": "2020-07-03T02:13:39Z",
            "id": "99ea2dce-248a-3adb-937b-b46841825581",
            "ips": [
                {
                    "assetId": "f58ccbb6-33df-3332-a2da-7e1f01d93af5",
                    "firstObserved": "2020-08-29T09:21:34Z",
                    "geolocation": {
                        "city": "MELBOURNE",
                        "countryCode": "AU",
                        "latitude": -37.82,
                        "longitude": 144.97,
                        "regionCode": "VIC",
                        "timeZone": null
                    },
                    "ip": "198.51.100.230",
                    "lastObserved": "2021-03-23T05:07:51Z",
                    "provider": {
                        "id": "OnPrem",
                        "name": "On Prem"
                    },
                    "transportProtocol": "UDP"
                }
            ],
            "lastObserved": "2021-03-23T05:07:51Z",
            "name": "DNS Server at 198.51.100.230:53",
            "portNumber": 53,
            "tlsVersions": []
        }
    }
}
```

#### Human Readable Output

>### Expanse Services
>
>|Id|Name|Ips|Domains|Port Number|Activity Status|Business Units|Certificates|Tls Versions|Classifications|First Observed|Last Observed|Annotations|Assets|Discovery Info|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 99ea2dce-248a-3adb-937b-b46841825581 | DNS Server at 198.51.100.230:53 | {'ip': '198.51.100.230', 'assetId': 'f58ccbb6-33df-3332-a2da-7e1f01d93af5', 'transportProtocol': 'UDP', 'geolocation': {'countryCode': 'AU', 'latitude': -37.82, 'longitude': 144.97, 'city': 'MELBOURNE', 'timeZone': None, 'regionCode': 'VIC'}, 'provider': {'id': 'OnPrem', 'name': 'On Prem'}, 'firstObserved': '2020-08-29T09:21:34Z', 'lastObserved': '2021-03-23T05:07:51Z'} |  | 53 | Active | {'id': 'a1f0f39b-f358-3c8c-947b-926887871b88', 'name': 'VanDelay Import-Export'} |  |  | {'id': 'DnsServer', 'name': 'DNS Server', 'details': [{'value': {'bindVersions': ['Forbidden']}, 'firstObserved': '2020-08-29T09:21:34Z', 'lastObserved': '2021-03-23T05:07:51Z'}], 'firstObserved': '2020-07-03T02:13:39Z', 'lastObserved': '2021-03-23T05:07:51Z'} | 2020-07-03T02:13:39Z | 2021-03-23T05:07:51Z | tags:  | {'id': 'f58ccbb6-33df-3332-a2da-7e1f01d93af5', 'assetKey': '2c156327-522e-33ef-aa15-fc8549b2446f', 'assetType': 'IpRange', 'displayName': '198.51.100.220-198.51.100.232', 'referenceReason': {'id': 'WithinOwnedIpRange', 'name': 'The IP Range this service is running on is attributed to your organization.'}} | type: DirectlyDiscovered<br/>details:  |



### expanse-get-services

***
Retrieve services


#### Base Command

`expanse-get-services`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of services to retrieve. | Optional | 
| content_search | Returns only results whose contents match the given query. | Optional | 
| provider | Returns only results that were found on the given providers (comma separated string). | Optional | 
| business_unit | Returns only results with a business unit whose name falls in the provided list (comma separated string). | Optional | 
| service_type | Returns only results whose service type name (or classification ID) matches one of the given types (comma separated string). | Optional | 
| inet_search | Returns results whose identifier includes an IP matching the query. Search for results in a given IP/CIDR block using a single IP (d.d.d.d), a dashed IP range (d.d.d.d-d.d.d.d), a CIDR block (d.d.d.d/m), a partial CIDR (d.d.), or a wildcard (d.d.*.d). | Optional | 
| domain_search | Returns results whose identifier includes a domain matching the query. | Optional | 
| port_number | Returns only results whose identifier includes one of the given port numbers (comma separated list). | Optional | 
| discovery_type | Returns only results whose discovery type matches one of the given values (comma separated string, options are 'ColocatedOnIp', 'DirectlyDiscovered'). | Optional | 
| country_code | Returns only results whose country code matches one of the given ISO-3166 two character country codes (comma separated list). | Optional | 
| activity_status | Returns only results whose activity status matches one of the given values. Possible values are: Active, Inactive. | Optional | 
| tag | Returns only results that are associated with the provided tag names (comma separated string). | Optional | 
| cloud_management_status | Returns only results whose cloud management status is the following.
        (comma separated string, options are 'NotApplicable', 'ManagedCloud', 'UnmanagedCloud'). | Optional |
| sort | Sort by specified properties. Possible values are: firstObserved, -firstObserved, lastObserved, -lastObserved, name, -name. Default is firstObserved. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Service.activityStatus | String | Activity status of service, whether the service is active or inactive | 
| Expanse.Service.annotations.tags.id | String | The Internal Xpanse tag id of the customer added tag | 
| Expanse.Service.annotations.tags.name | String | The tag name of the customer added tag | 
| Expanse.Service.assets.assetKey | String | Key used to access the asset in the respective Xpanse asset API | 
| Expanse.Service.assets.assetType | String | The type of asset the issue primarily relates to | 
| Expanse.Service.assets.displayName | String | A friendly name for the asset | 
| Expanse.Service.assets.id | String | Internal Xpanse ID the asset | 
| Expanse.Service.assets.referenceReason.id | String | ID for asset reference type | 
| Expanse.Service.assets.referenceReason.name | String | Description for asset reference reason | 
| Expanse.Service.businessUnits.id | String | The internal Xpanse ID for the business unit the affected asset belongs to | 
| Expanse.Service.businessUnits.name | String | The name of the business unit the affected asset belongs to | 
| Expanse.Service.certificates.assetId | String | Internal Asset ID of certificate | 
| Expanse.Service.certificates.firstObserved | Date | First observation of certificate | 
| Expanse.Service.certificates.lastObserved | Date | Most recent observation of certificate | 
| Expanse.Service.certificates.certificate.formattedIssuerOrg | String | The formatted issuer org in the certificate | 
| Expanse.Service.certificates.certificate.id | String | The Internal Xpanse certificate ID | 
| Expanse.Service.certificates.certificate.issuer | String | The issuer in the certificate | 
| Expanse.Service.certificates.certificate.issuerAlternativeNames | String | The issuer alternative names in the certificate | 
| Expanse.Service.certificates.certificate.issuerCountry | String | The issuer country in the certificate | 
| Expanse.Service.certificates.certificate.issuerEmail | String | The issuer email in the certificate | 
| Expanse.Service.certificates.certificate.issuerLocality | String | The issuer locality in the certificate | 
| Expanse.Service.certificates.certificate.issuerName | String | The issuer name in the certificate | 
| Expanse.Service.certificates.certificate.issuerOrg | String | The issuer org in the certificate | 
| Expanse.Service.certificates.certificate.issuerOrgUnit | String | The issuer org unit in the certificate | 
| Expanse.Service.certificates.certificate.issuerState | String | The issuer state in the certificate | 
| Expanse.Service.certificates.certificate.md5Hash | String | The md5hash in the certificate | 
| Expanse.Service.certificates.certificate.pemSha1 | String | The pemSha1 in the certificate | 
| Expanse.Service.certificates.certificate.pemSha256 | String | The pemSha256 in the certificate | 
| Expanse.Service.certificates.certificate.publicKey | String | The public key in the certificate | 
| Expanse.Service.certificates.certificate.publicKeyAlgorithm | String | The public key algorithm in the certificate | 
| Expanse.Service.certificates.certificate.publicKeyBits | Number | The public key bits in the certificate | 
| Expanse.Service.certificates.certificate.publicKeyModulus | String | The public key modulus in the certificate | 
| Expanse.Service.certificates.certificate.publicKeyRsaExponent | Number | The public key RSA exponent in the certificate | 
| Expanse.Service.certificates.certificate.publicKeySpki | String | The public key Spki in the certificate | 
| Expanse.Service.certificates.certificate.serialNumber | String | The serial number in the certificate | 
| Expanse.Service.certificates.certificate.signatureAlgorithm | String | The signature algorithm in the certificate | 
| Expanse.Service.certificates.certificate.subject | String | The subject in the certificate | 
| Expanse.Service.certificates.certificate.subjectAlternativeNames | String | The subject alternative names in the certificate | 
| Expanse.Service.certificates.certificate.subjectCountry | String | The subject country in the certificate | 
| Expanse.Service.certificates.certificate.subjectEmail | String | The subject email in the certificate | 
| Expanse.Service.certificates.certificate.subjectLocality | String | The subject locality in the certificate | 
| Expanse.Service.certificates.certificate.subjectName | String | The subject name in the certificate | 
| Expanse.Service.certificates.certificate.subjectOrg | String | The subject org in the certificate | 
| Expanse.Service.certificates.certificate.subjectOrgUnit | String | The subject org unit in the certificate | 
| Expanse.Service.certificates.certificate.subjectState | String | The subject state in the certificate | 
| Expanse.Service.certificates.certificate.validNotAfter | Date | The valid not after date in the certificate | 
| Expanse.Service.certificates.certificate.validNotBefore | Date | The valid not before date in the certificate | 
| Expanse.Service.certificates.certificate.version | String | The version in the certificate | 
| Expanse.Service.classifications.details.firstObserved | Date | When the service instance was first observed | 
| Expanse.Service.classifications.details.lastObserved | Date | When the service instance was last observed | 
| Expanse.Service.classifications.details.value.applicationServerSoftware | String | Application Server Software value of the service classification | 
| Expanse.Service.classifications.details.value.bgpOpenResponse | String | BGP Open value of the service classification | 
| Expanse.Service.classifications.details.value.bgpNotificationResponse.data | String | BGP Notification Data value of the service classification | 
| Expanse.Service.classifications.details.value.bgpNotificationResponse.errorCode | String | BGP Notification Error Code value of the service classification | 
| Expanse.Service.classifications.details.value.bgpNotificationResponse.errorSubCode | String | BGP Notification Sub-Error Code value of the service classification | 
| Expanse.Service.classifications.details.value.bindVersions | String | Bind version value of the service classification | 
| Expanse.Service.classifications.details.value.certificateId | String | Certificate Id value of the service classification | 
| Expanse.Service.classifications.details.value.connectResponse.statusCode | String | Connect Response Status Code value of the service classification | 
| Expanse.Service.classifications.details.value.connectResponse.responseLines | String | Connect Response Response value of the service classification | 
| Expanse.Service.classifications.details.value.credSspProtocol | Boolean | Cred SSP Protocol of the service classification | 
| Expanse.Service.classifications.details.value.exchanges.request.arguments | String | Exchange Request Arguments value of the service classification | 
| Expanse.Service.classifications.details.value.exchanges.request.command | String | Exchange Request Command value of the service classification | 
| Expanse.Service.classifications.details.value.exchanges.response.statusCode | String | Connect Response Status Code value of the service classification | 
| Expanse.Service.classifications.details.value.exchanges.response.responseLines | String | Connect Response Response value of the service classification | 
| Expanse.Service.classifications.details.value.extraInfo | String | Extra Info about the service classification | 
| Expanse.Service.classifications.details.value.htmlPasswordAction | String | HTML Password Action value of the service classification | 
| Expanse.Service.classifications.details.value.htmlPasswordField | String | HTML Password Field value of the service classification | 
| Expanse.Service.classifications.details.value.htmlPasswordAction | String | HTML Password Action value of the service classification | 
| Expanse.Service.classifications.details.value.httpAuthenticationMethods | String | HTTP Authentication Methods value of the service classification | 
| Expanse.Service.classifications.details.value.httpAuthenticationRealm | String | HTTP Authentication Realm value of the service classification | 
| Expanse.Service.classifications.details.value.httpHeaders.name | String | HTTP Header name included in the service classification | 
| Expanse.Service.classifications.details.value.httpHeaders.value | String | HTTP Header value included in the service classification | 
| Expanse.Service.classifications.details.value.httpStatusCode | String | HTTP Status code of the service classification | 
| Expanse.Service.classifications.details.value.isEncrypted | Boolean | Is Encrypted service classification | 
| Expanse.Service.classifications.details.value.isImplicit | Boolean | Is Implicit service classification | 
| Expanse.Service.classifications.details.value.loadBalancer | String | Load Balancer value of the service classification | 
| Expanse.Service.classifications.details.value.loadBalancerPool | String | Load Balancer Pool value of the service classification | 
| Expanse.Service.classifications.details.value.nativeRdpAlgorithms | String | Native RDP Algorithms of the service classification | 
| Expanse.Service.classifications.details.value.nativeRdpProtocol | Boolean | Native RDP Algorithms of the service classification | 
| Expanse.Service.classifications.details.value.serverSoftware | String | Detected Server Software the service classification | 
| Expanse.Service.classifications.details.value.serverVersion | String | Server Version details for the service classification | 
| Expanse.Service.classifications.details.value.sslProtocol | Boolean | SSL Protocol for the service classification | 
| Expanse.Service.classifications.details.value.validWhenScanned | Boolean | Whether a certificate on the service was valid at scan time | 
| Expanse.Service.classifications.details.value.version | String | Version details for the service classification | 
| Expanse.Service.classifications.firstObserved | Date | First observation of the service classification | 
| Expanse.Service.classifications.id | String | Service classification ID | 
| Expanse.Service.classifications.lastObserved | Date | Last observation of the service classification | 
| Expanse.Service.classifications.name | String | Service classification name | 
| Expanse.Service.cloudManagementStatus.id | String | The Internal ID of the cloud management status | 
| Expanse.Service.cloudManagementStatus.name | String | Name of the cloud management status | 
| Expanse.Service.domain.assetId | String | The Internal Asset ID of the domain related to the service | 
| Expanse.Service.domain.domain | String | The domain name related to the service | 
| Expanse.Service.domain.firstObserved | Date | The first observation of a domain related to the service | 
| Expanse.Service.domain.lastObserved | Date | The last observation of a domain related to the service | 
| Expanse.Service.discoveryInfo.type | String | Whether the service was directly discovered or colocated | 
| Expanse.Service.firstObserved | Date | First observation of the service | 
| Expanse.Service.id | String | The internal Xpanse ID of the service | 
| Expanse.Service.ips.assetId | String | The Internal Asset ID of the ip related to the service | 
| Expanse.Service.ips.firstObserved | Date | First observation of the ip related to the service | 
| Expanse.Service.ips.geolocation.city | String | Geolocation city of the ip related to the service | 
| Expanse.Service.ips.geolocation.countryCode | String | Geolocation country of the ip related to the service | 
| Expanse.Service.ips.geolocation.latitude | Number | Geolocation latitude of the ip related to the service | 
| Expanse.Service.ips.geolocation.longitude | Number | Geolocation longitude of the ip related to the service | 
| Expanse.Service.ips.geolocation.regionCode | String | Geolocation region of the ip related to the service | 
| Expanse.Service.ips.geolocation.timeZone | String | Geolocation timeZone of the ip related to the service | 
| Expanse.Service.ips.ip | String | IPv4 Address of the ip related to the service | 
| Expanse.Service.ips.lastObserved | Date | Last observation of the ip related to the service | 
| Expanse.Service.ips.provider.id | String | Provider ID of the ip related to the service | 
| Expanse.Service.ips.provider.name | String | provider name of the ip related to the service | 
| Expanse.Service.ips.transportProtocol | String | Transport protocol of the ip related to the service | 
| Expanse.Service.lastObserved | Date | Last observation of the service | 
| Expanse.Service.name | String | Summary of the service observation | 
| Expanse.Service.portNumber | Number | Summary of the service observation | 
| Expanse.Service.tlsVersions.cipherSuite | String | Cipher suite of the TLS version observed on the service | 
| Expanse.Service.tlsVersions.firstObserved | Date | First observation of the TLS version observed on the service | 
| Expanse.Service.tlsVersions.lastObserved | Date | Last observation of the TLS version observed on the service | 
| Expanse.Service.tlsVersions.tlsVersion | String | TLS version observed on the service | 


#### Command Example

```!expanse-get-services limit="1" provider="Amazon Web Services"```

#### Context Example

```json
{
    "Expanse": {
        "Service": {
            "activityStatus": "Active",
            "annotations": {
                "tags": []
            },
            "assets": [
                {
                    "assetKey": "ec73a0b3-a5e2-3a37-b718-06bff21546e6",
                    "assetType": "Certificate",
                    "displayName": "*.thespeedyou.com",
                    "id": "ec73a0b3-a5e2-3a37-b718-06bff21546e6",
                    "referenceReason": {
                        "id": "CertificateAdvertisedOnService",
                        "name": "This certificate \u2014 which is attributed to your organization \u2014 was advertised by this service."
                    }
                }
            ],
            "businessUnits": [
                {
                    "id": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5",
                    "name": "VanDelay Industries"
                }
            ],
            "certificates": [
                {
                    "assetId": "ec73a0b3-a5e2-3a37-b718-06bff21546e6",
                    "certificate": {
                        "formattedIssuerOrg": "COMODO",
                        "issuer": "C=GB,ST=Greater Manchester,L=Salford,O=COMODO CA Limited,CN=COMODO RSA Organization Validation Secure Server CA",
                        "issuerAlternativeNames": "",
                        "issuerCountry": "GB",
                        "issuerEmail": null,
                        "issuerLocality": "Salford",
                        "issuerName": "COMODO RSA Organization Validation Secure Server CA",
                        "issuerOrg": "COMODO CA Limited",
                        "issuerOrgUnit": null,
                        "issuerState": "Greater Manchester",
                        "md5Fingerprint": "6aec4d4a43851a0e2e0b15464c031de8",
                        "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3Wc7WbUjdzK8EyX85hYPq0kUdiaZYIdy92Qdic6Ng0EJwLDEvaWv6tjkmLofBu/XsbUwr8J3Qp9Glih8fudkBzHqUxjPHxiEnyPWIXJKZNoiEFKWuRhzvWwJYNYh842Jnam+sK2vC2PxusLuM0WAaRmGPdv3yGth309xesbc83hL7RlvKAbRMsQNu0JYjwYkXtBjl+pXIrxFuVOj73UxijJgte2yieP4nhKd6vIYLAWq7sIEN58xqzD0ovObRR7mKXuEwpt04aq0+E9acCBVdIGRmk7UZ9YfH6znXjPrNaM0NPJUEfUk+M92r1ZyjQstXfIz9NeQmkA9mYIse+aQtwIDAQAB",
                        "publicKeyAlgorithm": "RSA",
                        "publicKeyBits": 2048,
                        "publicKeyModulus": "dd673b59b5237732bc1325fce6160fab4914762699608772f7641d89ce8d834109c0b0c4bda5afead8e498ba1f06efd7b1b530afc277429f4696287c7ee7640731ea5318cf1f18849f23d621724a64da22105296b91873bd6c0960d621f38d899da9beb0adaf0b63f1bac2ee3345806919863ddbf7c86b61df4f717ac6dcf3784bed196f2806d132c40dbb42588f06245ed06397ea5722bc45b953a3ef75318a3260b5edb289e3f89e129deaf2182c05aaeec204379f31ab30f4a2f39b451ee6297b84c29b74e1aab4f84f5a7020557481919a4ed467d61f1face75e33eb35a33434f25411f524f8cf76af56728d0b2d5df233f4d7909a403d99822c7be690b7",
                        "publicKeyRsaExponent": 65537,
                        "publicKeySpki": "xmID8gn_JKlzrzuEoyaqLmdNlx5Xv3fFA6v_wpM6aSA=",
                        "serialNumber": "42792794729857115395309499847024762482",
                        "sha1Fingerprint": "2594a1428dae54eeaf6140a7de97680121c89fff",
                        "sha256Fingerprint": "4dcf9d18c10c6f9f09b71bad3cf1079a31c5c2ebb2eced23373aac8b9f3dc72e",
                        "signatureAlgorithm": "SHA256withRSA",
                        "subject": "C=US,PostalCode=60179,ST=Illinois,L=Hoffman Estates,STREET=3333 Beverly Road,O=Sears IT and Management Services India Pvt. Ltd.,OU=Home Services,OU=PlatinumSSL Wildcard,CN=*.shs-core.com",
                        "subjectAlternativeNames": "*.thespeedyou.com",
                        "subjectCountry": "US",
                        "subjectEmail": null,
                        "subjectLocality": "Hoffman Estates",
                        "subjectName": "*.thespeedyou.com",
                        "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.",
                        "subjectOrgUnit": "Home Services,PlatinumSSL Wildcard",
                        "subjectState": "Illinois",
                        "validNotAfter": "2017-11-10T23:59:59Z",
                        "validNotBefore": "2016-11-10T00:00:00Z",
                        "version": "3"
                    },
                    "firstObserved": "2021-01-12T06:56:51Z",
                    "lastObserved": "2021-03-23T18:37:05Z"
                }
            ],
            "classifications": [
                {
                    "details": [],
                    "firstObserved": null,
                    "id": "NginxWebServer",
                    "lastObserved": null,
                    "name": "NginxWebServer"
                },
                {
                    "details": [],
                    "firstObserved": null,
                    "id": "ServerSoftware",
                    "lastObserved": null,
                    "name": "ServerSoftware"
                },
                {
                    "details": [],
                    "firstObserved": null,
                    "id": "WildcardCertificate",
                    "lastObserved": null,
                    "name": "WildcardCertificate"
                },
                {
                    "details": [],
                    "firstObserved": null,
                    "id": "HttpServer",
                    "lastObserved": null,
                    "name": "HttpServer"
                },
                {
                    "details": [],
                    "firstObserved": null,
                    "id": "ExpiredWhenScannedCertificate",
                    "lastObserved": null,
                    "name": "ExpiredWhenScannedCertificate"
                }
            ],
            "cloudManagementStatus": {
                "id": "NotApplicable",
                "name": ""
            },
            "discoveryInfo": {
                "details": [],
                "type": "DirectlyDiscovered"
            },
            "domains": [],
            "firstObserved": "2020-11-09T19:15:45Z",
            "id": "c561a0f4-b5a2-3ab8-864b-b57a48aa2d12",
            "ips": [
                {
                    "assetId": null,
                    "firstObserved": "2021-01-12T06:56:51Z",
                    "geolocation": null,
                    "ip": "203.0.113.102",
                    "lastObserved": "2021-03-23T18:37:05Z",
                    "provider": {
                        "id": "AWS",
                        "name": "Amazon Web Services"
                    },
                    "transportProtocol": "TCP"
                }
            ],
            "lastObserved": "2021-03-23T18:37:05Z",
            "name": "HTTP Server at 203.0.113.102:443",
            "portNumber": 443,
            "tlsVersions": [
                {
                    "cipherSuite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "firstObserved": "2021-01-12T06:56:51Z",
                    "lastObserved": "2021-03-23T18:37:05Z",
                    "tlsVersion": "TLS 1.2"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Expanse Services
>
>|Id|Name|Ips|Domains|Port Number|Activity Status|Business Units|Certificates|Tls Versions|Classifications|First Observed|Last Observed|Annotations|Assets|Discovery Info|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| c561a0f4-b5a2-3ab8-864b-b57a48aa2d12 | HTTP Server at 203.0.113.102:443 | {'ip': '203.0.113.102', 'assetId': None, 'transportProtocol': 'TCP', 'geolocation': None, 'provider': {'id': 'AWS', 'name': 'Amazon Web Services'}, 'firstObserved': '2021-01-12T06:56:51Z', 'lastObserved': '2021-03-23T18:37:05Z'} |  | 443 | Active | {'id': '04b5140e-bbe2-3e9c-9318-a39a3b547ed5', 'name': 'VanDelay Industries'} | {'certificate': {'issuer': 'C=GB,ST=Greater Manchester,L=Salford,O=COMODO CA Limited,CN=COMODO RSA Organization Validation Secure Server CA', 'issuerAlternativeNames': '', 'issuerCountry': 'GB', 'issuerEmail': None, 'issuerLocality': 'Salford', 'issuerName': 'COMODO RSA Organization Validation Secure Server CA', 'issuerOrg': 'COMODO CA Limited', 'formattedIssuerOrg': 'COMODO', 'issuerOrgUnit': None, 'issuerState': 'Greater Manchester', 'publicKey': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3Wc7WbUjdzK8EyX85hYPq0kUdiaZYIdy92Qdic6Ng0EJwLDEvaWv6tjkmLofBu/XsbUwr8J3Qp9Glih8fudkBzHqUxjPHxiEnyPWIXJKZNoiEFKWuRhzvWwJYNYh842Jnam+sK2vC2PxusLuM0WAaRmGPdv3yGth309xesbc83hL7RlvKAbRMsQNu0JYjwYkXtBjl+pXIrxFuVOj73UxijJgte2yieP4nhKd6vIYLAWq7sIEN58xqzD0ovObRR7mKXuEwpt04aq0+E9acCBVdIGRmk7UZ9YfH6znXjPrNaM0NPJUEfUk+M92r1ZyjQstXfIz9NeQmkA9mYIse+aQtwIDAQAB', 'publicKeyAlgorithm': 'RSA', 'publicKeyRsaExponent': 65537, 'signatureAlgorithm': 'SHA256withRSA', 'subject': 'C=US,PostalCode=60179,ST=Illinois,L=Hoffman Estates,STREET=3333 Beverly Road,O=Sears Brands LLC,OU=Home Services,OU=PlatinumSSL Wildcard,CN=*.shs-core.com', 'subjectAlternativeNames': '*.shs-core.com', 'subjectCountry': 'US', 'subjectEmail': None, 'subjectLocality': 'Hoffman Estates', 'subjectName': '*.shs-core.com', 'subjectOrg': 'Sears Brands LLC', 'subjectOrgUnit': 'Home Services,PlatinumSSL Wildcard', 'subjectState': 'Illinois', 'serialNumber': '42792794729857115395309499847024762482', 'validNotBefore': '2016-11-10T00:00:00Z', 'validNotAfter': '2017-11-10T23:59:59Z', 'version': '3', 'publicKeyBits': 2048, 'publicKeyModulus': 'dd673b59b5237732bc1325fce6160fab4914762699608772f7641d89ce8d834109c0b0c4bda5afead8e498ba1f06efd7b1b530afc277429f4696287c7ee7640731ea5318cf1f18849f23d621724a64da22105296b91873bd6c0960d621f38d899da9beb0adaf0b63f1bac2ee3345806919863ddbf7c86b61df4f717ac6dcf3784bed196f2806d132c40dbb42588f06245ed06397ea5722bc45b953a3ef75318a3260b5edb289e3f89e129deaf2182c05aaeec204379f31ab30f4a2f39b451ee6297b84c29b74e1aab4f84f5a7020557481919a4ed467d61f1face75e33eb35a33434f25411f524f8cf76af56728d0b2d5df233f4d7909a403d99822c7be690b7', 'publicKeySpki': 'xmID8gn_JKlzrzuEoyaqLmdNlx5Xv3fFA6v_wpM6aSA=', 'sha1Fingerprint': '2594a1428dae54eeaf6140a7de97680121c89fff', 'sha256Fingerprint': '4dcf9d18c10c6f9f09b71bad3cf1079a31c5c2ebb2eced23373aac8b9f3dc72e', 'md5Fingerprint': '6aec4d4a43851a0e2e0b15464c031de8'}, 'assetId': 'ec73a0b3-a5e2-3a37-b718-06bff21546e6', 'firstObserved': '2021-01-12T06:56:51Z', 'lastObserved': '2021-03-23T18:37:05Z'} | {'tlsVersion': 'TLS 1.2', 'cipherSuite': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'firstObserved': '2021-01-12T06:56:51Z', 'lastObserved': '2021-03-23T18:37:05Z'} | {'id': 'NginxWebServer', 'name': 'NginxWebServer', 'details': [], 'firstObserved': None, 'lastObserved': None},<br/>{'id': 'ServerSoftware', 'name': 'ServerSoftware', 'details': [], 'firstObserved': None, 'lastObserved': None},<br/>{'id': 'WildcardCertificate', 'name': 'WildcardCertificate', 'details': [], 'firstObserved': None, 'lastObserved': None},<br/>{'id': 'HttpServer', 'name': 'HttpServer', 'details': [], 'firstObserved': None, 'lastObserved': None},<br/>{'id': 'ExpiredWhenScannedCertificate', 'name': 'ExpiredWhenScannedCertificate', 'details': [], 'firstObserved': None, 'lastObserved': None} | 2020-11-09T19:15:45Z | 2021-03-23T18:37:05Z | tags:  | {'id': 'ec73a0b3-a5e2-3a37-b718-06bff21546e6', 'assetKey': 'ec73a0b3-a5e2-3a37-b718-06bff21546e6', 'assetType': 'Certificate', 'displayName': '*.shs-core.com', 'referenceReason': {'id': 'CertificateAdvertisedOnService', 'name': 'This certificate — which is attributed to your organization — was advertised by this service.'}} | type: DirectlyDiscovered<br/>details:  |

### expanse-list-pocs

***
List available Point of Contacts from Xpanse.


#### Base Command

`expanse-list-pocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.PointOfContact.created | Date | The date in which the Point of Contact was first created | 
| Expanse.PointOfContact.email | String | Email address of Point of Contact | 
| Expanse.PointOfContact.firstName | String | First Name of Point of Contact | 
| Expanse.PointOfContact.id | String | Internal ID of Point of Contact | 
| Expanse.PointOfContact.lastName | String | Last Name of Point of Contact | 
| Expanse.PointOfContact.modified | Date | The date in which the Point of Contact was last modified | 
| Expanse.PointOfContact.phone | String | Phone number of Point of Contact | 
| Expanse.PointOfContact.role | String | Role of Point of Contact | 


#### Command Example

```!expanse-list-pocs limit=1```

#### Context Example

```json
{
    "Expanse": {
        "PointOfContact": {
            "created": "2019-05-22T00:59:28.919496Z",
            "email": "analyst@expanseinc.com",
            "firstName": "Test",
            "id": "f491b7ef-a7b9-4644-af90-36dc0a6b2000",
            "lastName": "User",
            "modified": "2019-05-22T00:59:28.919937Z",
            "phone": "4157066803",
            "role": "analyst"
        }
    }
}
```

#### Human Readable Output

>### Results
>
>|created|email|firstName|id|lastName|modified|phone|role|
>|---|---|---|---|---|---|---|---|
>| 2019-05-22T00:59:28.919496Z | <analyst@expanseinc.com> | Test | f491b7ef-a7b9-4644-af90-36dc0a6b2000 | User | 2019-05-22T00:59:28.919937Z | 4157066803 | analyst |


### expanse-create-poc

***
Create a new Point of Contact in Xpanse.


#### Base Command

`expanse-create-poc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email for Point of Contact. | Required | 
| first_name | First name of Point of Contact. | Optional | 
| last_name | Last name of Point of Contact. | Optional | 
| phone | Phone number of Point of Contact. | Optional | 
| role | Role of Point of Contact. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.PointOfContact.created | Date | The date in which the Point of Contact was first created | 
| Expanse.PointOfContact.email | String | Email address of Point of Contact | 
| Expanse.PointOfContact.firstName | String | First Name of Point of Contact | 
| Expanse.PointOfContact.id | String | Internal ID of Point of Contact | 
| Expanse.PointOfContact.lastName | String | Last Name of Point of Contact | 
| Expanse.PointOfContact.modified | Date | The date in which the Point of Contact was last modified | 
| Expanse.PointOfContact.phone | String | Phone number of Point of Contact | 
| Expanse.PointOfContact.role | String | Role of Point of Contact | 


#### Command Example

```!expanse-create-tag email="analyst@expanse.inc"```

#### Human Readable Output

```json
{}
```


### expanse-assign-pocs-to-asset

***
Assign Point of Contacts to an Xpanse asset.


#### Base Command

`expanse-assign-pocs-to-asset`

#### Input

| **Argument Name** | **Description**                                                                                                                               | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------| --- |
| asset_type | Type of Xpanse asset to assign the poc to. Possible values are: IpRange, Certificate, Domain, Network, Device, ResponseiveIP.                 | Required | 
| asset_id | ID of the asset to assign the poc to.                                                                                                         | Required | 
| pocs | IDs of the pocs to assign to the asset (comma separated string). If used in combination with 'poc_emails' the lists of pocs are merged.       | Optional | 
| poc_emails | Email Addresses of the pocs to assign to the asset (comma separated string). If used in combination with 'pocs' the lists of pocs are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-assign-pocs-to-asset asset_type="IpRange" asset_id="9847aa57-3c5d-4308-91d6-ee0fd5435785" poc_emails="analyst@expanseinc.com"```

#### Human Readable Output

>Operation complete

### expanse-unassign-pocs-from-asset

***
Unassign Point of Contacts from an Xpanse Asset.


#### Base Command

`expanse-unassign-pocs-from-asset`

#### Input

| **Argument Name** | **Description**                                                                                                                             | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------| --- |
| asset_type | Type of Xpanse asset to unassign the pocs from. Possible values are: IpRange, Certificate, Domain, Network, Device, ResponseiveIP.          | Required | 
| asset_id | ID of the asset to unassign the pocs from.                                                                                                  | Required | 
| pocs | IDs of the pocs to unassign from the asset (comma separated string). If used in combination with 'poc_emails' the lists of pocs are merged. | Optional | 
| poc_emails | Names of the pocs to unassign from the asset (comma separated string). If used in combination with 'pocs' the lists of pocs are merged.     | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

``` ```

#### Human Readable Output



### expanse-assign-pocs-to-iprange

***
Assign Point of Contacts to an Xpanse IP range.


#### Base Command

`expanse-assign-pocs-to-iprange`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the IP range to assign pocs to. | Required | 
| pocs | IDs of the pocs to assign to the IP range (comma separated string). If used in combination with 'poc_emails' the lists of pocs are merged. | Optional | 
| poc_emails | Emails of the pocs to assign to the IP range (comma separated string). If used in combination with 'pocs' the lists of pocs are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-assign-pocs-to-iprange asset_id="9847aa57-3c5d-4308-91d6-ee0fd5435785" poc_emails="analyst@expanseinc.com"```

#### Human Readable Output

>Operation complete

### expanse-unassign-pocs-from-iprange

***
Unassign Point of Contacts from an Xpanse IP range.


#### Base Command

`expanse-unassign-pocs-from-iprange`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the IP range to unassign pocs from. | Required | 
| pocs | IDs of the pocs to unassign from the IP range (comma separated string). If used in combination with 'poc_emails' the lists of pocs are merged. | Optional | 
| poc_emails | Names of the pocs to unassign from the IP range (comma separated string). If used in combination with 'pocs' the lists of pocs are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-unassign-pocs-from-iprange asset_id="9847aa57-3c5d-4308-91d6-ee0fd5435785" poc_emails="analyst@expanseinc.com"```

#### Human Readable Output

>Operation complete

### expanse-assign-pocs-to-certificate

***
Assign pocs to an Xpanse certificate.


#### Base Command

`expanse-assign-pocs-to-certificate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the certificate to assign pocs to. | Required | 
| pocs | IDs of the pocs to assign to the certificate (comma separated string). If used in combination with 'poc_emails' the lists of pocs are merged. | Optional | 
| poc_emails | Emails of the pocs to assign to the certificate (comma separated string). If used in combination with 'pocs' the lists of pocs are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-assign-pocs-to-certificate asset_id="1834b291-7be6-3161-a5f5-78207a548596" poc_emails="analyst@expanseinc.com"```

#### Human Readable Output

>Operation complete

### expanse-unassign-pocs-from-certificate

***
Unassign pocs from an Xpanse certificate.


#### Base Command

`expanse-unassign-pocs-from-certificate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the certificate to assign pocs to. | Required | 
| pocs | IDs of the pocs to unassign from the certificate (comma separated string). If used in combination with 'poc_emails' the lists of pocs are merged. | Optional | 
| poc_emails | Emails of the pocs to unassign from the certificate (comma separated string). If used in combination with 'pocs' the lists of pocs are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-unassign-pocs-from-certificate asset_id="1834b291-7be6-3161-a5f5-78207a548596" poc_emails="analyst@expanseinc.com"```

#### Human Readable Output

>Operation complete

### expanse-assign-pocs-to-domain

***
Assign pocs to an Xpanse domain.


#### Base Command

`expanse-assign-pocs-to-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the domain to assign pocs to. | Required | 
| pocs | IDs of the pocs to assign to the domain (comma separated string). If used in combination with 'poc_emails' the lists of pocs are merged. | Optional | 
| poc_emails | Emails of the pocs to assign to the domain (comma separated string). If used in combination with 'pocs' the lists of pocs are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-assign-pocs-to-domain asset_id="3e65e20d-51eb-364c-bfa9-c54746131098" poc_emails="analyst@expanseinc.com"```

#### Human Readable Output

>Operation complete

### expanse-unassign-pocs-from-domain

***
Unassign pocs from an Xpanse domain.


#### Base Command

`expanse-unassign-pocs-from-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the domain to unassign pocs from. | Required | 
| pocs | IDs of the pocs to unassign from the domain (comma separated string). If used in combination with 'poc_emails' the lists of pocs are merged. | Optional | 
| poc_emails | Emails of the pocs to unassign from the domain (comma separated string). If used in combination with 'pocs' the lists of pocs are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-unassign-pocs-from-domain asset_id="3e65e20d-51eb-364c-bfa9-c54746131098" poc_emails="analyst@expanseinc.com"```

#### Human Readable Output

>Operation complete


### expanse-list-businessunits

***
List available business units from Xpanse.


#### Base Command

`expanse-list-businessunits`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.BusinessUnit.id | String | Business unit ID | 
| Expanse.BusinessUnit.name | String | Business unit name | 


#### Command Example

```!expanse-list-businessunits limit="2"```

#### Context Example

```json
{
    "Expanse": {
        "BusinessUnit": [
            {
                "id": "c4de7fad-cde1-46cf-8725-a5999533db59",
                "name": "PANW VanDelay Import-Export Dev"
            },
            {
                "id": "c94c50ca-124f-4983-8da5-1756138e2252",
                "name": "PANW Acme Latex Supply Dev"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>
>|id|name|
>|---|---|
>| c4de7fad-cde1-46cf-8725-a5999533db59 | PANW VanDelay Import-Export Dev |
>| c94c50ca-124f-4983-8da5-1756138e2252 | PANW Acme Latex Supply Dev |


### expanse-list-providers

***
List available providers from Xpanse.


#### Base Command

`expanse-list-providers`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Provider.id | String | Provider ID | 
| Expanse.Provider.name | String | Provider name | 


#### Command Example

```!expanse-list-providers limit="2"```

#### Context Example

```json
{
    "Expanse": {
        "Provider": [
            {
                "id": "AlibabaCloud",
                "name": "Alibaba Cloud"
            },
            {
                "id": "AWS",
                "name": "Amazon Web Services"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>
>|id|name|
>|---|---|
>| AlibabaCloud | Alibaba Cloud |
>| AWS | Amazon Web Services |


### expanse-list-tags

***
List available tags from Expanse.


#### Base Command

`expanse-list-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Tag.created | Date | The date in which the tag was first created | 
| Expanse.Tag.description | String | The description associated with the tag | 
| Expanse.Tag.disabled | Boolean | If the tag should be hidden as a tag option in the Expander UI | 
| Expanse.Tag.id | String | The Xpanse ID for the tag | 
| Expanse.Tag.modified | Date | The date in which metadata about the tag was last modified | 
| Expanse.Tag.name | String | The display name for the tag | 
| Expanse.Tag.tenantId | String | The tenant ID associated with the tag | 


#### Command Example

```!expanse-list-tags limit="2"```

#### Context Example

```json
{
    "Expanse": {
        "Tag": [
            {
                "created": "2020-12-07T12:18:38.047826Z",
                "description": "XSOAR Test Tag",
                "disabled": false,
                "id": "a96792e9-ac04-338e-bd7f-467e395c3739",
                "modified": "2020-12-07T12:18:38.047826Z",
                "name": "xsoar-test-tag-new",
                "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
            },
            {
                "created": "2020-12-07T09:42:40.456398Z",
                "description": "XSOAR Test Playbook Tag",
                "disabled": false,
                "id": "e00bc79d-d367-36f4-824c-042836fef5fc",
                "modified": "2020-12-07T09:42:40.456398Z",
                "name": "xsoar-test-pb-tag",
                "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>
>|created|description|disabled|id|modified|name|tenantId|
>|---|---|---|---|---|---|---|
>| 2020-12-07T12:18:38.047826Z | XSOAR Test Tag | false | a96792e9-ac04-338e-bd7f-467e395c3739 | 2020-12-07T12:18:38.047826Z | xsoar-test-tag-new | f738ace6-f451-4f31-898d-a12afa204b2a |
>| 2020-12-07T09:42:40.456398Z | XSOAR Test Playbook Tag | false | e00bc79d-d367-36f4-824c-042836fef5fc | 2020-12-07T09:42:40.456398Z | xsoar-test-pb-tag | f738ace6-f451-4f31-898d-a12afa204b2a |


### expanse-assign-tags-to-asset

***
Assign tags to an Xpanse asset.


#### Base Command

`expanse-assign-tags-to-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | Type of Xpanse asset to assign the tag to. Possible values are: IpRange, Certificate, Domain, Network, Device, ResponseiveIP. | Required | 
| asset_id | ID of the asset to assign the tags to. | Required | 
| tags | IDs of the tags to assign to the asset (comma separated string). If used in combination with 'tag_names' the lists of tags are merged. | Optional | 
| tag_names | Names of the tags to assign to the asset (comma separated string). If used in combination with 'tags' the lists of tags are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-assign-tags-to-asset asset_type="IpRange" asset_id="0a8f44f9-05dc-42a3-a395-c83dad49fadf" tags="e00bc79d-d367-36f4-824c-042836fef5fc"```

#### Context Example

```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-unassign-tags-from-asset

***
Unassign tags from an Xpanse Asset.


#### Base Command

`expanse-unassign-tags-from-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | Type of Xpanse asset to unassign the tags from. Possible values are: IpRange, Certificate, Domain, Network, Device, ResponseiveIP. | Required | 
| asset_id | ID of the asset to unassign the tags from. | Required | 
| tags | IDs of the tags to unassign from the asset (comma separated string). If used in combination with 'tag_names' the lists of tags are merged. | Optional | 
| tag_names | Names of the tags to unassign from the asset (comma separated string). If used in combination with 'tags' the lists of tags are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-unassign-tags-from-asset asset_type="IpRange" asset_id="0a8f44f9-05dc-42a3-a395-c83dad49fadf" tags="e00bc79d-d367-36f4-824c-042836fef5fc"```

#### Context Example

```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-assign-tags-to-iprange

***
Assign tags to an Xpanse IP range.


#### Base Command

`expanse-assign-tags-to-iprange`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the IP range to assign tags to. | Required | 
| tags | IDs of the tags to assign to the IP range (comma separated string). If used in combination with 'tag_names' the lists of tags are merged. | Optional | 
| tag_names | Names of the tags to assign to the IP range (comma separated string). If used in combination with 'tags' the lists of tags are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-assign-tags-to-iprange asset_id="0a8f44f9-05dc-42a3-a395-c83dad49fadf" tag_names="xsoar-test-pb-tag"```

#### Context Example

```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-unassign-tags-from-iprange

***
Unassign tags from an Xpanse IP range.


#### Base Command

`expanse-unassign-tags-from-iprange`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the IP range to unassign tags from. | Required | 
| tags | IDs of the tags to unassign from the IP range (comma separated string). If used in combination with 'tag_names' the lists of tags are merged. | Optional | 
| tag_names | Names of the tags to unassign from the IP range (comma separated string). If used in combination with 'tags' the lists of tags are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-unassign-tags-from-iprange asset_id="0a8f44f9-05dc-42a3-a395-c83dad49fadf" tag_names="xsoar-test-pb-tag"```

#### Context Example

```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-assign-tags-to-certificate

***
Assign tags to an Xpanse certificate.


#### Base Command

`expanse-assign-tags-to-certificate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the certificate to assign tags to. | Required | 
| tags | IDs of the tags to assign to the certificate (comma separated string). If used in combination with 'tag_names' the lists of tags are merged. | Optional | 
| tag_names | Names of the tags to assign to the certificate (comma separated string). If used in combination with 'tags' the lists of tags are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-assign-tags-to-certificate asset_id="30a111ae-39e2-3b82-b459-249bac0c6065" tag_names="xsoar-test-pb-tag"```

#### Context Example

```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-unassign-tags-from-certificate

***
Unassign tags from an Xpanse certificate.


#### Base Command

`expanse-unassign-tags-from-certificate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the certificate to assign tags to. | Required | 
| tags | IDs of the tags to unassign from the certificate (comma separated string). If used in combination with 'tag_names' the lists of tags are merged. | Optional | 
| tag_names | Names of the tags to unassign from the certificate (comma separated string). If used in combination with 'tags' the lists of tags are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-unassign-tags-from-certificate asset_id="30a111ae-39e2-3b82-b459-249bac0c6065" tag_names="xsoar-test-pb-tag"```

#### Context Example

```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-assign-tags-to-domain

***
Assign tags to an Xpanse domain.


#### Base Command

`expanse-assign-tags-to-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the domain to assign tags to. | Required | 
| tags | IDs of the tags to assign to the domain (comma separated string). If used in combination with 'tag_names' the lists of tags are merged. | Optional | 
| tag_names | Names of the tags to assign to the domain (comma separated string). If used in combination with 'tags' the lists of tags are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-assign-tags-to-domain asset_id="142194a1-f443-3878-8dcc-540f4061c5f5" tag_names="xsoar-test-pb-tag"```

#### Context Example

```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-unassign-tags-from-domain

***
Unassign tags from an Xpanse domain.


#### Base Command

`expanse-unassign-tags-from-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the domain to unassign tags from. | Required | 
| tags | IDs of the tags to unassign from the domain (comma separated string). If used in combination with 'tag_names' the lists of tags are merged. | Optional | 
| tag_names | Names of the tags to unassign from the domain (comma separated string). If used in combination with 'tags' the lists of tags are merged. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example

```!expanse-unassign-tags-from-domain asset_id="142194a1-f443-3878-8dcc-540f4061c5f5" tag_names="xsoar-test-pb-tag"```

#### Context Example

```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-create-tag

***
Create a new tag in Xpanse.


#### Base Command

`expanse-create-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the tag (less than 128 characters). | Required | 
| description | Description of the tag (less than 512 characters). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Tag.created | Date | The date in which the tag was first created | 
| Expanse.Tag.description | String | The description associated with the tag | 
| Expanse.Tag.disabled | Boolean | If the tag should be hidden as a tag option in the Expander UI | 
| Expanse.Tag.id | String | The Xpanse ID for the tag | 
| Expanse.Tag.modified | Date | The date in which metadata about the tag was last modified | 
| Expanse.Tag.name | String | The display name for the tag | 
| Expanse.Tag.tenantId | String | The tenant ID associated with the tag | 


#### Command Example

```!expanse-create-tag name="xsoar-test-tag-new" description="XSOAR Test Tag"```

#### Context Example

```json
{}
```

#### Human Readable Output

>Tag already exists

### expanse-get-iprange

***
Retrieve Xpanse IP ranges by asset id or search parameters.


#### Base Command

`expanse-get-iprange`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Asset ID of the Xpanse IP range to retrieve. If provided, other search parameters are ignored. | Optional | 
| business_units | Returns only results whose Business Unit's ID falls in the provided list. (comma separated string). Cannot be used with the 'business_unit_names' argument. | Optional | 
| business_unit_names | Returns only results whose Business Unit's ID falls in the provided list. (comma separated string). Cannot be used with the 'business_units' argument. | Optional | 
| inet | Search for given IP/CIDR block using a single IP (d.d.d.d), a dashed IP range (d.d.d.d-d.d.d.d), a CIDR block (d.d.d.d/m), a partial CIDR (d.d.), or a wildcard (d.d.*.d). | Optional | 
| limit | Maximum number of entries to retrieve. | Optional | 
| tags | Returns only results whose Tag ID falls in the provided list. (comma separated string). Cannot be used with the 'tag_names' argument. | Optional | 
| tag_names | Returns only results whose Tag name falls in the provided list. (comma separated string). Cannot be used with the 'tags' argument. | Optional | 
| include | Include "none" or any of the following options in the response (comma separated) - annotations, severityCounts, attributionReasons, relatedRegistrationInformation, locationInformation. Default is none. | Optional | 
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IPRange.annotations.additionalNotes | String | Customer provided annotation details for an IP range | 
| Expanse.IPRange.annotations.contacts | String | Customer provided point-of-contact details for an IP range | 
| Expanse.IPRange.annotations.tags | String | Customer provided tags for an IP range | 
| Expanse.IPRange.attributionReasons.reason | String | The reasons why an IP range is attributed to the customer | 
| Expanse.IPRange.businessUnits.id | String | Business Units that the IP range has been assigned to | 
| Expanse.IPRange.businessUnits.name | String | Business Units that the IP range has been assigned to | 
| Expanse.IPRange.created | Date | The date that the IP range was added to the Expander instance | 
| Expanse.IPRange.id | String | Internal Xpanse ID for the IP Range | 
| Expanse.IPRange.ipVersion | String | The IP version of the IP range | 
| Expanse.IPRange.locationInformation.geolocation.city | String | The IP range geolocation | 
| Expanse.IPRange.locationInformation.geolocation.countryCode | String | The IP range geolocation | 
| Expanse.IPRange.locationInformation.geolocation.latitude | Number | The IP range geolocation | 
| Expanse.IPRange.locationInformation.geolocation.longitude | Number | The IP range geolocation | 
| Expanse.IPRange.locationInformation.geolocation.regionCode | String | The IP range geolocation | 
| Expanse.IPRange.locationInformation.ip | String | The IP range geolocation | 
| Expanse.IPRange.modified | Date | The date on which the IP range was last ingested into Expander | 
| Expanse.IPRange.rangeIntroduced | Date | The date that the IP range was added to the Expander instance | 
| Expanse.IPRange.rangeSize | Number | The number of IP addresses in the IP range | 
| Expanse.IPRange.rangeType | String | If the IP range is Xpanse-generated parent range or a customer-generated custom range | 
| Expanse.IPRange.relatedRegistrationInformation.country | String | The country within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.endAddress | String | The end address within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.handle | String | The handle within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.ipVersion | String | The IP version within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.name | String | The name within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.parentHandle | String | The parent handle within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.address | String | The address within the registry entities of the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.email | String | The email within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.action | String | The events action within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.actor | String | The events actor within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.date | Date | The events date within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.firstRegistered | Date | The first registered date within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.formattedName | String | The formatted name within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.handle | String | The handle within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.id | String | The ID within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.lastChanged | Date | The last changed date within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.org | String | The org within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.phone | String | The phone number within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.relatedEntityHandles | String | The related entity handles within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.remarks | String | The remarks within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.roles | String | The roles within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.statuses | String | The statuses within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.remarks | String | The remarks within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.startAddress | String | The start address within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.updatedDate | Date | The last update date within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.whoisServer | String | The Whois server within the IP range registration information | 
| Expanse.IPRange.responsiveIpCount | Number | The number of IPs responsive on the public Internet within the IP range | 
| Expanse.IPRange.severityCounts.count | Number | The number of exposures observed on the IP range | 
| Expanse.IPRange.severityCounts.type | String | The severity level of the exposures observed on the IP range | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 


#### Command Example

```!expanse-get-iprange limit="1" include="none" limit="1"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "1.179.133.112/29",
        "Score": 0,
        "Type": [
            "cidr"
        ],
        "Vendor": "ExpanseV2"
    },
    "Expanse": {
        "IPRange": {
            "businessUnits": [
                {
                    "id": "c94c50ca-124f-4983-8da5-1756138e2252",
                    "name": "PANW Acme Latex Supply Dev"
                }
            ],
            "cidr": "1.179.133.112/29",
            "created": "2020-09-22",
            "customChildRanges": [],
            "id": "0a8f44f9-05dc-42a3-a395-c83dad49fadf",
            "ipVersion": "4",
            "modified": "2020-12-18",
            "rangeIntroduced": "2020-09-22",
            "rangeSize": 8,
            "rangeType": "parent",
            "responsiveIpCount": 0
        }
    }
}
```

#### Human Readable Output

>### Expanse IP Range List
>
>|businessUnits|cidr|created|customChildRanges|id|ipVersion|modified|rangeIntroduced|rangeSize|rangeType|responsiveIpCount|
>|---|---|---|---|---|---|---|---|---|---|---|
>| {'id': 'c94c50ca-124f-4983-8da5-1756138e2252', 'name': 'PANW Acme Latex Supply Dev'} | 1.179.133.112/29 | 2020-09-22 |  | 0a8f44f9-05dc-42a3-a395-c83dad49fadf | 4 | 2020-12-18 | 2020-09-22 | 8 | parent | 0 |


### expanse-get-domain

***
Retrieve Xpanse domains by domain name or search parameters.


#### Base Command

`expanse-get-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to retrieve (exact match). If provided, other search parameters are ignored. | Optional | 
| last_observed_date | Last date the domain was observed by Xpanse (Format is YYYY-MM-DD). | Optional | 
| search | Search domain names that match the specified substring. | Optional | 
| limit | Maximum number of entries to retrieve. | Optional | 
| has_dns_resolution | Retrieve only domains with or without DNS resolution. Possible values are: true, false. | Optional | 
| has_active_service | Retrieve only domains with or without an active service discovered by Xpanse. Possible values are: true, false. | Optional | 
| has_related_cloud_resources | Retrieve only domains with or without cloud resources discovered by Xpanse. Possible values are: true, false. | Optional | 
| tags | Returns only results whose Tag ID falls in the provided list. (comma separated string). Cannot be used with the 'tag_names' argument. | Optional | 
| tag_names | Returns only results whose Tag name falls in the provided list. (comma separated string). Cannot be used with the 'tags' argument. | Optional | 
| business_units | Returns only results whose Business Unit's ID falls in the provided list. (comma separated string). Cannot be used with the 'business_unit_names' argument. | Optional | 
| business_unit_names | Returns only results whose Business Unit's name falls in the provided list. (comma separated string). Cannot be used with the 'business_units' argument. | Optional | 
| providers | Returns only results whose Provider's ID falls in the provided list. (comma separated string). Cannot be used with the 'provider_names' argument. | Optional | 
| provider_names | Returns only results whose Provider's name falls in the provided list. (comma separated string). Cannot be used with the 'providers' argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Domain.annotations.note | String | Customer provided annotation details for a domain | 
| Expanse.Domain.annotations.contacts.id | String | ID for customer provided contact details for a domain | 
| Expanse.Domain.annotations.contacts.name | String | Customer provided contact details for a domain | 
| Expanse.Domain.annotations.tags.id | String | ID for customer added tag on a domain in Expander | 
| Expanse.Domain.annotations.tags.name | String | Customer added tag on a domain in Expander | 
| Expanse.Domain.businessUnits.id | String | Business Units that the domain has been assigned to | 
| Expanse.Domain.businessUnits.name | String | Business Units that the domain has been assigned to | 
| Expanse.Domain.businessUnits.tenantId | String | Tenant ID for business Units that the domain has been assigned to | 
| Expanse.Domain.dateAdded | Date | The date that the domain was added to the Expander instance | 
| Expanse.Domain.details.recentIps.assetKey | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.assetType | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.businessUnits.id | String | Business Units for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.businessUnits.name | String | Business Units for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.businessUnits.tenantId | String | Tenant information for business Units that the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.commonName | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.domain | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.ip | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.lastObserved | Date | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.provider.id | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.provider.name | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.tenant.id | String | Tenant information for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.tenant.name | String | Tenant information for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.tenant.tenantId | String | Tenant information for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.type | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.dnsResolutionStatus | String | Latest DNS resolution status | 
| Expanse.Domain.firstObserved | Date | The date that the domain was first observed | 
| Expanse.Domain.hasLinkedCloudResources | Boolean | Whether the domain has any linked cloud resources associated with it | 
| Expanse.Domain.id | String | Internal Xpanse ID for Domain | 
| Expanse.Domain.domain | String | The domain value | 
| Expanse.Domain.isCollapsed | Boolean | Whether or not the subdomains of the domain are collapsed | 
| Expanse.Domain.isPaidLevelDomain | Boolean | Whether or not the domain is a PLD | 
| Expanse.Domain.lastObserved | Date | The date that the domain was most recently observed | 
| Expanse.Domain.lastSampledIp | String | The last observed IPv4 address for the domain | 
| Expanse.Domain.lastSubdomainMetadata.collapseType | String | Sub-domain metadata | 
| Expanse.Domain.lastSubdomainMetadata.numSubdomains | Number | Sub-domain metadata | 
| Expanse.Domain.lastSubdomainMetadata.numDistinctIps | Number | Sub-domain metadata | 
| Expanse.Domain.lastSubdomainMetadata.date | Date | Sub-domain metadata | 
| Expanse.Domain.providers.id | String | Information about the hosting provider of the IP the domain resolves to | 
| Expanse.Domain.providers.name | String | Information about the hosting provider of the IP the domain resolves to | 
| Expanse.Domain.serviceStatus | String | Detected service statuses for the domain | 
| Expanse.Domain.sourceDomain | String | The source domain for the domain object | 
| Expanse.Domain.tenant.id | String | Tenant information for the domain | 
| Expanse.Domain.tenant.name | String | Tenant information for the domain | 
| Expanse.Domain.tenant.tenantId | String | Tenant information for the domain | 
| Expanse.Domain.whois.admin.city | String | The admin city in the Whois information for the domain | 
| Expanse.Domain.whois.admin.country | String | The admin country in the Whois information for the domain | 
| Expanse.Domain.whois.admin.emailAddress | String | The admin email address in the Whois information for the domain | 
| Expanse.Domain.whois.admin.faxExtension | String | The admin fax extension in the Whois information for the domain | 
| Expanse.Domain.whois.admin.faxNumber | String | The admin fax number in the Whois information for the domain | 
| Expanse.Domain.whois.admin.name | String | The admin name in the Whois information for the domain | 
| Expanse.Domain.whois.admin.organization | String | The admin organization in the Whois information for the domain | 
| Expanse.Domain.whois.admin.phoneExtension | String | The admin phone extension in the Whois information for the domain | 
| Expanse.Domain.whois.admin.phoneNumber | String | The admin phone number in the Whois information for the domain | 
| Expanse.Domain.whois.admin.postalCode | String | The admin postal code in the Whois information for the domain | 
| Expanse.Domain.whois.admin.province | String | The admin province in the Whois information for the domain | 
| Expanse.Domain.whois.admin.registryId | String | The admin registry ID in the Whois information for the domain | 
| Expanse.Domain.whois.admin.street | String | The admin street in the Whois information for the domain | 
| Expanse.Domain.whois.creationDate | Date | The creation date in the Whois information for the domain | 
| Expanse.Domain.whois.dnssec | String | The dnssec in the Whois information for the domain | 
| Expanse.Domain.whois.domain | String | The domain in the Whois information for the domain | 
| Expanse.Domain.whois.domainStatuses | String | The domain statuses in the Whois information for the domain | 
| Expanse.Domain.whois.nameServers | String | The name servers in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.city | String | The registrant city in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.country | String | The registrant country in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.emailAddress | String | The registrant email address in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.faxExtension | String | The registrant fax extension in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.faxNumber | String | The registrant fax number in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.name | String | The registrant name in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.organization | String | The registrant organization in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.phoneExtension | String | The registrant phone extension in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.phoneNumber | String | The registrant phone number in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.postalCode | String | The registrant postal code in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.province | String | The registrant province in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.registryId | String | The registrant registry ID in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.street | String | The registrant street in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.abuseContactEmail | String | The registrar abuse contact email in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.abuseContactPhone | String | The registrar abuse contact phone in the Whois information for the domain'' | 
| Expanse.Domain.whois.registrar.formattedName | String | The registrar formatted name Whois information for the domain | 
| Expanse.Domain.whois.registrar.ianaId | String | The registrar iana ID in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.name | String | The registrar name in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.registrationExpirationDate | Date | The registrar registration expiration date in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.url | String | The registrar URL in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.whoisServer | String | The registrar Whois server in the Whois information for the domain | 
| Expanse.Domain.whois.registryDomainId | String | The registry domain ID in the Whois information for the domain | 
| Expanse.Domain.whois.registryExpiryDate | Date | The registry expiry date in the Whois information for the domain | 
| Expanse.Domain.whois.reseller | String | The reseller in the Whois information for the domain | 
| Expanse.Domain.whois.tech.city | String | The tech city in the Whois information for the domain | 
| Expanse.Domain.whois.tech.country | String | The tech country in the Whois information for the domain | 
| Expanse.Domain.whois.tech.emailAddress | String | The tech email address in the Whois information for the domain | 
| Expanse.Domain.whois.tech.faxExtension | String | The tech fax extension in the Whois information for the domain | 
| Expanse.Domain.whois.tech.faxNumber | String | The tech fax number in the Whois information for the domain | 
| Expanse.Domain.whois.tech.name | String | The tech name in the Whois information for the domain | 
| Expanse.Domain.whois.tech.organization | String | The tech organization in the Whois information for the domain | 
| Expanse.Domain.whois.tech.phoneExtension | String | The tech phone extension in the Whois information for the domain | 
| Expanse.Domain.whois.tech.phoneNumber | String | The tech phone number in the Whois information for the domain | 
| Expanse.Domain.whois.tech.postalCode | String | The tech postal code in the Whois information for the domain | 
| Expanse.Domain.whois.tech.province | String | The tech province in the Whois information for the domain | 
| Expanse.Domain.whois.tech.registryId | String | The tech registry ID in the Whois information for the domain | 
| Expanse.Domain.whois.tech.street | String | The tech street in the Whois information for the domain | 
| Expanse.Domain.whois.updatedDate | Date | The updated date in the Whois information for the domain | 
| Expanse.Domain.details.cloudResources.id | String | The cloud resource ID | 
| Expanse.Domain.details.cloudResources.tenant.id | String | Tenant information for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.tenant.name | String | Tenant information for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.tenant.tenantId | String | Tenant information for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.businessUnits.id | String | Business Units that the cloud resource has been assigned to | 
| Expanse.Domain.details.cloudResources.businessUnits.name | String | Business Units that the cloud resource has been assigned to | 
| Expanse.Domain.details.cloudResources.businessUnits.tenantId | String | Tenant information businessUnits that the cloud resource as been assigned to | 
| Expanse.Domain.details.cloudResources.dateAdded | Date | The date that the cloud resource was added to the Expander instance | 
| Expanse.Domain.details.cloudResources.firstObserved | Date | The date that the cloud resource was first observed | 
| Expanse.Domain.details.cloudResources.lastObserved | Date | The date that the domain was most recently observed | 
| Expanse.Domain.details.cloudResources.instanceId | String | Instance ID for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.type | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.name | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.ips | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.domain | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.provider.id | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.provider.name | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.region | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.vpc.id | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.vpc.name | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.accountIntegration.id | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.accountIntegration.name | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.recentIps.assetKey | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.assetType | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.businessUnits.id | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Domain.details.cloudResources.recentIps.businessUnits.name | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Domain.details.cloudResources.recentIps.businessUnits.tenantId | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Domain.details.cloudResources.recentIps.commonName | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.domain | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.ip | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.lastObserved | Date | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.provider.id | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.provider.name | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.tenant.id | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.tenant.name | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.tenant.tenantId | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.type | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.annotations.note | String | Customer provided annotation details for a domain | 
| Expanse.Domain.details.cloudResources.annotations.contacts.id | String | ID for customer provided contact details for a domain | 
| Expanse.Domain.details.cloudResources.annotations.contacts.name | String | Customer provided contact details for a domain | 
| Expanse.Domain.details.cloudResources.annotations.tags.id | String | ID for customer added tag on a domain in Expander | 
| Expanse.Domain.details.cloudResources.annotations.tags.name | String | Customer added tag on a domain in Expander | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.DNS | String | A list of IP objects resolved by DNS. | 
| Domain.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| Domain.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| Domain.CreationDate | Date | The date that the domain was created. | 
| Domain.UpdatedDate | String | The date that the domain was last updated. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.DomainStatus | Date | The status of the domain. | 
| Domain.NameServers | String | Name servers of the domain. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.Subdomains | String | Subdomains of the domain. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Registrant.Email | String | The email address of the registrant. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.WHOIS.DomainStatus | String | The status of the domain. | 
| Domain.WHOIS.NameServers | String | Name servers of the domain. | 
| Domain.WHOIS.CreationDate | Date | The date that the domain was created. | 
| Domain.WHOIS.UpdatedDate | Date | The date that the domain was last updated. | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.Registrant.Name | String | The name of the registrant. | 
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant. | 
| Domain.WHOIS.Registrant.Phone | String | The phone number of the registrant. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: "GoDaddy" | 
| Domain.WHOIS.Registrar.AbuseEmail | String | The email address of the contact for reporting abuse. | 
| Domain.WHOIS.Registrar.AbusePhone | String | The phone number of contact for reporting abuse. | 
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator. | 
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator. | 
| Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.WHOIS.History | String | List of Whois objects | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example

```!expanse-get-domain limit="1"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "*.108.pets.com",
        "Score": 0,
        "Type": "domainglob",
        "Vendor": "ExpanseV2"
    },
    "Domain": {
        "Admin": {
            "Country": "UNITED STATES",
            "Email": "legal@petsmart.com",
            "Name": "Admin Contact",
            "Phone": "16235806100"
        },
        "CreationDate": "1994-11-21T05:00:00Z",
        "DomainStatus": "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited",
        "ExpirationDate": "2018-11-20T05:00:00Z",
        "Name": "*.108.pets.com",
        "NameServers": [
            "NS1.MARKMONITOR.COM",
            "NS2.MARKMONITOR.COM",
            "NS3.MARKMONITOR.COM",
            "NS4.MARKMONITOR.COM",
            "NS5.MARKMONITOR.COM",
            "NS6.MARKMONITOR.COM",
            "NS7.MARKMONITOR.COM"
        ],
        "Organization": "PetSmart Home Office, Inc.",
        "Registrant": {
            "Country": "UNITED STATES",
            "Email": "legal@petsmart.com",
            "Name": "Admin Contact",
            "Phone": "16235806100"
        },
        "Registrar": {
            "AbuseEmail": null,
            "AbusePhone": null,
            "Name": "MarkMonitor Inc."
        },
        "UpdatedDate": "2016-10-19T09:12:50Z",
        "WHOIS": {
            "Admin": {
                "Country": "UNITED STATES",
                "Email": "legal@petsmart.com",
                "Name": "Admin Contact",
                "Phone": "16235806100"
            },
            "CreationDate": "1994-11-21T05:00:00Z",
            "DomainStatus": "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited",
            "ExpirationDate": "2018-11-20T05:00:00Z",
            "NameServers": [
                "NS1.MARKMONITOR.COM",
                "NS2.MARKMONITOR.COM",
                "NS3.MARKMONITOR.COM",
                "NS4.MARKMONITOR.COM",
                "NS5.MARKMONITOR.COM",
                "NS6.MARKMONITOR.COM",
                "NS7.MARKMONITOR.COM"
            ],
            "Registrant": {
                "Country": "UNITED STATES",
                "Email": "legal@petsmart.com",
                "Name": "Admin Contact",
                "Phone": "16235806100"
            },
            "Registrar": {
                "AbuseEmail": null,
                "AbusePhone": null,
                "Name": "MarkMonitor Inc."
            },
            "UpdatedDate": "2016-10-19T09:12:50Z"
        }
    },
    "Expanse": {
        "Domain": {
            "annotations": {
                "contacts": [],
                "note": "",
                "tags": []
            },
            "businessUnits": [
                {
                    "id": "c4de7fad-cde1-46cf-8725-a5999533db59",
                    "name": "PANW VanDelay Import-Export Dev",
                    "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
                },
                {
                    "id": "f738ace6-f451-4f31-898d-a12afa204b2a",
                    "name": "PANW VanDelay Dev",
                    "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
                }
            ],
            "dateAdded": "2020-09-22T21:23:02.372Z",
            "details": null,
            "dnsResolutionStatus": [
                "HAS_DNS_RESOLUTION"
            ],
            "domain": "*.108.pets.com",
            "firstObserved": "2020-09-22T06:10:31.787Z",
            "hasLinkedCloudResources": false,
            "id": "142194a1-f443-3878-8dcc-540f4061c5f5",
            "isCollapsed": false,
            "isPaidLevelDomain": false,
            "lastObserved": "2020-09-22T06:10:31.787Z",
            "lastSampledIp": "72.52.10.14",
            "lastSubdomainMetadata": null,
            "providers": [
                {
                    "id": "Akamai",
                    "name": "Akamai Technologies"
                }
            ],
            "serviceStatus": [
                "NO_ACTIVE_SERVICE",
                "NO_ACTIVE_ON_PREM_SERVICE",
                "NO_ACTIVE_CLOUD_SERVICE"
            ],
            "sourceDomain": "pets.com",
            "tenant": {
                "id": "f738ace6-f451-4f31-898d-a12afa204b2a",
                "name": "PANW VanDelay Dev",
                "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
            },
            "whois": [
                {
                    "admin": {
                        "city": "Phoenix",
                        "country": "UNITED STATES",
                        "emailAddress": "legal@petsmart.com",
                        "faxExtension": "",
                        "faxNumber": "16235806109",
                        "name": "Admin Contact",
                        "organization": "PetSmart Home Office, Inc.",
                        "phoneExtension": "",
                        "phoneNumber": "16235806100",
                        "postalCode": "85027",
                        "province": "AZ",
                        "registryId": null,
                        "street": "19601 N 27th Ave,"
                    },
                    "creationDate": "1994-11-21T05:00:00Z",
                    "dnssec": null,
                    "domain": "pets.com",
                    "domainStatuses": [
                        "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited"
                    ],
                    "nameServers": [
                        "NS1.MARKMONITOR.COM",
                        "NS2.MARKMONITOR.COM",
                        "NS3.MARKMONITOR.COM",
                        "NS4.MARKMONITOR.COM",
                        "NS5.MARKMONITOR.COM",
                        "NS6.MARKMONITOR.COM",
                        "NS7.MARKMONITOR.COM"
                    ],
                    "registrant": {
                        "city": "Phoenix",
                        "country": "UNITED STATES",
                        "emailAddress": "legal@petsmart.com",
                        "faxExtension": "",
                        "faxNumber": "16235806109",
                        "name": "Admin Contact",
                        "organization": "PetSmart Home Office, Inc.",
                        "phoneExtension": "",
                        "phoneNumber": "16235806100",
                        "postalCode": "85027",
                        "province": "AZ",
                        "registryId": null,
                        "street": "19601 N 27th Ave,"
                    },
                    "registrar": {
                        "abuseContactEmail": null,
                        "abuseContactPhone": null,
                        "formattedName": null,
                        "ianaId": null,
                        "name": "MarkMonitor Inc.",
                        "registrationExpirationDate": null,
                        "url": null,
                        "whoisServer": "whois.markmonitor.com"
                    },
                    "registryDomainId": null,
                    "registryExpiryDate": "2018-11-20T05:00:00Z",
                    "reseller": null,
                    "tech": {
                        "city": null,
                        "country": null,
                        "emailAddress": null,
                        "faxExtension": null,
                        "faxNumber": null,
                        "name": null,
                        "organization": null,
                        "phoneExtension": null,
                        "phoneNumber": null,
                        "postalCode": null,
                        "province": null,
                        "registryId": null,
                        "street": null
                    },
                    "updatedDate": "2016-10-19T09:12:50Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Expanse Domain List
>
>|annotations|businessUnits|dateAdded|details|dnsResolutionStatus|domain|firstObserved|hasLinkedCloudResources|id|isCollapsed|isPaidLevelDomain|lastObserved|lastSampledIp|lastSubdomainMetadata|providers|serviceStatus|sourceDomain|tenant|whois|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| contacts: <br/>tags: <br/>note:  | {'id': 'c4de7fad-cde1-46cf-8725-a5999533db59', 'name': 'PANW VanDelay Import-Export Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'},<br/>{'id': 'f738ace6-f451-4f31-898d-a12afa204b2a', 'name': 'PANW VanDelay Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'} | 2020-09-22T21:23:02.372Z |  | HAS_DNS_RESOLUTION | *.108.pets.com | 2020-09-22T06:10:31.787Z | false | 142194a1-f443-3878-8dcc-540f4061c5f5 | false | false | 2020-09-22T06:10:31.787Z | 72.52.10.14 |  | {'id': 'Akamai', 'name': 'Akamai Technologies'} | NO_ACTIVE_SERVICE,<br/>NO_ACTIVE_ON_PREM_SERVICE,<br/>NO_ACTIVE_CLOUD_SERVICE | pets.com | id: f738ace6-f451-4f31-898d-a12afa204b2a<br/>name: PANW VanDelay Dev<br/>tenantId: f738ace6-f451-4f31-898d-a12afa204b2a | {'domain': 'pets.com', 'registryDomainId': None, 'updatedDate': '2016-10-19T09:12:50Z', 'creationDate': '1994-11-21T05:00:00Z', 'registryExpiryDate': '2018-11-20T05:00:00Z', 'reseller': None, 'registrar': {'name': 'MarkMonitor Inc.', 'formattedName': None, 'whoisServer': 'whois.markmonitor.com', 'url': None, 'ianaId': None, 'registrationExpirationDate': None, 'abuseContactEmail': None, 'abuseContactPhone': None}, 'domainStatuses': ['clientDeleteProhibited clientTransferProhibited clientUpdateProhibited'], 'nameServers': ['NS1.MARKMONITOR.COM', 'NS2.MARKMONITOR.COM', 'NS3.MARKMONITOR.COM', 'NS4.MARKMONITOR.COM', 'NS5.MARKMONITOR.COM', 'NS6.MARKMONITOR.COM', 'NS7.MARKMONITOR.COM'], 'registrant': {'name': 'Admin Contact', 'organization': 'PetSmart Home Office, Inc.', 'street': '19601 N 27th Ave,', 'city': 'Phoenix', 'province': 'AZ', 'postalCode': '85027', 'country': 'UNITED STATES', 'phoneNumber': '16235806100', 'phoneExtension': '', 'faxNumber': '16235806109', 'faxExtension': '', 'emailAddress': '<legal@petsmart.com>', 'registryId': None}, 'admin': {'name': 'Admin Contact', 'organization': 'PetSmart Home Office, Inc.', 'street': '19601 N 27th Ave,', 'city': 'Phoenix', 'province': 'AZ', 'postalCode': '85027', 'country': 'UNITED STATES', 'phoneNumber': '16235806100', 'phoneExtension': '', 'faxNumber': '16235806109', 'faxExtension': '', 'emailAddress': '<legal@petsmart.com>', 'registryId': None}, 'tech': {'name': None, 'organization': None, 'street': None, 'city': None, 'province': None, 'postalCode': None, 'country': None, 'phoneNumber': None, 'phoneExtension': None, 'faxNumber': None, 'faxExtension': None, 'emailAddress': None, 'registryId': None}, 'dnssec': None} |


### expanse-get-associated-domains

***
Returns all the Xpanse domains which have been seen with the specified certificate or IP address.


#### Base Command

`expanse-get-associated-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| common_name | The common name of the certificate to search domains for. Fuzzy matching is done on this name, however query times can grow quite large when searching for short strings. Ex. "*.myhost.com" is a better search term than "host". | Optional | 
| ip | The IP address to search domains for. | Optional | 
| limit | Maximum number of matching certificates to retrieve. | Optional | 
| domains_limit | Maximum number of domains per certificate to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.AssociatedDomain.name | String | Name of the domain. | 
| Expanse.AssociatedDomain.IP | String | IP Address the domain resolved to. | 
| Expanse.AssociatedDomain.certificate | String | Xpanse ID of the certificate associated to this domain. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example

```!expanse-get-associated-domains ip="1.1.1.1"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "test.developers.company.com",
        "Score": 0,
        "Type": "domain",
        "Vendor": "ExpanseV2"
    },
    "Domain": {
        "Name": "test.developers.company.com"
    },
    "Expanse": {
        "AssociatedDomain": {
            "IP": [
                "1.1.1.1"
            ],
            "certificate": [],
            "name": "test.developers.company.com"
        }
    }
}
```

#### Human Readable Output

>### Expanse Domains matching Certificate Common Name: None
>
>|name|IP|certificate|
>|---|---|---|
>| test.developers.company.com | 1.1.1.1 |  |


### expanse-get-certificate

***
Retrieve Xpanse certificates by MD5 hash or search parameters.


#### Base Command

`expanse-get-certificate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5_hash | MD5 Hash of the certificate. If provided, other search parameters are ignored. | Optional | 
| last_observed_date | Last date the domain was observed by Xpanse (Format is YYYY-MM-DD), to be used with domain argument. | Optional | 
| search | Search for  certificates with the specified substring in common name. | Optional | 
| limit | Maximum number of entries to retrieve. | Optional | 
| has_certificate_advertisement | Retrieve only certificates actively/not actively advertised. Possible values are: true, false. | Optional | 
| has_active_service | Retrieve only certificates with or without an active service discovered by Xpanse. Possible values are: true, false. | Optional | 
| has_related_cloud_resources | Retrieve only certificates with or without cloud resources discovered by Xpanse. Possible values are: true, false. | Optional | 
| tags | Returns only results whose Tag ID falls in the provided list. (comma separated string). Cannot be used with the 'tag_names' argument. | Optional | 
| tag_names | Returns only results whose Tag name falls in the provided list. (comma separated string). Cannot be used with the 'tags' argument. | Optional | 
| business_units | Returns only results whose Business Unit's ID falls in the provided list. (comma separated string). Cannot be used with the 'business_unit_names' argument. | Optional | 
| business_unit_names | Returns only results whose Business Unit's name falls in the provided list. (comma separated string). Cannot be used with the 'business_units' argument. | Optional | 
| providers | Returns only results whose Provider's ID falls in the provided list. (comma separated string). Cannot be used with the 'provider_names' argument. | Optional | 
| provider_names | Returns only results whose Provider's name falls in the provided list. (comma separated string). Cannot be used with the 'providers' argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Certificate.annotations.note | String | Customer provided annotation details for a certificate | 
| Expanse.Certificate.annotations.contacts.id | String | ID for customer provided contact details for a certificate | 
| Expanse.Certificate.annotations.contacts.name | String | Customer provided contact details for a certificate | 
| Expanse.Certificate.annotations.tags.id | String | ID for customer added tag on a certificate in Expander | 
| Expanse.Certificate.annotations.tags.name | String | Customer added tag on a certificate in Expander | 
| Expanse.Certificate.businessUnits.id | String | Business Units that the certificate has been assigned to | 
| Expanse.Certificate.businessUnits.name | String | Business Units that the certificate has been assigned to | 
| Expanse.Certificate.businessUnits.tenantId | String | Tenant information for business units that the certificate has been assigned to | 
| Expanse.Certificate.certificate.formattedIssuerOrg | String | The formatted issuer org in the certificate | 
| Expanse.Certificate.certificate.id | String | The certificate ID | 
| Expanse.Certificate.certificate.issuer | String | The issuer in the certificate | 
| Expanse.Certificate.certificate.issuerAlternativeNames | String | The issuer alternative names in the certificate | 
| Expanse.Certificate.certificate.issuerCountry | String | The issuer country in the certificate | 
| Expanse.Certificate.certificate.issuerEmail | String | The issuer email in the certificate | 
| Expanse.Certificate.certificate.issuerLocality | String | The issuer locality in the certificate | 
| Expanse.Certificate.certificate.issuerName | String | The issuer name in the certificate | 
| Expanse.Certificate.certificate.issuerOrg | String | The issuer org in the certificate | 
| Expanse.Certificate.certificate.issuerOrgUnit | String | The issuer org unit in the certificate | 
| Expanse.Certificate.certificate.issuerState | String | The issuer state in the certificate | 
| Expanse.Certificate.certificate.md5Hash | String | The md5hash in the certificate | 
| Expanse.Certificate.certificate.pemSha1 | String | The pemSha1 in the certificate | 
| Expanse.Certificate.certificate.pemSha256 | String | The pemSha256 in the certificate | 
| Expanse.Certificate.certificate.publicKey | String | The public key in the certificate | 
| Expanse.Certificate.certificate.publicKeyAlgorithm | String | The public key algorithm in the certificate | 
| Expanse.Certificate.certificate.publicKeyBits | Number | The public key bits in the certificate | 
| Expanse.Certificate.certificate.publicKeyModulus | String | The public key modulus in the certificate | 
| Expanse.Certificate.certificate.publicKeyRsaExponent | Number | The public key RSA exponent in the certificate | 
| Expanse.Certificate.certificate.publicKeySpki | String | The public key Spki in the certificate | 
| Expanse.Certificate.certificate.serialNumber | String | The serial number in the certificate | 
| Expanse.Certificate.certificate.signatureAlgorithm | String | The signature algorithm in the certificate | 
| Expanse.Certificate.certificate.subject | String | The subject in the certificate | 
| Expanse.Certificate.certificate.subjectAlternativeNames | String | The subject alternative names in the certificate | 
| Expanse.Certificate.certificate.subjectCountry | String | The subject country in the certificate | 
| Expanse.Certificate.certificate.subjectEmail | String | The subject email in the certificate | 
| Expanse.Certificate.certificate.subjectLocality | String | The subject locality in the certificate | 
| Expanse.Certificate.certificate.subjectName | String | The subject name in the certificate | 
| Expanse.Certificate.certificate.subjectOrg | String | The subject org in the certificate | 
| Expanse.Certificate.certificate.subjectOrgUnit | String | The subject org unit in the certificate | 
| Expanse.Certificate.certificate.subjectState | String | The subject state in the certificate | 
| Expanse.Certificate.certificate.validNotAfter | Date | The valid not after date in the certificate | 
| Expanse.Certificate.certificate.validNotBefore | Date | The valid not before date in the certificate | 
| Expanse.Certificate.certificate.version | String | The version in the certificate | 
| Expanse.Certificate.certificateAdvertisementStatus | String | Certificate advertisement statuses | 
| Expanse.Certificate.commonName | String | Common Name for the certificate | 
| Expanse.Certificate.dateAdded | Date | The date that the certificate was added to the Expander instance | 
| Expanse.Certificate.details.base64Encoded | String | Additional details for the certificate | 
| Expanse.Certificate.details.recentIps.assetKey | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.assetType | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.businessUnits.id | String | Business Units that the recent IPs linked to the certificate has been assigned to | 
| Expanse.Certificate.details.recentIps.businessUnits.name | String | Business Units that the recent IPs linked to the certificate has been assigned to | 
| Expanse.Certificate.details.recentIps.businessUnits.tenantId | String | Tenant information for business Units that the recent IPs linked to the certificate has been assigned to | 
| Expanse.Certificate.details.recentIps.commonName | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.domain | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.ip | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.lastObserved | Date | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.provider.id | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.provider.name | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.tenant.id | String | Tenant information for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.tenant.name | String | Tenant information for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.tenant.tenantId | String | Tenant information for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.type | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.firstObserved | Date | The date that the certificate was first observed | 
| Expanse.Certificate.hasLinkedCloudResources | Boolean | Whether the certificate has any linked cloud resources associated with it | 
| Expanse.Certificate.id | String | Internal Xpanse ID for Certificate | 
| Expanse.Certificate.lastObserved | Date | The date that the certificate was most recently observed | 
| Expanse.Certificate.properties | String | Xpanse tagged properties of the certificate | 
| Expanse.Certificate.providers.id | String | The Provider information for the certificate | 
| Expanse.Certificate.providers.name | String | The Provider information for the certificate | 
| Expanse.Certificate.serviceStatus | String | Detected service statuses for the certificate | 
| Expanse.Certificate.tenant.id | String | Tenant information for the certificate | 
| Expanse.Certificate.tenant.name | String | Tenant information for the certificate | 
| Expanse.Certificate.tenant.tenantId | String | Tenant information for the certificate | 
| Expanse.Certificate.details.cloudResources.id | String | The cloud resource ID | 
| Expanse.Certificate.details.cloudResources.tenant.id | String | Tenant information for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.tenant.name | String | Tenant information for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.tenant.tenantId | String | Tenant information for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.businessUnits.id | String | Business Units that the cloud resource has been assigned to | 
| Expanse.Certificate.details.cloudResources.businessUnits.name | String | Business Units that the cloud resource has been assigned to | 
| Expanse.Certificate.details.cloudResources.businessUnits.tenantId | String | Tenant information businessUnits that the cloud resource as been assigned to | 
| Expanse.Certificate.details.cloudResources.dateAdded | Date | The date that the cloud resource was added to the Expander instance | 
| Expanse.Certificate.details.cloudResources.firstObserved | Date | The date that the cloud resource was first observed | 
| Expanse.Certificate.details.cloudResources.lastObserved | Date | The date that the certificate was most recently observed | 
| Expanse.Certificate.details.cloudResources.instanceId | String | Instance ID for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.type | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.name | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.ips | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.domain | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.provider.id | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.provider.name | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.region | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.vpc.id | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.vpc.name | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.accountIntegration.id | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.accountIntegration.name | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.recentIps.assetKey | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.assetType | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.businessUnits.id | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Certificate.details.cloudResources.recentIps.businessUnits.name | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Certificate.details.cloudResources.recentIps.businessUnits.tenantId | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Certificate.details.cloudResources.recentIps.commonName | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.domain | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.ip | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.lastObserved | Date | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.provider.id | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.provider.name | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.tenant.id | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.tenant.name | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.tenant.tenantId | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.type | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.annotations.note | String | Customer provided annotation details for a certificate | 
| Expanse.Certificate.details.cloudResources.annotations.contacts.id | String | ID for customer provided contact details for a certificate | 
| Expanse.Certificate.details.cloudResources.annotations.contacts.name | String | Customer provided contact details for a certificate | 
| Expanse.Certificate.details.cloudResources.annotations.tags.id | String | ID for customer added tag on a certificate in Expander | 
| Expanse.Certificate.details.cloudResources.annotations.tags.name | String | Customer added tag on a certificate in Expander | 
| Certificate.Name | String | Name \(CN or SAN\) appearing in the certificate. | 
| Certificate.SubjectDN | String | The Subject Distinguished Name of the certificate.
This field includes the Common Name of the certificate.
 | 
| Certificate.PEM | String | Certificate in PEM format. | 
| Certificate.IssuerDN | String | The Issuer Distinguished Name of the certificate. | 
| Certificate.SerialNumber | String | The Serial Number of the certificate. | 
| Certificate.ValidityNotAfter | Date | End of certificate validity period. | 
| Certificate.ValidityNotBefore | Date | Start of certificate validity period. | 
| Certificate.SubjectAlternativeName.Value | String | Name of the SAN. | 
| Certificate.SHA256 | String | SHA256 Fingerprint of the certificate in DER format. | 
| Certificate.SHA1 | String | SHA1 Fingerprint of the certificate in DER format. | 
| Certificate.MD5 | String | MD5 Fingerprint of the certificate in DER format. | 
| Certificate.PublicKey.Algorithm | String | Algorithm used for public key of the certificate. | 
| Certificate.PublicKey.Length | Number | Length in bits of the public key of the certificate. | 
| Certificate.PublicKey.Modulus | String | Modulus of the public key for RSA keys. | 
| Certificate.PublicKey.Exponent | Number | Exponent of the public key for RSA keys. | 
| Certificate.PublicKey.PublicKey | String | The public key for DSA/Unknown keys. | 
| Certificate.SPKISHA256 | String | SHA256 fingerprint of the certificate Subject Public Key Info. | 
| Certificate.Signature.Algorithm | String | Algorithm used in the signature of the certificate. | 
| Certificate.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| Certificate.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 


#### Command Example

```!expanse-get-certificate limit="1"```

#### Context Example

```json
{
    "Certificate": {
        "IssuerDN": "C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254",
        "MD5": "d4c65570578b04b69bde30beff3f6de5",
        "Name": [
            "10.254.254.254"
        ],
        "PublicKey": {
            "Algorithm": "RSA",
            "Exponent": 65537,
            "Length": 1024,
            "Modulus": "a0:1c:f5:ac:95:17:36:d6:f1:b4:12:a9:8d:c8:73:e2:23:73:20:7a:be:40:11:72:44:d5:85:12:d9:5e:27:9d:21:27:80:4f:5f:e4:68:63:5e:c6:e6:97:2b:68:28:f4:2d:ee:dc:9f:de:59:b4:f9:25:4e:f3:3e:ff:c2:2b:98:8a:a8:6c:0d:0a:f8:23:09:9b:d2:df:69:22:31:7e:16:7f:c7:e8:3b:bd:31:f2:20:61:ea:1d:93:89:3e:24:15:33:a7:7f:10:8b:50:3c:e1:01:a7:51:90:e3:c6:04:37:e5:4b:55:37:15:f8:e3:83:4c:be:bd:7b:81:fd:a1:91",
            "PublicKey": "30:81:9f:30:0d:06:09:2a:86:48:86:f7:0d:01:01:01:05:00:03:81:8d:00:30:81:89:02:81:81:00:a0:1c:f5:ac:95:17:36:d6:f1:b4:12:a9:8d:c8:73:e2:23:73:20:7a:be:40:11:72:44:d5:85:12:d9:5e:27:9d:21:27:80:4f:5f:e4:68:63:5e:c6:e6:97:2b:68:28:f4:2d:ee:dc:9f:de:59:b4:f9:25:4e:f3:3e:ff:c2:2b:98:8a:a8:6c:0d:0a:f8:23:09:9b:d2:df:69:22:31:7e:16:7f:c7:e8:3b:bd:31:f2:20:61:ea:1d:93:89:3e:24:15:33:a7:7f:10:8b:50:3c:e1:01:a7:51:90:e3:c6:04:37:e5:4b:55:37:15:f8:e3:83:4c:be:bd:7b:81:fd:a1:91:02:03:01:00:01"
        },
        "SHA1": "9867b47d69cd5632b39642ae83111ed4ccdea05a",
        "SHA256": "cbb0fe776ca808694dfd99cf59f4cf9278da4af4fab49b57b6aa83067223fd9b",
        "SPKISHA256": "631dc65da0ebd34092d588969da71ecaf4d8348b2660e18e4f71b82374b109ad",
        "SerialNumber": "12064359",
        "Signature": {
            "Algorithm": "SHA256withRSA"
        },
        "SubjectDN": "C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254",
        "ValidityNotAfter": "2112-06-12T00:39:31Z",
        "ValidityNotBefore": "2013-11-18T00:39:31Z"
    },
    "DBotScore": {
        "Indicator": "cbb0fe776ca808694dfd99cf59f4cf9278da4af4fab49b57b6aa83067223fd9b",
        "Score": 0,
        "Type": "certificate",
        "Vendor": "ExpanseV2"
    },
    "Expanse": {
        "Certificate": {
            "annotations": {
                "contacts": [],
                "note": "",
                "tags": []
            },
            "businessUnits": [
                {
                    "id": "c94c50ca-124f-4983-8da5-1756138e2252",
                    "name": "PANW Acme Latex Supply Dev",
                    "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
                }
            ],
            "certificate": {
                "formattedIssuerOrg": null,
                "id": "d4c65570-578b-34b6-9bde-30beff3f6de5",
                "issuer": "C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254",
                "issuerAlternativeNames": "",
                "issuerCountry": "CN",
                "issuerEmail": null,
                "issuerLocality": "GD",
                "issuerName": "10.254.254.254",
                "issuerOrg": "CHINA-ISI",
                "issuerOrgUnit": "CHINA-ISI",
                "issuerState": "GZ",
                "md5Hash": "1MZVcFeLBLab3jC-_z9t5Q==",
                "pemSha1": "mGe0fWnNVjKzlkKugxEe1MzeoFo=",
                "pemSha256": "y7D-d2yoCGlN_ZnPWfTPknjaSvT6tJtXtqqDBnIj_Zs=",
                "publicKey": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgHPWslRc21vG0EqmNyHPiI3Mger5AEXJE1YUS2V4nnSEngE9f5GhjXsbmlytoKPQt7tyf3lm0+SVO8z7/wiuYiqhsDQr4Iwmb0t9pIjF+Fn/H6Du9MfIgYeodk4k+JBUzp38Qi1A84QGnUZDjxgQ35UtVNxX444NMvr17gf2hkQIDAQAB",
                "publicKeyAlgorithm": "RSA",
                "publicKeyBits": 1024,
                "publicKeyModulus": "a01cf5ac951736d6f1b412a98dc873e22373207abe40117244d58512d95e279d2127804f5fe468635ec6e6972b6828f42deedc9fde59b4f9254ef33effc22b988aa86c0d0af823099bd2df6922317e167fc7e83bbd31f22061ea1d93893e241533a77f108b503ce101a75190e3c60437e54b553715f8e3834cbebd7b81fda191",
                "publicKeyRsaExponent": 65537,
                "publicKeySpki": "Yx3GXaDr00CS1YiWnaceyvTYNIsmYOGOT3G4I3SxCa0=",
                "serialNumber": "12064359",
                "signatureAlgorithm": "SHA256withRSA",
                "subject": "C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254",
                "subjectAlternativeNames": "",
                "subjectCountry": "CN",
                "subjectEmail": null,
                "subjectLocality": "GD",
                "subjectName": "10.254.254.254",
                "subjectOrg": "CHINA-ISI",
                "subjectOrgUnit": "CHINA-ISI",
                "subjectState": "GZ",
                "validNotAfter": "2112-06-12T00:39:31Z",
                "validNotBefore": "2013-11-18T00:39:31Z",
                "version": "3"
            },
            "certificateAdvertisementStatus": [
                "NO_CERTIFICATE_ADVERTISEMENT"
            ],
            "commonName": "10.254.254.254",
            "dateAdded": "2020-09-22T21:23:06.866Z",
            "details": null,
            "firstObserved": null,
            "hasLinkedCloudResources": false,
            "id": "30a111ae-39e2-3b82-b459-249bac0c6065",
            "lastObserved": null,
            "properties": [
                "LONG_EXPIRATION",
                "SELF_SIGNED",
                "SHORT_KEY"
            ],
            "providers": [
                {
                    "id": "Unknown",
                    "name": "None"
                }
            ],
            "serviceStatus": [
                "NO_ACTIVE_SERVICE",
                "NO_ACTIVE_ON_PREM_SERVICE",
                "NO_ACTIVE_CLOUD_SERVICE"
            ],
            "tenant": {
                "id": "f738ace6-f451-4f31-898d-a12afa204b2a",
                "name": "PANW VanDelay Dev",
                "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
            }
        }
    }
}
```

#### Human Readable Output

>### Expanse Certificate List
>
>|annotations|businessUnits|certificate|certificateAdvertisementStatus|commonName|dateAdded|details|firstObserved|hasLinkedCloudResources|id|lastObserved|properties|providers|serviceStatus|tenant|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| contacts: <br/>tags: <br/>note:  | {'id': 'c94c50ca-124f-4983-8da5-1756138e2252', 'name': 'PANW Acme Latex Supply Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'} | md5Hash: 1MZVcFeLBLab3jC-_z9t5Q==<br/>id: d4c65570-578b-34b6-9bde-30beff3f6de5<br/>issuer: C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254<br/>issuerAlternativeNames: <br/>issuerCountry: CN<br/>issuerEmail: null<br/>issuerLocality: GD<br/>issuerName: 10.254.254.254<br/>issuerOrg: CHINA-ISI<br/>formattedIssuerOrg: null<br/>issuerOrgUnit: CHINA-ISI<br/>issuerState: GZ<br/>publicKey: MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgHPWslRc21vG0EqmNyHPiI3Mger5AEXJE1YUS2V4nnSEngE9f5GhjXsbmlytoKPQt7tyf3lm0+SVO8z7/wiuYiqhsDQr4Iwmb0t9pIjF+Fn/H6Du9MfIgYeodk4k+JBUzp38Qi1A84QGnUZDjxgQ35UtVNxX444NMvr17gf2hkQIDAQAB<br/>publicKeyAlgorithm: RSA<br/>publicKeyRsaExponent: 65537<br/>signatureAlgorithm: SHA256withRSA<br/>subject: C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254<br/>subjectAlternativeNames: <br/>subjectCountry: CN<br/>subjectEmail: null<br/>subjectLocality: GD<br/>subjectName: 10.254.254.254<br/>subjectOrg: CHINA-ISI<br/>subjectOrgUnit: CHINA-ISI<br/>subjectState: GZ<br/>serialNumber: 12064359<br/>validNotBefore: 2013-11-18T00:39:31Z<br/>validNotAfter: 2112-06-12T00:39:31Z<br/>version: 3<br/>publicKeyBits: 1024<br/>pemSha256: y7D-d2yoCGlN_ZnPWfTPknjaSvT6tJtXtqqDBnIj_Zs=<br/>pemSha1: mGe0fWnNVjKzlkKugxEe1MzeoFo=<br/>publicKeyModulus: a01cf5ac951736d6f1b412a98dc873e22373207abe40117244d58512d95e279d2127804f5fe468635ec6e6972b6828f42deedc9fde59b4f9254ef33effc22b988aa86c0d0af823099bd2df6922317e167fc7e83bbd31f22061ea1d93893e241533a77f108b503ce101a75190e3c60437e54b553715f8e3834cbebd7b81fda191<br/>publicKeySpki: Yx3GXaDr00CS1YiWnaceyvTYNIsmYOGOT3G4I3SxCa0= | NO_CERTIFICATE_ADVERTISEMENT | 10.254.254.254 | 2020-09-22T21:23:06.866Z |  |  | false | 30a111ae-39e2-3b82-b459-249bac0c6065 |  | LONG_EXPIRATION,<br/>SELF_SIGNED,<br/>SHORT_KEY | {'id': 'Unknown', 'name': 'None'} | NO_ACTIVE_SERVICE,<br/>NO_ACTIVE_ON_PREM_SERVICE,<br/>NO_ACTIVE_CLOUD_SERVICE | id: f738ace6-f451-4f31-898d-a12afa204b2a<br/>name: PANW VanDelay Dev<br/>tenantId: f738ace6-f451-4f31-898d-a12afa204b2a |


### certificate

***
Provides data enrichment for an X509 Certificate from Xpanse.


#### Base Command

`certificate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificate | MD5, SHA-1, SHA-256 or SHA-512 hash of the certificate to enrich.<br/>If MD5 is given, the command will check directly with Xpanse API otherwise<br/>the script looks first for an indicator with the given hash to retrieve the<br/>corresponding MD5 hash.<br/>. | Optional | 
| set_expanse_fields | If set to true, the command updates the Xpanse custom fields of the indicator.<br/>Only if an indicator already exists.<br/>. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Certificate.annotations.note | String | Customer provided annotation details for a certificate | 
| Expanse.Certificate.annotations.contacts.id | String | ID for customer provided contact details for a certificate | 
| Expanse.Certificate.annotations.contacts.name | String | Customer provided contact details for a certificate | 
| Expanse.Certificate.annotations.tags.id | String | ID for customer added tag on a certificate in Expander | 
| Expanse.Certificate.annotations.tags.name | String | Customer added tag on a certificate in Expander | 
| Expanse.Certificate.businessUnits.id | String | Business Units that the certificate has been assigned to | 
| Expanse.Certificate.businessUnits.name | String | Business Units that the certificate has been assigned to | 
| Expanse.Certificate.businessUnits.tenantId | String | Tenant information for business units that the certificate has been assigned to | 
| Expanse.Certificate.certificate.formattedIssuerOrg | String | The formatted issuer org in the certificate | 
| Expanse.Certificate.certificate.id | String | The certificate ID | 
| Expanse.Certificate.certificate.issuer | String | The issuer in the certificate | 
| Expanse.Certificate.certificate.issuerAlternativeNames | String | The issuer alternative names in the certificate | 
| Expanse.Certificate.certificate.issuerCountry | String | The issuer country in the certificate | 
| Expanse.Certificate.certificate.issuerEmail | String | The issuer email in the certificate | 
| Expanse.Certificate.certificate.issuerLocality | String | The issuer locality in the certificate | 
| Expanse.Certificate.certificate.issuerName | String | The issuer name in the certificate | 
| Expanse.Certificate.certificate.issuerOrg | String | The issuer org in the certificate | 
| Expanse.Certificate.certificate.issuerOrgUnit | String | The issuer org unit in the certificate | 
| Expanse.Certificate.certificate.issuerState | String | The issuer state in the certificate | 
| Expanse.Certificate.certificate.md5Hash | String | The md5hash in the certificate | 
| Expanse.Certificate.certificate.pemSha1 | String | The pemSha1 in the certificate | 
| Expanse.Certificate.certificate.pemSha256 | String | The pemSha256 in the certificate | 
| Expanse.Certificate.certificate.publicKey | String | The public key in the certificate | 
| Expanse.Certificate.certificate.publicKeyAlgorithm | String | The public key algorithm in the certificate | 
| Expanse.Certificate.certificate.publicKeyBits | Number | The public key bits in the certificate | 
| Expanse.Certificate.certificate.publicKeyModulus | String | The public key modulus in the certificate | 
| Expanse.Certificate.certificate.publicKeyRsaExponent | Number | The public key RSA exponent in the certificate | 
| Expanse.Certificate.certificate.publicKeySpki | String | The public key Spki in the certificate | 
| Expanse.Certificate.certificate.serialNumber | String | The serial number in the certificate | 
| Expanse.Certificate.certificate.signatureAlgorithm | String | The signature algorithm in the certificate | 
| Expanse.Certificate.certificate.subject | String | The subject in the certificate | 
| Expanse.Certificate.certificate.subjectAlternativeNames | String | The subject alternative names in the certificate | 
| Expanse.Certificate.certificate.subjectCountry | String | The subject country in the certificate | 
| Expanse.Certificate.certificate.subjectEmail | String | The subject email in the certificate | 
| Expanse.Certificate.certificate.subjectLocality | String | The subject locality in the certificate | 
| Expanse.Certificate.certificate.subjectName | String | The subject name in the certificate | 
| Expanse.Certificate.certificate.subjectOrg | String | The subject org in the certificate | 
| Expanse.Certificate.certificate.subjectOrgUnit | String | The subject org unit in the certificate | 
| Expanse.Certificate.certificate.subjectState | String | The subject state in the certificate | 
| Expanse.Certificate.certificate.validNotAfter | Date | The valid not after date in the certificate | 
| Expanse.Certificate.certificate.validNotBefore | Date | The valid not before date in the certificate | 
| Expanse.Certificate.certificate.version | String | The version in the certificate | 
| Expanse.Certificate.certificateAdvertisementStatus | String | Certificate advertisement statuses | 
| Expanse.Certificate.commonName | String | Common Name for the certificate | 
| Expanse.Certificate.dateAdded | Date | The date that the certificate was added to the Expander instance | 
| Expanse.Certificate.details.base64Encoded | String | Additional details for the certificate | 
| Expanse.Certificate.details.recentIps.assetKey | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.assetType | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.businessUnits.id | String | Business Units that the recent IPs linked to the certificate has been assigned to | 
| Expanse.Certificate.details.recentIps.businessUnits.name | String | Business Units that the recent IPs linked to the certificate has been assigned to | 
| Expanse.Certificate.details.recentIps.businessUnits.tenantId | String | Tenant information for business Units that the recent IPs linked to the certificate has been assigned to | 
| Expanse.Certificate.details.recentIps.commonName | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.domain | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.ip | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.lastObserved | Date | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.provider.id | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.provider.name | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.tenant.id | String | Tenant information for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.tenant.name | String | Tenant information for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.tenant.tenantId | String | Tenant information for the recent IPs linked to the certificate | 
| Expanse.Certificate.details.recentIps.type | String | Additional details for the recent IPs linked to the certificate | 
| Expanse.Certificate.firstObserved | Date | The date that the certificate was first observed | 
| Expanse.Certificate.hasLinkedCloudResources | Boolean | Whether the certificate has any linked cloud resources associated with it | 
| Expanse.Certificate.id | String | Internal Xpanse ID for Certificate | 
| Expanse.Certificate.lastObserved | Date | The date that the certificate was most recently observed | 
| Expanse.Certificate.properties | String | Xpanse tagged properties of the certificate | 
| Expanse.Certificate.providers.id | String | The Provider information for the certificate | 
| Expanse.Certificate.providers.name | String | The Provider information for the certificate | 
| Expanse.Certificate.serviceStatus | String | Detected service statuses for the certificate | 
| Expanse.Certificate.tenant.id | String | Tenant information for the certificate | 
| Expanse.Certificate.tenant.name | String | Tenant information for the certificate | 
| Expanse.Certificate.tenant.tenantId | String | Tenant information for the certificate | 
| Expanse.Certificate.details.cloudResources.id | String | The cloud resource ID | 
| Expanse.Certificate.details.cloudResources.tenant.id | String | Tenant information for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.tenant.name | String | Tenant information for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.tenant.tenantId | String | Tenant information for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.businessUnits.id | String | Business Units that the cloud resource has been assigned to | 
| Expanse.Certificate.details.cloudResources.businessUnits.name | String | Business Units that the cloud resource has been assigned to | 
| Expanse.Certificate.details.cloudResources.businessUnits.tenantId | String | Tenant information businessUnits that the cloud resource as been assigned to | 
| Expanse.Certificate.details.cloudResources.dateAdded | Date | The date that the cloud resource was added to the Expander instance | 
| Expanse.Certificate.details.cloudResources.firstObserved | Date | The date that the cloud resource was first observed | 
| Expanse.Certificate.details.cloudResources.lastObserved | Date | The date that the certificate was most recently observed | 
| Expanse.Certificate.details.cloudResources.instanceId | String | Instance ID for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.type | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.name | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.ips | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.domain | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.provider.id | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.provider.name | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.region | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.vpc.id | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.vpc.name | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.accountIntegration.id | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.accountIntegration.name | String | Additional details for the cloud resource linked to the certificate | 
| Expanse.Certificate.details.cloudResources.recentIps.assetKey | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.assetType | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.businessUnits.id | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Certificate.details.cloudResources.recentIps.businessUnits.name | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Certificate.details.cloudResources.recentIps.businessUnits.tenantId | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Certificate.details.cloudResources.recentIps.commonName | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.domain | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.ip | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.lastObserved | Date | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.provider.id | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.provider.name | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.tenant.id | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.tenant.name | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.tenant.tenantId | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.recentIps.type | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Certificate.details.cloudResources.annotations.note | String | Customer provided annotation details for a certificate | 
| Expanse.Certificate.details.cloudResources.annotations.contacts.id | String | ID for customer provided contact details for a certificate | 
| Expanse.Certificate.details.cloudResources.annotations.contacts.name | String | Customer provided contact details for a certificate | 
| Expanse.Certificate.details.cloudResources.annotations.tags.id | String | ID for customer added tag on a certificate in Expander | 
| Expanse.Certificate.details.cloudResources.annotations.tags.name | String | Customer added tag on a certificate in Expander | 
| Certificate.Name | String | Name \(CN or SAN\) appearing in the certificate. | 
| Certificate.SubjectDN | String | The Subject Distinguished Name of the certificate.
This field includes the Common Name of the certificate.
 | 
| Certificate.PEM | String | Certificate in PEM format. | 
| Certificate.IssuerDN | String | The Issuer Distinguished Name of the certificate. | 
| Certificate.SerialNumber | String | The Serial Number of the certificate. | 
| Certificate.ValidityNotAfter | Date | End of certificate validity period. | 
| Certificate.ValidityNotBefore | Date | Start of certificate validity period. | 
| Certificate.SubjectAlternativeName.Value | String | Name of the SAN. | 
| Certificate.SHA256 | String | SHA256 Fingerprint of the certificate in DER format. | 
| Certificate.SHA1 | String | SHA1 Fingerprint of the certificate in DER format. | 
| Certificate.MD5 | String | MD5 Fingerprint of the certificate in DER format. | 
| Certificate.PublicKey.Algorithm | String | Algorithm used for public key of the certificate. | 
| Certificate.PublicKey.Length | Number | Length in bits of the public key of the certificate. | 
| Certificate.PublicKey.Modulus | String | Modulus of the public key for RSA keys. | 
| Certificate.PublicKey.Exponent | Number | Exponent of the public key for RSA keys. | 
| Certificate.PublicKey.PublicKey | String | The public key for DSA/Unknown keys. | 
| Certificate.SPKISHA256 | String | SHA256 fingerprint of the certificate Subject Public Key Info. | 
| Certificate.Signature.Algorithm | String | Algorithm used in the signature of the certificate. | 
| Certificate.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| Certificate.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 


#### Command Example

```!certificate certificate="d4c65570578b04b69bde30beff3f6de5" set_expanse_fields="false"```

#### Context Example

```json
{
    "Certificate": {
        "IssuerDN": "C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254",
        "MD5": "d4c65570578b04b69bde30beff3f6de5",
        "Name": [
            "10.254.254.254"
        ],
        "PublicKey": {
            "Algorithm": "RSA",
            "Exponent": 65537,
            "Length": 1024,
            "Modulus": "a0:1c:f5:ac:95:17:36:d6:f1:b4:12:a9:8d:c8:73:e2:23:73:20:7a:be:40:11:72:44:d5:85:12:d9:5e:27:9d:21:27:80:4f:5f:e4:68:63:5e:c6:e6:97:2b:68:28:f4:2d:ee:dc:9f:de:59:b4:f9:25:4e:f3:3e:ff:c2:2b:98:8a:a8:6c:0d:0a:f8:23:09:9b:d2:df:69:22:31:7e:16:7f:c7:e8:3b:bd:31:f2:20:61:ea:1d:93:89:3e:24:15:33:a7:7f:10:8b:50:3c:e1:01:a7:51:90:e3:c6:04:37:e5:4b:55:37:15:f8:e3:83:4c:be:bd:7b:81:fd:a1:91",
            "PublicKey": "30:81:9f:30:0d:06:09:2a:86:48:86:f7:0d:01:01:01:05:00:03:81:8d:00:30:81:89:02:81:81:00:a0:1c:f5:ac:95:17:36:d6:f1:b4:12:a9:8d:c8:73:e2:23:73:20:7a:be:40:11:72:44:d5:85:12:d9:5e:27:9d:21:27:80:4f:5f:e4:68:63:5e:c6:e6:97:2b:68:28:f4:2d:ee:dc:9f:de:59:b4:f9:25:4e:f3:3e:ff:c2:2b:98:8a:a8:6c:0d:0a:f8:23:09:9b:d2:df:69:22:31:7e:16:7f:c7:e8:3b:bd:31:f2:20:61:ea:1d:93:89:3e:24:15:33:a7:7f:10:8b:50:3c:e1:01:a7:51:90:e3:c6:04:37:e5:4b:55:37:15:f8:e3:83:4c:be:bd:7b:81:fd:a1:91:02:03:01:00:01"
        },
        "SHA1": "9867b47d69cd5632b39642ae83111ed4ccdea05a",
        "SHA256": "cbb0fe776ca808694dfd99cf59f4cf9278da4af4fab49b57b6aa83067223fd9b",
        "SPKISHA256": "631dc65da0ebd34092d588969da71ecaf4d8348b2660e18e4f71b82374b109ad",
        "SerialNumber": "12064359",
        "Signature": {
            "Algorithm": "SHA256withRSA"
        },
        "SubjectDN": "C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254",
        "ValidityNotAfter": "2112-06-12T00:39:31Z",
        "ValidityNotBefore": "2013-11-18T00:39:31Z"
    },
    "DBotScore": {
        "Indicator": "cbb0fe776ca808694dfd99cf59f4cf9278da4af4fab49b57b6aa83067223fd9b",
        "Score": 0,
        "Type": "certificate",
        "Vendor": "ExpanseV2"
    },
    "Expanse": {
        "Certificate": {
            "annotations": {
                "contacts": [],
                "note": "",
                "tags": [
                    {
                        "id": "e00bc79d-d367-36f4-824c-042836fef5fc",
                        "name": "xsoar-test-pb-tag"
                    }
                ]
            },
            "businessUnits": [
                {
                    "id": "c94c50ca-124f-4983-8da5-1756138e2252",
                    "name": "PANW Acme Latex Supply Dev",
                    "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
                }
            ],
            "certificate": {
                "formattedIssuerOrg": null,
                "id": "d4c65570-578b-34b6-9bde-30beff3f6de5",
                "issuer": "C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254",
                "issuerAlternativeNames": "",
                "issuerCountry": "CN",
                "issuerEmail": null,
                "issuerLocality": "GD",
                "issuerName": "10.254.254.254",
                "issuerOrg": "CHINA-ISI",
                "issuerOrgUnit": "CHINA-ISI",
                "issuerState": "GZ",
                "md5Hash": "1MZVcFeLBLab3jC-_z9t5Q==",
                "pemSha1": "mGe0fWnNVjKzlkKugxEe1MzeoFo=",
                "pemSha256": "y7D-d2yoCGlN_ZnPWfTPknjaSvT6tJtXtqqDBnIj_Zs=",
                "publicKey": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgHPWslRc21vG0EqmNyHPiI3Mger5AEXJE1YUS2V4nnSEngE9f5GhjXsbmlytoKPQt7tyf3lm0+SVO8z7/wiuYiqhsDQr4Iwmb0t9pIjF+Fn/H6Du9MfIgYeodk4k+JBUzp38Qi1A84QGnUZDjxgQ35UtVNxX444NMvr17gf2hkQIDAQAB",
                "publicKeyAlgorithm": "RSA",
                "publicKeyBits": 1024,
                "publicKeyModulus": "a01cf5ac951736d6f1b412a98dc873e22373207abe40117244d58512d95e279d2127804f5fe468635ec6e6972b6828f42deedc9fde59b4f9254ef33effc22b988aa86c0d0af823099bd2df6922317e167fc7e83bbd31f22061ea1d93893e241533a77f108b503ce101a75190e3c60437e54b553715f8e3834cbebd7b81fda191",
                "publicKeyRsaExponent": 65537,
                "publicKeySpki": "Yx3GXaDr00CS1YiWnaceyvTYNIsmYOGOT3G4I3SxCa0=",
                "serialNumber": "12064359",
                "signatureAlgorithm": "SHA256withRSA",
                "subject": "C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254",
                "subjectAlternativeNames": "",
                "subjectCountry": "CN",
                "subjectEmail": null,
                "subjectLocality": "GD",
                "subjectName": "10.254.254.254",
                "subjectOrg": "CHINA-ISI",
                "subjectOrgUnit": "CHINA-ISI",
                "subjectState": "GZ",
                "validNotAfter": "2112-06-12T00:39:31Z",
                "validNotBefore": "2013-11-18T00:39:31Z",
                "version": "3"
            },
            "certificateAdvertisementStatus": [
                "NO_CERTIFICATE_ADVERTISEMENT"
            ],
            "commonName": "10.254.254.254",
            "dateAdded": "2020-09-22T21:23:06.866Z",
            "details": {
                "base64Encoded": "",
                "cloudResources": [],
                "recentIps": []
            },
            "firstObserved": null,
            "hasLinkedCloudResources": false,
            "id": "30a111ae-39e2-3b82-b459-249bac0c6065",
            "lastObserved": null,
            "properties": [
                "LONG_EXPIRATION",
                "SELF_SIGNED",
                "SHORT_KEY"
            ],
            "providers": [
                {
                    "id": "Unknown",
                    "name": "None"
                }
            ],
            "serviceStatus": [
                "NO_ACTIVE_SERVICE",
                "NO_ACTIVE_ON_PREM_SERVICE",
                "NO_ACTIVE_CLOUD_SERVICE"
            ],
            "tenant": {
                "id": "f738ace6-f451-4f31-898d-a12afa204b2a",
                "name": "PANW VanDelay Dev",
                "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
            }
        }
    }
}
```

#### Human Readable Output

>### Expanse Certificate List
>
>|annotations|businessUnits|certificate|certificateAdvertisementStatus|commonName|dateAdded|details|firstObserved|hasLinkedCloudResources|id|lastObserved|properties|providers|serviceStatus|tenant|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| contacts: <br/>tags: {'id': 'e00bc79d-d367-36f4-824c-042836fef5fc', 'name': 'xsoar-test-pb-tag'}<br/>note:  | {'id': 'c94c50ca-124f-4983-8da5-1756138e2252', 'name': 'PANW Acme Latex Supply Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'} | md5Hash: 1MZVcFeLBLab3jC-_z9t5Q==<br/>id: d4c65570-578b-34b6-9bde-30beff3f6de5<br/>issuer: C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254<br/>issuerAlternativeNames: <br/>issuerCountry: CN<br/>issuerEmail: null<br/>issuerLocality: GD<br/>issuerName: 10.254.254.254<br/>issuerOrg: CHINA-ISI<br/>formattedIssuerOrg: null<br/>issuerOrgUnit: CHINA-ISI<br/>issuerState: GZ<br/>publicKey: MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgHPWslRc21vG0EqmNyHPiI3Mger5AEXJE1YUS2V4nnSEngE9f5GhjXsbmlytoKPQt7tyf3lm0+SVO8z7/wiuYiqhsDQr4Iwmb0t9pIjF+Fn/H6Du9MfIgYeodk4k+JBUzp38Qi1A84QGnUZDjxgQ35UtVNxX444NMvr17gf2hkQIDAQAB<br/>publicKeyAlgorithm: RSA<br/>publicKeyRsaExponent: 65537<br/>signatureAlgorithm: SHA256withRSA<br/>subject: C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254<br/>subjectAlternativeNames: <br/>subjectCountry: CN<br/>subjectEmail: null<br/>subjectLocality: GD<br/>subjectName: 10.254.254.254<br/>subjectOrg: CHINA-ISI<br/>subjectOrgUnit: CHINA-ISI<br/>subjectState: GZ<br/>serialNumber: 12064359<br/>validNotBefore: 2013-11-18T00:39:31Z<br/>validNotAfter: 2112-06-12T00:39:31Z<br/>version: 3<br/>publicKeyBits: 1024<br/>pemSha256: y7D-d2yoCGlN_ZnPWfTPknjaSvT6tJtXtqqDBnIj_Zs=<br/>pemSha1: mGe0fWnNVjKzlkKugxEe1MzeoFo=<br/>publicKeyModulus: a01cf5ac951736d6f1b412a98dc873e22373207abe40117244d58512d95e279d2127804f5fe468635ec6e6972b6828f42deedc9fde59b4f9254ef33effc22b988aa86c0d0af823099bd2df6922317e167fc7e83bbd31f22061ea1d93893e241533a77f108b503ce101a75190e3c60437e54b553715f8e3834cbebd7b81fda191<br/>publicKeySpki: Yx3GXaDr00CS1YiWnaceyvTYNIsmYOGOT3G4I3SxCa0= | NO_CERTIFICATE_ADVERTISEMENT | 10.254.254.254 | 2020-09-22T21:23:06.866Z | recentIps: <br/>cloudResources: <br/>base64Encoded:  |  | false | 30a111ae-39e2-3b82-b459-249bac0c6065 |  | LONG_EXPIRATION,<br/>SELF_SIGNED,<br/>SHORT_KEY | {'id': 'Unknown', 'name': 'None'} | NO_ACTIVE_SERVICE,<br/>NO_ACTIVE_ON_PREM_SERVICE,<br/>NO_ACTIVE_CLOUD_SERVICE | id: f738ace6-f451-4f31-898d-a12afa204b2a<br/>name: PANW VanDelay Dev<br/>tenantId: f738ace6-f451-4f31-898d-a12afa204b2a |

### expanse-get-cloud-resources

***
Retrieve Cloud Resource assets from Xpanse.


#### Base Command

`expanse-get-cloud-resources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of cloud resources to retrieve. | Optional | 
| last_observed_date | Last date the cloud resource was observed by Xpanse. (Format is YYYY-MM-DD). | Optional | 
| domain | A domain search string to find related cloud resources. | Optional | 
| ip | An IP search string to find related cloud resources. | Optional | 
| providers | A search string of provider IDs to find cloud resources hosted by specific providers. | Optional | 
| provider_names | A search string of provider names to find cloud resources hosted by specific providers. | Optional | 
| business_units | A search string of business unit ids to find cloud resources belonging to a specific business unit. | Optional | 
| business_unit_names | A search string of business unit names to find cloud resources belonging to a specific business unit. | Optional | 
| tags | A search string of tag IDs to find cloud resources that have been assigned a specific tag. | Optional | 
| tag_names | A search string of tag names to find cloud resources that have been assigned a specific tag. | Optional | 
| types | A search string of asset types to find cloud resources of a specific type. | Optional | 
| regions | A search string of regions to find cloud resources that are hosted in a specific region. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.CloudResource.accountIntegration.id | String | The ID of the cloud resource account integration. |
| Expanse.CloudResource.accountIntegration.name | String | The name of the cloud resource account integration. |
| Expanse.CloudResource.annotations.note | String | Note metadata on the cloud resource. |
| Expanse.CloudResource.businessUnits.id | String | The internal ID of the business unit that the cloud resource belongs to. |
| Expanse.CloudResource.businessUnits.name | String | The name of the business unit that the cloud resource belongs to. |
| Expanse.CloudResource.businessUnits.tenantId | String | The internal tenant ID of the business unit that the cloud resource belongs to. |
| Expanse.CloudResource.dateAdded | Date | The date that the cloud resource was added. |
| Expanse.CloudResource.details | String | Details about the cloud resource. |
| Expanse.CloudResource.domain | String | Domain name associated with the cloud resource. |
| Expanse.CloudResource.firstObserved | Date | The date that the cloud resource was first observed. |
| Expanse.CloudResource.id | String | The internal ID for the cloud resource. |
| Expanse.CloudResource.instanceId | String | The instance ID of the cloud resource. |
| Expanse.CloudResource.ips | String | IPs associated with the cloud resource. |
| Expanse.CloudResource.lastObserved | Date | The date that the cloud resource was most recently observed. |
| Expanse.CloudResource.name | String | The friendly name of the cloud resource. |
| Expanse.CloudResource.provider.id | String | The ID of the provider where the cloud resource is hosted. |
| Expanse.CloudResource.provider.name | String | The name of the provider where the cloud resource is hosted. |
| Expanse.CloudResource.region | String | The region where the cloud resouce is hosted. |
| Expanse.CloudResource.serviceStatus | String | Whether the cloud resource has any known associated services. |
| Expanse.CloudResource.sourceDetails | String | The integration source of the cloud resource. |
| Expanse.CloudResource.tenant.id | String | The internal tenant ID of the cloud resource. |
| Expanse.CloudResource.tenant.name | String | The tenant name of the cloud resouce |
| Expanse.CloudResource.tenant.tenantId | String | The internal tenant ID of the cloud resource. |
| Expanse.CloudResource.type | String | The type of cloud resource. |
| Expanse.CloudResource.vpc.id | String | Any associated VPC IDs. |
| Expanse.CloudResource.vpc.name | String | Any associated VPC names. |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 

#### Command Example

```!expanse-get-cloud-resources limit=1```

#### Context Example

```json
{
    "DBotScore": {
        "Vendor": "ExpanseV2", 
        "Indicator": "1.179.133.116", 
        "Score": 0, 
        "Type": "ip"
    }, 
    "Expanse": {
        "CloudResource": {
            "domain": null, 
            "dateAdded": "2021-05-17T04:02:24.351Z", 
            "name": "gke-prisma-cloud-demo-2-default-pool-e7eb62e3-vkc5", 
            "instanceId": "2656988220364570480", 
            "sourceDetails": [
                "Prisma Cloud: Prisma Demo"
            ], 
            "region": "us-central1", 
            "firstObserved": "2021-05-16T08:28:27.035Z", 
            "provider": {
                "id": "Google", 
                "name": "Google"
            }, 
            "id": "0194af18-4d32-36d9-8dba-527509ae8e1c", 
            "ips": [
                "1.179.133.116"
            ], 
            "businessUnits": [
                {
                    "tenantId": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5", 
                    "id": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5", 
                    "name": "VanDelay Industries"
                }
            ], 
            "lastObserved": "2021-05-17T08:28:26.711Z", 
            "details": null, 
            "vpc": {
                "id": "https://www.googleapis.com/compute/v1/projects/demo/global/networks/default", 
                "name": "default"
            }, 
            "accountIntegration": {
                "id": "e2154dbf-1e7e-4e25-9b88-0c43c98c9551", 
                "name": "Prisma Demo"
            }, 
            "serviceStatus": [
                "NO_ACTIVE_SERVICE"
            ], 
            "type": "GCE", 
            "annotations": {
                "note": "", 
                "tags": [], 
                "contacts": []
            }, 
            "tenant": {
                "tenantId": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5", 
                "id": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5", 
                "name": "VanDelay Industries"
            }
        }
    }
}
```

#### Human Readable Output

>### Expanse Cloud Resource List
>
>|Asset Type|Cloud Provider|Domain|ID|IP|Instance ID|Region|Source|
>|---|---|---|---|---|---|---|---|
>| NETWORK_LB | Google |  | 0220f936-3fd3-33e4-9e00-fd6a54e9bb7a | 1.179.133.116 | 2656988220364570480 | us-central1 | Prisma Cloud: Prisma Demo |

### expanse-get-cloud-resource

***
Retrieve a specified cloud resource from Xpanse.


#### Base Command

`expanse-get-cloud-resource`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the cloud resource. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| Expanse.CloudResource.accountIntegration.id | String | The ID of the cloud resource account integration. | 
| Expanse.CloudResource.accountIntegration.name | String | The name of the cloud resource account integration. | 
| Expanse.CloudResource.annotations.note | String | Note metadata on the cloud resource. | 
| Expanse.CloudResource.businessUnits.id | String | The internal ID of the business unit that the cloud resource belongs to. | 
| Expanse.CloudResource.businessUnits.name | String | The name of the business unit that the cloud resource belongs to. | 
| Expanse.CloudResource.businessUnits.tenantId | String | The internal tenant ID of the business unit that the cloud resource belongs to. | 
| Expanse.CloudResource.dateAdded | Date | The date that the cloud resource was added. | 
| Expanse.CloudResource.details | String | Details about the cloud resource. | 
| Expanse.CloudResource.domain | String | Domain name associated with the cloud resource. | 
| Expanse.CloudResource.firstObserved | Date | The date that the cloud resource was first observed. | 
| Expanse.CloudResource.id | String | The internal ID for the cloud resource. | 
| Expanse.CloudResource.instanceId | String | The instance ID of the cloud resource. | 
| Expanse.CloudResource.ips | String | IPs associated with the cloud resource. | 
| Expanse.CloudResource.lastObserved | Date | The date that the cloud resource was most recently observed. | 
| Expanse.CloudResource.name | String | The friendly name of the cloud resource. | 
| Expanse.CloudResource.provider.id | String | The ID of the provider where the cloud resource is hosted. | 
| Expanse.CloudResource.provider.name | String | The name of the provider where the cloud resource is hosted. | 
| Expanse.CloudResource.region | String | The region where the cloud resouce is hosted. | 
| Expanse.CloudResource.serviceStatus | String | Whether the cloud resource has any known associated services. | 
| Expanse.CloudResource.sourceDetails | String | The integration source of the cloud resource. | 
| Expanse.CloudResource.tenant.id | String | The internal tenant ID of the cloud resource. | 
| Expanse.CloudResource.tenant.name | String | The tenant name of the cloud resouce | 
| Expanse.CloudResource.tenant.tenantId | String | The internal tenant ID of the cloud resource. | 
| Expanse.CloudResource.type | String | The type of cloud resource. | 
| Expanse.CloudResource.vpc.id | String | Any associated VPC ID. | 
| Expanse.CloudResource.vpc.name | String | Any associated VPC names. | 


#### Command Example

``` 
{
    "DBotScore": {
        "Vendor": "ExpanseV2", 
        "Indicator": "1.179.133.116", 
        "Score": 0, 
        "Type": "ip"
    }, 
    "Expanse": {
        "CloudResource": {
            "domain": null, 
            "dateAdded": "2021-05-17T04:02:24.351Z", 
            "name": "gke-prisma-cloud-demo-2-default-pool-e7eb62e3-vkc5", 
            "instanceId": "2656988220364570480", 
            "sourceDetails": [
                "Prisma Cloud: Prisma Demo"
            ], 
            "region": "us-central1", 
            "firstObserved": "2021-05-16T08:28:27.035Z", 
            "provider": {
                "id": "Google", 
                "name": "Google"
            }, 
            "id": "0194af18-4d32-36d9-8dba-527509ae8e1c", 
            "ips": [
                "1.179.133.116"
            ], 
            "businessUnits": [
                {
                    "tenantId": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5", 
                    "id": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5", 
                    "name": "VanDelay Industries"
                }
            ], 
            "lastObserved": "2021-05-17T08:28:26.711Z", 
            "details": null, 
            "vpc": {
                "id": "https://www.googleapis.com/compute/v1/projects/demo/global/networks/default", 
                "name": "default"
            }, 
            "accountIntegration": {
                "id": "e2154dbf-1e7e-4e25-9b88-0c43c98c9551", 
                "name": "Prisma Demo"
            }, 
            "serviceStatus": [
                "NO_ACTIVE_SERVICE"
            ], 
            "type": "GCE", 
            "annotations": {
                "note": "", 
                "tags": [], 
                "contacts": []
            }, 
            "tenant": {
                "tenantId": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5", 
                "id": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5", 
                "name": "VanDelay Industries"
            }
        }
    }
}
```

#### Human Readable Output
>
>|Asset Type|Cloud Provider|Domain|ID|IP|Instance ID|Region|Source|
>|---|---|---|---|---|---|---|---|
>| NETWORK_LB | Google |  | 0220f936-3fd3-33e4-9e00-fd6a54e9bb7a | 1.179.133.116 | 2656988220364570480 | us-central1 | Prisma Cloud: Prisma Demo |

### expanse-get-risky-flows

***
(Deprecated) Retrieve risky flows detected by Xpanse Behavior.


#### Base Command

`expanse-get-risky-flows`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of flows to retrieve. | Optional | 
| risk_rule | Retrieve only flows matching this risk rule ID. | Optional | 
| internal_ip_range | Filter by internal IP range. Supported formats a.b.c.d, a.b.c.d/e, a.b.c.d-a.b.c.d, a., a.*. | Optional | 
| tag_names | Filter by tag names (comma separated string). | Optional | 
| created_before | Created Before date (supports ISO8601 format). | Optional | 
| created_after | Created After date (supports ISO8601 format). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.RiskyFlow.acked | Boolean | Whether the risky flow was acked | 
| Expanse.RiskyFlow.businessUnit.id | String | The business unit id of the asset involved in the risky flow | 
| Expanse.RiskyFlow.businessUnit.name | String | The business unit name of the asset involved in the risky flow | 
| Expanse.RiskyFlow.created | Date | The timestamp when the risky flow was found and created by Xpanse | 
| Expanse.RiskyFlow.externalAddress | String | The external IPv4 address involved in the risky flow | 
| Expanse.RiskyFlow.externalCountryCode | String | The external country code of the IPv4 involved in the risky flow | 
| Expanse.RiskyFlow.externalCountryCodes | String | The external country codes of the IPv4 involved in the risky flow | 
| Expanse.RiskyFlow.externalPort | Number | The external port of the communication involved in the risky flow | 
| Expanse.RiskyFlow.flowDirection | String | The direction of the risky flow | 
| Expanse.RiskyFlow.id | String | The internal ID of the risky flow | 
| Expanse.RiskyFlow.internalAddress | String | The internal IPv4 address involved in the risky flow | 
| Expanse.RiskyFlow.internalCountryCode | String | The internal country code of the IPv4 involved in the risky flow'' | 
| Expanse.RiskyFlow.internalCountryCodes | String | The internal country codes of the IPv4 involved in the risky flow | 
| Expanse.RiskyFlow.internalPort | Number | The internal port of the communication involved in the risky flow | 
| Expanse.RiskyFlow.internalTags.ipRange | String | Any tags associated with with the internal asset involved in the risky flow | 
| Expanse.RiskyFlow.observationTimestamp | Date | The timestamp when the risky flow took place | 
| Expanse.RiskyFlow.protocol | String | The protocol of the risky flow | 
| Expanse.RiskyFlow.riskRule.additionalDataFields | String | Additional data fields associated with the risk rule for the risky flow | 
| Expanse.RiskyFlow.riskRule.description | String | The risk rule description for the risky flow | 
| Expanse.RiskyFlow.riskRule.id | String | The risk rule ID for the risky flow | 
| Expanse.RiskyFlow.riskRule.name | String | The risk rule name for the risky flow | 
| Expanse.RiskyFlow.tenantBusinessUnitId | String | The tenant ID that the risky flow affects | 
| Expanse.RiskyFlow.internalDomains | String | The internal domains associated with the risky flow | 
| Expanse.RiskyFlow.internalExposureTypes | String | The known exposure types associated with the asset involved in the risky flow | 


#### Command Example

```!expanse-get-risky-flows limit=1```

#### Context Example

```json
{
    "Expanse": {
        "RiskyFlow": {
            "acked": true,
            "businessUnit": {
                "id": "a823144b-ef1a-4c34-8c02-d080cb4fc4e8",
                "name": "Company Test"
            },
            "created": "2020-12-18T03:50:10.490005Z",
            "externalAddress": "8.8.8.8",
            "externalCountryCode": "DE",
            "externalCountryCodes": [
                "DE"
            ],
            "externalPort": 443,
            "flowDirection": "OUTBOUND",
            "id": "898b267f-e0cf-35d4-bfe3-4089fbe10c55",
            "internalAddress": "1.1.1.1",
            "internalCountryCode": "DE",
            "internalCountryCodes": [
                "DE"
            ],
            "internalDomains": [],
            "internalExposureTypes": [],
            "internalPort": 42630,
            "internalTags": {
                "ipRange": []
            },
            "observationTimestamp": "2020-12-17T20:13:28.192Z",
            "protocol": "TCP",
            "riskRule": {
                "additionalDataFields": "[]",
                "description": "Connections to Tor",
                "id": "392d03de-ea20-4637-bf17-d419aaaeec19",
                "name": "Connections to Tor"
            },
            "tenantBusinessUnitId": "a823144b-ef1a-4c34-8c02-d080cb4fc4e8"
        }
    }
}
```

#### Human Readable Output

>### Results
>
>|acked|businessUnit|created|externalAddress|externalCountryCode|externalCountryCodes|externalPort|flowDirection|id|internalAddress|internalCountryCode|internalCountryCodes|internalDomains|internalExposureTypes|internalPort|internalTags|observationTimestamp|protocol|riskRule|tenantBusinessUnitId|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| true | id: a823144b-ef1a-4c34-8c02-d080cb4fc4e8<br/>name: Company Test | 2020-12-18T03:50:10.490005Z | 1.1.1.1 | DE | DE | 443 | OUTBOUND | 898b267f-e0cf-35d4-bfe3-4089fbe10c55 | 1.1.1.1 | DE | DE |  |  | 42630 | ipRange:  | 2020-12-17T20:13:28.192Z | TCP | id: 392d03de-ea20-4637-bf17-d419aaaeec19<br/>name: Connections to Tor<br/>description: Connections to Tor<br/>additionalDataFields: [] | a823144b-ef1a-4c34-8c02-d080cb4fc4e8 |


### expanse-list-risk-rules

***
(Deprecated) List risk rules from Xpanse Behavior


#### Base Command

`expanse-list-risk-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of entries to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.RiskRule.abbreviatedName | String | The abbreviated name of the risk rule | 
| Expanse.RiskRule.businessUnits.id | String | The business unit ID that the risk rule applies to | 
| Expanse.RiskRule.dataFields | String | The data fields of the risk rule | 
| Expanse.RiskRule.description | String | The description of the risk rule | 
| Expanse.RiskRule.direction | String | The directionality of the risk rule | 
| Expanse.RiskRule.id | String | The risk rule ID | 
| Expanse.RiskRule.name | String | The risk rule name | 


#### Command Example

```!expanse-list-risk-rules limit=3```

#### Context Example

```json
{
  "Expanse.RiskRule(val.id == obj.id)": [
    {
      "abbreviatedName": "Connections to Kaspersky",
      "businessUnits": [
        {
          "id": "a823144b-ef1a-4c34-8c02-d080cb4fc4e8"
        }
      ],
      "dataFields": "[]",
      "description": "Connections to Kaspersky",
      "direction": "OUTBOUND",
      "id": "81b9f50f-2eab-4101-b8c8-c902842887c5",
      "name": "Connections to Kaspersky"
    },
    {
      "abbreviatedName": "Outbound Flows from Serve",
      "businessUnits": [
        {
          "id": "a823144b-ef1a-4c34-8c02-d080cb4fc4e8"
        }
      ],
      "dataFields": "[]",
      "description": "Outbound Flows from Servers (eg, File Downloads and Web Browsing)",
      "direction": "OUTBOUND",
      "id": "feae9144-bbfe-4681-8a1e-c426d1de0e54",
      "name": "Outbound Flows from Servers"
    },
    {
      "abbreviatedName": "Connections to and from B",
      "businessUnits": [
        {
          "id": "a823144b-ef1a-4c34-8c02-d080cb4fc4e8"
        }
      ],
      "dataFields": "[]",
      "description": "Connections to and from countries on block list (Belarus, Côte d'Ivoire, Cuba, Democratic Republic of the Congo, Iran, Iraq, Liberia, North Korea, South Sudan, Sudan, Syria, Zimbabwe)",
      "direction": "EITHER",
      "id": "392d03de-ea20-4637-bf17-d419aaaeec19",
      "name": "Connections to and from countries on block list"
    }
  ]
}
```

#### Human Readable Output

>### Results
>
>|abbreviatedName|businessUnits|dataFields|description|direction|id|name|
>|---|---|---|---|---|---|---|
>| Connections to Kaspersky | {'id': 'a823144b-ef1a-4c34-8c02-d080cb4fc4e8'} | [] | Connections to Kaspersky | OUTBOUND | 81b9f50f-2eab-4101-b8c8-c902842887c5 | Connections to Kaspersky |
>| Outbound Flows from Serve | {'id': 'a823144b-ef1a-4c34-8c02-d080cb4fc4e8'} | [] | Outbound Flows from Servers (eg, File Downloads and Web Browsing) | OUTBOUND | feae9144-bbfe-4681-8a1e-c426d1de0e54 | Outbound Flows from Servers |
>| Connections to and from B | {'id': 'a823144b-ef1a-4c34-8c02-d080cb4fc4e8'} | [] | Connections to and from countries on block list (Belarus, Côte d'Ivoire, Cuba, Democratic Republic of the Congo, Iran, Iraq, Liberia, North Korea, South Sudan, Sudan, Syria, Zimbabwe) | EITHER | 392d03de-ea20-4637-bf17-d419aaaeec19 | Connections to and from countries on block list |


### domain

***
Provides data enrichment for domains.


#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to enrich. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Domain.annotations.note | String | Customer provided annotation details for a domain | 
| Expanse.Domain.annotations.contacts.id | String | ID for customer provided contact details for a domain | 
| Expanse.Domain.annotations.contacts.name | String | Customer provided contact details for a domain | 
| Expanse.Domain.annotations.tags.id | String | ID for customer added tag on a domain in Expander | 
| Expanse.Domain.annotations.tags.name | String | Customer added tag on a domain in Expander | 
| Expanse.Domain.businessUnits.id | String | Business Units that the domain has been assigned to | 
| Expanse.Domain.businessUnits.name | String | Business Units that the domain has been assigned to | 
| Expanse.Domain.businessUnits.tenantId | String | Tenant ID for business Units that the domain has been assigned to | 
| Expanse.Domain.dateAdded | Date | The date that the domain was added to the Expander instance | 
| Expanse.Domain.details.recentIps.assetKey | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.assetType | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.businessUnits.id | String | Business Units for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.businessUnits.name | String | Business Units for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.businessUnits.tenantId | String | Tenant information for business Units that the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.commonName | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.domain | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.ip | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.lastObserved | Date | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.provider.id | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.provider.name | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.tenant.id | String | Tenant information for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.tenant.name | String | Tenant information for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.tenant.tenantId | String | Tenant information for the recent IPs that the domain resolved to | 
| Expanse.Domain.details.recentIps.type | String | Additional details for the recent IPs that the domain resolved to | 
| Expanse.Domain.dnsResolutionStatus | String | Latest DNS resolution status | 
| Expanse.Domain.firstObserved | Date | The date that the domain was first observed | 
| Expanse.Domain.hasLinkedCloudResources | Boolean | Whether the domain has any linked cloud resources associated with it | 
| Expanse.Domain.id | String | Internal Xpanse ID for Domain | 
| Expanse.Domain.domain | String | The domain value | 
| Expanse.Domain.isCollapsed | Boolean | Whether or not the subdomains of the domain are collapsed | 
| Expanse.Domain.isPaidLevelDomain | Boolean | Whether or not the domain is a PLD | 
| Expanse.Domain.lastObserved | Date | The date that the domain was most recently observed | 
| Expanse.Domain.lastSampledIp | String | The last observed IPv4 address for the domain | 
| Expanse.Domain.lastSubdomainMetadata.collapseType | String | Sub-domain metadata | 
| Expanse.Domain.lastSubdomainMetadata.numSubdomains | Number | Sub-domain metadata | 
| Expanse.Domain.lastSubdomainMetadata.numDistinctIps | Number | Sub-domain metadata | 
| Expanse.Domain.lastSubdomainMetadata.date | Date | Sub-domain metadata | 
| Expanse.Domain.providers.id | String | Information about the hosting provider of the IP the domain resolves to | 
| Expanse.Domain.providers.name | String | Information about the hosting provider of the IP the domain resolves to | 
| Expanse.Domain.serviceStatus | String | Detected service statuses for the domain | 
| Expanse.Domain.sourceDomain | String | The source domain for the domain object | 
| Expanse.Domain.tenant.id | String | Tenant information for the domain | 
| Expanse.Domain.tenant.name | String | Tenant information for the domain | 
| Expanse.Domain.tenant.tenantId | String | Tenant information for the domain | 
| Expanse.Domain.whois.admin.city | String | The admin city in the Whois information for the domain | 
| Expanse.Domain.whois.admin.country | String | The admin country in the Whois information for the domain | 
| Expanse.Domain.whois.admin.emailAddress | String | The admin email address in the Whois information for the domain | 
| Expanse.Domain.whois.admin.faxExtension | String | The admin fax extension in the Whois information for the domain | 
| Expanse.Domain.whois.admin.faxNumber | String | The admin fax number in the Whois information for the domain | 
| Expanse.Domain.whois.admin.name | String | The admin name in the Whois information for the domain | 
| Expanse.Domain.whois.admin.organization | String | The admin organization in the Whois information for the domain | 
| Expanse.Domain.whois.admin.phoneExtension | String | The admin phone extension in the Whois information for the domain | 
| Expanse.Domain.whois.admin.phoneNumber | String | The admin phone number in the Whois information for the domain | 
| Expanse.Domain.whois.admin.postalCode | String | The admin postal code in the Whois information for the domain | 
| Expanse.Domain.whois.admin.province | String | The admin province in the Whois information for the domain | 
| Expanse.Domain.whois.admin.registryId | String | The admin registry ID in the Whois information for the domain | 
| Expanse.Domain.whois.admin.street | String | The admin street in the Whois information for the domain | 
| Expanse.Domain.whois.creationDate | Date | The creation date in the Whois information for the domain | 
| Expanse.Domain.whois.dnssec | String | The dnssec in the Whois information for the domain | 
| Expanse.Domain.whois.domain | String | The domain in the Whois information for the domain | 
| Expanse.Domain.whois.domainStatuses | String | The domain statuses in the Whois information for the domain | 
| Expanse.Domain.whois.nameServers | String | The name servers in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.city | String | The registrant city in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.country | String | The registrant country in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.emailAddress | String | The registrant email address in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.faxExtension | String | The registrant fax extension in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.faxNumber | String | The registrant fax number in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.name | String | The registrant name in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.organization | String | The registrant organization in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.phoneExtension | String | The registrant phone extension in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.phoneNumber | String | The registrant phone number in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.postalCode | String | The registrant postal code in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.province | String | The registrant province in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.registryId | String | The registrant registry ID in the Whois information for the domain | 
| Expanse.Domain.whois.registrant.street | String | The registrant street in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.abuseContactEmail | String | The registrar abuse contact email in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.abuseContactPhone | String | The registrar abuse contact phone in the Whois information for the domain'' | 
| Expanse.Domain.whois.registrar.formattedName | String | The registrar formatted name Whois information for the domain | 
| Expanse.Domain.whois.registrar.ianaId | String | The registrar iana ID in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.name | String | The registrar name in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.registrationExpirationDate | Date | The registrar registration expiration date in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.url | String | The registrar URL in the Whois information for the domain | 
| Expanse.Domain.whois.registrar.whoisServer | String | The registrar Whois server in the Whois information for the domain | 
| Expanse.Domain.whois.registryDomainId | String | The registry domain ID in the Whois information for the domain | 
| Expanse.Domain.whois.registryExpiryDate | Date | The registry expiry date in the Whois information for the domain | 
| Expanse.Domain.whois.reseller | String | The reseller in the Whois information for the domain | 
| Expanse.Domain.whois.tech.city | String | The tech city in the Whois information for the domain | 
| Expanse.Domain.whois.tech.country | String | The tech country in the Whois information for the domain | 
| Expanse.Domain.whois.tech.emailAddress | String | The tech email address in the Whois information for the domain | 
| Expanse.Domain.whois.tech.faxExtension | String | The tech fax extension in the Whois information for the domain | 
| Expanse.Domain.whois.tech.faxNumber | String | The tech fax number in the Whois information for the domain | 
| Expanse.Domain.whois.tech.name | String | The tech name in the Whois information for the domain | 
| Expanse.Domain.whois.tech.organization | String | The tech organization in the Whois information for the domain | 
| Expanse.Domain.whois.tech.phoneExtension | String | The tech phone extension in the Whois information for the domain | 
| Expanse.Domain.whois.tech.phoneNumber | String | The tech phone number in the Whois information for the domain | 
| Expanse.Domain.whois.tech.postalCode | String | The tech postal code in the Whois information for the domain | 
| Expanse.Domain.whois.tech.province | String | The tech province in the Whois information for the domain | 
| Expanse.Domain.whois.tech.registryId | String | The tech registry ID in the Whois information for the domain | 
| Expanse.Domain.whois.tech.street | String | The tech street in the Whois information for the domain | 
| Expanse.Domain.whois.updatedDate | Date | The updated date in the Whois information for the domain | 
| Expanse.Domain.details.cloudResources.id | String | The cloud resource ID | 
| Expanse.Domain.details.cloudResources.tenant.id | String | Tenant information for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.tenant.name | String | Tenant information for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.tenant.tenantId | String | Tenant information for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.businessUnits.id | String | Business Units that the cloud resource has been assigned to | 
| Expanse.Domain.details.cloudResources.businessUnits.name | String | Business Units that the cloud resource has been assigned to | 
| Expanse.Domain.details.cloudResources.businessUnits.tenantId | String | Tenant information businessUnits that the cloud resource as been assigned to | 
| Expanse.Domain.details.cloudResources.dateAdded | Date | The date that the cloud resource was added to the Expander instance | 
| Expanse.Domain.details.cloudResources.firstObserved | Date | The date that the cloud resource was first observed | 
| Expanse.Domain.details.cloudResources.lastObserved | Date | The date that the domain was most recently observed | 
| Expanse.Domain.details.cloudResources.instanceId | String | Instance ID for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.type | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.name | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.ips | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.domain | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.provider.id | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.provider.name | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.region | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.vpc.id | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.vpc.name | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.accountIntegration.id | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.accountIntegration.name | String | Additional details for the cloud resource linked to the domain | 
| Expanse.Domain.details.cloudResources.recentIps.assetKey | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.assetType | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.businessUnits.id | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Domain.details.cloudResources.recentIps.businessUnits.name | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Domain.details.cloudResources.recentIps.businessUnits.tenantId | String | Business Units that the recent IPs linked to the linked cloud resource has been assigned to | 
| Expanse.Domain.details.cloudResources.recentIps.commonName | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.domain | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.ip | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.lastObserved | Date | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.provider.id | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.provider.name | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.tenant.id | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.tenant.name | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.tenant.tenantId | String | Tenant information for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.recentIps.type | String | Additional details for the recent IPs linked to the linked cloud resource | 
| Expanse.Domain.details.cloudResources.annotations.note | String | Customer provided annotation details for a domain | 
| Expanse.Domain.details.cloudResources.annotations.contacts.id | String | ID for customer provided contact details for a domain | 
| Expanse.Domain.details.cloudResources.annotations.contacts.name | String | Customer provided contact details for a domain | 
| Expanse.Domain.details.cloudResources.annotations.tags.id | String | ID for customer added tag on a domain in Expander | 
| Expanse.Domain.details.cloudResources.annotations.tags.name | String | Customer added tag on a domain in Expander | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.DNS | String | A list of IP objects resolved by DNS. | 
| Domain.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| Domain.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| Domain.CreationDate | Date | The date that the domain was created. | 
| Domain.UpdatedDate | String | The date that the domain was last updated. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.DomainStatus | Date | The status of the domain. | 
| Domain.NameServers | String | Name servers of the domain. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.Subdomains | String | Subdomains of the domain. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Registrant.Email | String | The email address of the registrant. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.WHOIS.DomainStatus | String | The status of the domain. | 
| Domain.WHOIS.NameServers | String | Name servers of the domain. | 
| Domain.WHOIS.CreationDate | Date | The date that the domain was created. | 
| Domain.WHOIS.UpdatedDate | Date | The date that the domain was last updated. | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.Registrant.Name | String | The name of the registrant. | 
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant. | 
| Domain.WHOIS.Registrant.Phone | String | The phone number of the registrant. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: "GoDaddy" | 
| Domain.WHOIS.Registrar.AbuseEmail | String | The email address of the contact for reporting abuse. | 
| Domain.WHOIS.Registrar.AbusePhone | String | The phone number of contact for reporting abuse. | 
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator. | 
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator. | 
| Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.WHOIS.History | String | List of Whois objects | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example

```!domain domain="*.108.pets.com"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "*.108.pets.com",
        "Score": 0,
        "Type": "domainglob",
        "Vendor": "ExpanseV2"
    },
    "Domain": {
        "Admin": {
            "Country": "UNITED STATES",
            "Email": "legal@petsmart.com",
            "Name": "Admin Contact",
            "Phone": "16235806100"
        },
        "CreationDate": "1994-11-21T05:00:00Z",
        "DomainStatus": "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited",
        "ExpirationDate": "2018-11-20T05:00:00Z",
        "Name": "*.108.pets.com",
        "NameServers": [
            "NS1.MARKMONITOR.COM",
            "NS2.MARKMONITOR.COM",
            "NS3.MARKMONITOR.COM",
            "NS4.MARKMONITOR.COM",
            "NS5.MARKMONITOR.COM",
            "NS6.MARKMONITOR.COM",
            "NS7.MARKMONITOR.COM"
        ],
        "Organization": "PetSmart Home Office, Inc.",
        "Registrant": {
            "Country": "UNITED STATES",
            "Email": "legal@petsmart.com",
            "Name": "Admin Contact",
            "Phone": "16235806100"
        },
        "Registrar": {
            "AbuseEmail": null,
            "AbusePhone": null,
            "Name": "MarkMonitor Inc."
        },
        "UpdatedDate": "2016-10-19T09:12:50Z",
        "WHOIS": {
            "Admin": {
                "Country": "UNITED STATES",
                "Email": "legal@petsmart.com",
                "Name": "Admin Contact",
                "Phone": "16235806100"
            },
            "CreationDate": "1994-11-21T05:00:00Z",
            "DomainStatus": "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited",
            "ExpirationDate": "2018-11-20T05:00:00Z",
            "NameServers": [
                "NS1.MARKMONITOR.COM",
                "NS2.MARKMONITOR.COM",
                "NS3.MARKMONITOR.COM",
                "NS4.MARKMONITOR.COM",
                "NS5.MARKMONITOR.COM",
                "NS6.MARKMONITOR.COM",
                "NS7.MARKMONITOR.COM"
            ],
            "Registrant": {
                "Country": "UNITED STATES",
                "Email": "legal@petsmart.com",
                "Name": "Admin Contact",
                "Phone": "16235806100"
            },
            "Registrar": {
                "AbuseEmail": null,
                "AbusePhone": null,
                "Name": "MarkMonitor Inc."
            },
            "UpdatedDate": "2016-10-19T09:12:50Z"
        }
    },
    "Expanse": {
        "Domain": {
            "annotations": {
                "contacts": [],
                "note": "",
                "tags": [
                    {
                        "id": "e00bc79d-d367-36f4-824c-042836fef5fc",
                        "name": "xsoar-test-pb-tag"
                    }
                ]
            },
            "businessUnits": [
                {
                    "id": "c4de7fad-cde1-46cf-8725-a5999533db59",
                    "name": "PANW VanDelay Import-Export Dev",
                    "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
                },
                {
                    "id": "f738ace6-f451-4f31-898d-a12afa204b2a",
                    "name": "PANW VanDelay Dev",
                    "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
                }
            ],
            "dateAdded": "2020-09-22T21:23:02.372Z",
            "details": {
                "cloudResources": [],
                "recentIps": []
            },
            "dnsResolutionStatus": [
                "HAS_DNS_RESOLUTION"
            ],
            "domain": "*.108.pets.com",
            "firstObserved": "2020-09-22T06:10:31.787Z",
            "hasLinkedCloudResources": false,
            "id": "142194a1-f443-3878-8dcc-540f4061c5f5",
            "isCollapsed": false,
            "isPaidLevelDomain": false,
            "lastObserved": "2020-09-22T06:10:31.787Z",
            "lastSampledIp": "72.52.10.14",
            "lastSubdomainMetadata": null,
            "providers": [
                {
                    "id": "Akamai",
                    "name": "Akamai Technologies"
                }
            ],
            "serviceStatus": [
                "NO_ACTIVE_SERVICE",
                "NO_ACTIVE_ON_PREM_SERVICE",
                "NO_ACTIVE_CLOUD_SERVICE"
            ],
            "sourceDomain": "pets.com",
            "tenant": {
                "id": "f738ace6-f451-4f31-898d-a12afa204b2a",
                "name": "PANW VanDelay Dev",
                "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
            },
            "whois": [
                {
                    "admin": {
                        "city": "Phoenix",
                        "country": "UNITED STATES",
                        "emailAddress": "legal@petsmart.com",
                        "faxExtension": "",
                        "faxNumber": "16235806109",
                        "name": "Admin Contact",
                        "organization": "PetSmart Home Office, Inc.",
                        "phoneExtension": "",
                        "phoneNumber": "16235806100",
                        "postalCode": "85027",
                        "province": "AZ",
                        "registryId": null,
                        "street": "19601 N 27th Ave,"
                    },
                    "creationDate": "1994-11-21T05:00:00Z",
                    "dnssec": null,
                    "domain": "pets.com",
                    "domainStatuses": [
                        "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited"
                    ],
                    "nameServers": [
                        "NS1.MARKMONITOR.COM",
                        "NS2.MARKMONITOR.COM",
                        "NS3.MARKMONITOR.COM",
                        "NS4.MARKMONITOR.COM",
                        "NS5.MARKMONITOR.COM",
                        "NS6.MARKMONITOR.COM",
                        "NS7.MARKMONITOR.COM"
                    ],
                    "registrant": {
                        "city": "Phoenix",
                        "country": "UNITED STATES",
                        "emailAddress": "legal@petsmart.com",
                        "faxExtension": "",
                        "faxNumber": "16235806109",
                        "name": "Admin Contact",
                        "organization": "PetSmart Home Office, Inc.",
                        "phoneExtension": "",
                        "phoneNumber": "16235806100",
                        "postalCode": "85027",
                        "province": "AZ",
                        "registryId": null,
                        "street": "19601 N 27th Ave,"
                    },
                    "registrar": {
                        "abuseContactEmail": null,
                        "abuseContactPhone": null,
                        "formattedName": null,
                        "ianaId": null,
                        "name": "MarkMonitor Inc.",
                        "registrationExpirationDate": null,
                        "url": null,
                        "whoisServer": "whois.markmonitor.com"
                    },
                    "registryDomainId": null,
                    "registryExpiryDate": "2018-11-20T05:00:00Z",
                    "reseller": null,
                    "tech": {
                        "city": null,
                        "country": null,
                        "emailAddress": null,
                        "faxExtension": null,
                        "faxNumber": null,
                        "name": null,
                        "organization": null,
                        "phoneExtension": null,
                        "phoneNumber": null,
                        "postalCode": null,
                        "province": null,
                        "registryId": null,
                        "street": null
                    },
                    "updatedDate": "2016-10-19T09:12:50Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Expanse Domain List
>
>|annotations|businessUnits|dateAdded|details|dnsResolutionStatus|domain|firstObserved|hasLinkedCloudResources|id|isCollapsed|isPaidLevelDomain|lastObserved|lastSampledIp|lastSubdomainMetadata|providers|serviceStatus|sourceDomain|tenant|whois|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| contacts: <br/>tags: {'id': 'e00bc79d-d367-36f4-824c-042836fef5fc', 'name': 'xsoar-test-pb-tag'}<br/>note:  | {'id': 'c4de7fad-cde1-46cf-8725-a5999533db59', 'name': 'PANW VanDelay Import-Export Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'},<br/>{'id': 'f738ace6-f451-4f31-898d-a12afa204b2a', 'name': 'PANW VanDelay Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'} | 2020-09-22T21:23:02.372Z | recentIps: <br/>cloudResources:  | HAS_DNS_RESOLUTION | *.108.pets.com | 2020-09-22T06:10:31.787Z | false | 142194a1-f443-3878-8dcc-540f4061c5f5 | false | false | 2020-09-22T06:10:31.787Z | 72.52.10.14 |  | {'id': 'Akamai', 'name': 'Akamai Technologies'} | NO_ACTIVE_SERVICE,<br/>NO_ACTIVE_ON_PREM_SERVICE,<br/>NO_ACTIVE_CLOUD_SERVICE | pets.com | id: f738ace6-f451-4f31-898d-a12afa204b2a<br/>name: PANW VanDelay Dev<br/>tenantId: f738ace6-f451-4f31-898d-a12afa204b2a | {'domain': 'pets.com', 'registryDomainId': None, 'updatedDate': '2016-10-19T09:12:50Z', 'creationDate': '1994-11-21T05:00:00Z', 'registryExpiryDate': '2018-11-20T05:00:00Z', 'reseller': None, 'registrar': {'name': 'MarkMonitor Inc.', 'formattedName': None, 'whoisServer': 'whois.markmonitor.com', 'url': None, 'ianaId': None, 'registrationExpirationDate': None, 'abuseContactEmail': None, 'abuseContactPhone': None}, 'domainStatuses': ['clientDeleteProhibited clientTransferProhibited clientUpdateProhibited'], 'nameServers': ['NS1.MARKMONITOR.COM', 'NS2.MARKMONITOR.COM', 'NS3.MARKMONITOR.COM', 'NS4.MARKMONITOR.COM', 'NS5.MARKMONITOR.COM', 'NS6.MARKMONITOR.COM', 'NS7.MARKMONITOR.COM'], 'registrant': {'name': 'Admin Contact', 'organization': 'PetSmart Home Office, Inc.', 'street': '19601 N 27th Ave,', 'city': 'Phoenix', 'province': 'AZ', 'postalCode': '85027', 'country': 'UNITED STATES', 'phoneNumber': '16235806100', 'phoneExtension': '', 'faxNumber': '16235806109', 'faxExtension': '', 'emailAddress': '<legal@petsmart.com>', 'registryId': None}, 'admin': {'name': 'Admin Contact', 'organization': 'PetSmart Home Office, Inc.', 'street': '19601 N 27th Ave,', 'city': 'Phoenix', 'province': 'AZ', 'postalCode': '85027', 'country': 'UNITED STATES', 'phoneNumber': '16235806100', 'phoneExtension': '', 'faxNumber': '16235806109', 'faxExtension': '', 'emailAddress': '<legal@petsmart.com>', 'registryId': None}, 'tech': {'name': None, 'organization': None, 'street': None, 'city': None, 'province': None, 'postalCode': None, 'country': None, 'phoneNumber': None, 'phoneExtension': None, 'faxNumber': None, 'faxExtension': None, 'emailAddress': None, 'registryId': None}, 'dnssec': None} |


### ip

***
Provides data enrichment for IPs.


#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP to enrich. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IP.ip | String | The IPv4 address of the asset | 
| Expanse.IP.assetKey | String | Key used to access the asset in the respective Xpanse asset API | 
| Expanse.IP.assetType | String | The type of asset | 
| Expanse.IP.businessUnits.id | String | The internal Xpanse ID for the business unit the asset belongs to | 
| Expanse.IP.businessUnits.name | String | The name of the business unit the asset belongs to | 
| Expanse.IP.businessUnits.tenantId | String | The ID of the tenant that the asset belongs to | 
| Expanse.IP.commonName | String | The certificate common name of the asset | 
| Expanse.IP.domain | String | The domain name of the asset | 
| Expanse.IP.lastObserved | Date | The last observed IPv4 address of the asset | 
| Expanse.IP.provider.id | String | The ID of the provider the asset was detected on | 
| Expanse.IP.provider.name | String | The name of the provider the asset was detected on | 
| Expanse.IP.tenant.id | String | The internal Xpanse ID of the tenant that the asset belongs to | 
| Expanse.IP.tenant.name | String | The name of the tenant that the asset belongs to | 
| Expanse.IP.tenant.tenantId | String | The ID of the tenant that the asset belongs to | 
| Expanse.IP.type | String | The type of asset that the IPv4 address relates to | 
| IP.Address | String | IP address | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Hostname | String | The hostname that is mapped to this IP address. | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Geo.Description | String | Additional information about the location. | 
| IP.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| IP.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example

```!ip ip="1.1.1.1"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Score": 0,
        "Type": "ip",
        "Vendor": "ExpanseV2"
    },
    "Expanse": {
        "IP": {
            "assetKey": "test.developers.company.com",
            "assetType": "DOMAIN",
            "businessUnits": [
                {
                    "id": "a823144b-ef1a-4c34-8c02-d080cb4fc4e",
                    "name": "Company Test",
                    "tenantId": "a823144b-ef1a-4c34-8c02-d080cb4fc4e"
                }
            ],
            "commonName": null,
            "domain": "test.developers.company.com",
            "ip": "1.1.1.1",
            "lastObserved": "2020-12-16T07:10:36.961Z",
            "provider": {
                "id": "AWS",
                "name": "Amazon Web Services"
            },
            "tenant": {
                "id": "a823144b-ef1a-4c34-8c02-d080cb4fc4e",
                "name": "Company Test",
                "tenantId": "a823144b-ef1a-4c34-8c02-d080cb4fc4e"
            },
            "type": "DOMAIN_RESOLUTION"
        }
    },
    "IP": {
        "Address": "1.1.1.1",
        "Hostname": "test.developers.company.com"
    }
}
```

#### Human Readable Output

>### Expanse IP List
>
>|assetKey|assetType|businessUnits|commonName|domain|ip|lastObserved|provider|tenant|type|
>|---|---|---|---|---|---|---|---|---|---|
>| test.developers.company.com | DOMAIN | {'id': 'a823144b-ef1a-4c34-8c02-d080cb4fc4e', 'name': 'Company Test', 'tenantId': 'a823144b-ef1a-4c34-8c02-d080cb4fc4e'} |  | test.developers.company.com | 1.1.1.1 | 2020-12-16T07:10:36.961Z | id: AWS<br/>name: Amazon Web Services | id: a823144b-ef1a-4c34-8c02-d080cb4fc4e<br/>name: Company Test<br/>tenantId: a823144b-ef1a-4c34-8c02-d080cb4fc4e | DOMAIN_RESOLUTION |


### cidr

***
Provides data enrichment for CIDR blocks using Xpanse IP Range.


#### Base Command

`cidr`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cidr | The CIDR block to enrich. | Optional | 
| include | Include "none" or any of the following options (comma separated) - annotations, severityCounts, attributionReasons, relatedRegistrationInformation, locationInformation. Default is severityCounts,annotations,attributionReasons,relatedRegistrationInformation,locationInformation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IPRange.annotations.additionalNotes | String | Customer provided annotation details for an IP range | 
| Expanse.IPRange.annotations.contacts | String | Customer provided point-of-contact details for an IP range | 
| Expanse.IPRange.annotations.tags | String | Customer provided tags for an IP range | 
| Expanse.IPRange.attributionReasons.reason | String | The reasons why an IP range is attributed to the customer | 
| Expanse.IPRange.businessUnits.id | String | Business Units that the IP range has been assigned to | 
| Expanse.IPRange.businessUnits.name | String | Business Units that the IP range has been assigned to | 
| Expanse.IPRange.created | Date | The date that the IP range was added to the Expander instance | 
| Expanse.IPRange.id | String | Internal Xpanse ID for the IP Range | 
| Expanse.IPRange.ipVersion | String | The IP version of the IP range | 
| Expanse.IPRange.locationInformation.geolocation.city | String | The IP range geolocation | 
| Expanse.IPRange.locationInformation.geolocation.countryCode | String | The IP range geolocation | 
| Expanse.IPRange.locationInformation.geolocation.latitude | Number | The IP range geolocation | 
| Expanse.IPRange.locationInformation.geolocation.longitude | Number | The IP range geolocation | 
| Expanse.IPRange.locationInformation.geolocation.regionCode | String | The IP range geolocation | 
| Expanse.IPRange.locationInformation.ip | String | The IP range geolocation | 
| Expanse.IPRange.modified | Date | The date on which the IP range was last ingested into Expander | 
| Expanse.IPRange.rangeIntroduced | Date | The date that the IP range was added to the Expander instance | 
| Expanse.IPRange.rangeSize | Number | The number of IP addresses in the IP range | 
| Expanse.IPRange.rangeType | String | If the IP range is Xpanse-generated parent range or a customer-generated custom range | 
| Expanse.IPRange.relatedRegistrationInformation.country | String | The country within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.endAddress | String | The end address within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.handle | String | The handle within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.ipVersion | String | The IP version within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.name | String | The name within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.parentHandle | String | The parent handle within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.address | String | The address within the registry entities of the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.email | String | The email within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.action | String | The events action within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.actor | String | The events actor within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.date | Date | The events date within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.firstRegistered | Date | The first registered date within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.formattedName | String | The formatted name within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.handle | String | The handle within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.id | String | The ID within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.lastChanged | Date | The last changed date within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.org | String | The org within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.phone | String | The phone number within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.relatedEntityHandles | String | The related entity handles within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.remarks | String | The remarks within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.roles | String | The roles within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.statuses | String | The statuses within the registry entities of the e IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.remarks | String | The remarks within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.startAddress | String | The start address within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.updatedDate | Date | The last update date within the IP range registration information | 
| Expanse.IPRange.relatedRegistrationInformation.whoisServer | String | The Whois server within the IP range registration information | 
| Expanse.IPRange.responsiveIpCount | Number | The number of IPs responsive on the public Internet within the IP range | 
| Expanse.IPRange.severityCounts.count | Number | The number of exposures observed on the IP range | 
| Expanse.IPRange.severityCounts.type | String | The severity level of the exposures observed on the IP range | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 


#### Command Example

```!cidr cidr="1.179.133.112/29"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "1.179.133.112/29",
        "Score": 0,
        "Type": [
            "cidr"
        ],
        "Vendor": "ExpanseV2"
    },
    "Expanse": {
        "IPRange": {
            "annotations": {
                "additionalNotes": "",
                "pointsOfContact": [],
                "tags": [
                    {
                        "created": "2020-12-07",
                        "id": "e00bc79d-d367-36f4-824c-042836fef5fc",
                        "modified": "2020-12-07",
                        "name": "xsoar-test-pb-tag"
                    }
                ]
            },
            "attributionReasons": [
                {
                    "reason": "This parent range is attributed via IP network registration records for 1.179.133.116\u20131.179.133.119"
                },
                {
                    "reason": "This parent range is attributed via IP network registration records for 1.179.133.112\u20131.179.133.115"
                }
            ],
            "businessUnits": [
                {
                    "id": "c94c50ca-124f-4983-8da5-1756138e2252",
                    "name": "PANW Acme Latex Supply Dev"
                }
            ],
            "cidr": "1.179.133.112/29",
            "created": "2020-09-22",
            "customChildRanges": [],
            "id": "0a8f44f9-05dc-42a3-a395-c83dad49fadf",
            "ipVersion": "4",
            "locationInformation": [],
            "modified": "2020-12-18",
            "rangeIntroduced": "2020-09-22",
            "rangeSize": 8,
            "rangeType": "parent",
            "relatedRegistrationInformation": [
                {
                    "country": "th",
                    "endAddress": "1.179.133.115",
                    "handle": "1.179.133.112 - 1.179.133.115",
                    "ipVersion": "4",
                    "name": "saim-synthetic-latex",
                    "parentHandle": "",
                    "registryEntities": [
                        {
                            "address": "",
                            "email": "",
                            "events": [],
                            "firstRegistered": null,
                            "formattedName": "",
                            "handle": "",
                            "id": "125d112c-1169-3025-89e7-4c8c5a16db0b",
                            "lastChanged": null,
                            "org": "",
                            "phone": "",
                            "relatedEntityHandles": [
                                ""
                            ],
                            "remarks": "",
                            "roles": [
                                "administrative"
                            ],
                            "statuses": ""
                        },
                        {
                            "address": "",
                            "email": "",
                            "events": [],
                            "firstRegistered": null,
                            "formattedName": "",
                            "handle": "",
                            "id": "13cb65ca-9572-394b-b385-b2bd15aceb95",
                            "lastChanged": null,
                            "org": "",
                            "phone": "",
                            "relatedEntityHandles": [
                                ""
                            ],
                            "remarks": "",
                            "roles": [
                                "technical"
                            ],
                            "statuses": ""
                        },
                        {
                            "address": "TOT Public Company Limited\n89/2 Moo 3 Chaengwattana Rd, Laksi,Bangkok 10210 THAILAND          ",
                            "email": "apipolg@tot.co.th, abuse@totisp.net",
                            "events": [
                                {
                                    "action": "last changed",
                                    "actor": "null",
                                    "date": "2017-06-21T07:19:22Z",
                                    "links": []
                                }
                            ],
                            "firstRegistered": null,
                            "formattedName": "IRT-TOT-TH",
                            "handle": "IRT-TOT-TH",
                            "id": "3c5ef28b-64d7-3d1f-b343-a31078292b04",
                            "lastChanged": "2017-06-21",
                            "org": "",
                            "phone": "",
                            "relatedEntityHandles": [],
                            "remarks": "",
                            "roles": [
                                "abuse"
                            ],
                            "statuses": ""
                        }
                    ],
                    "remarks": "saim synthetic latex,Nong Khaem Province",
                    "startAddress": "1.179.133.112",
                    "updatedDate": "2020-09-22",
                    "whoisServer": "whois.apnic.net"
                },
                {
                    "country": "th",
                    "endAddress": "1.179.133.119",
                    "handle": "1.179.133.116 - 1.179.133.119",
                    "ipVersion": "4",
                    "name": "siam-synthetic-latex",
                    "parentHandle": "",
                    "registryEntities": [
                        {
                            "address": "",
                            "email": "",
                            "events": [],
                            "firstRegistered": null,
                            "formattedName": "",
                            "handle": "",
                            "id": "125d112c-1169-3025-89e7-4c8c5a16db0b",
                            "lastChanged": null,
                            "org": "",
                            "phone": "",
                            "relatedEntityHandles": [
                                ""
                            ],
                            "remarks": "",
                            "roles": [
                                "administrative"
                            ],
                            "statuses": ""
                        },
                        {
                            "address": "",
                            "email": "",
                            "events": [],
                            "firstRegistered": null,
                            "formattedName": "",
                            "handle": "",
                            "id": "13cb65ca-9572-394b-b385-b2bd15aceb95",
                            "lastChanged": null,
                            "org": "",
                            "phone": "",
                            "relatedEntityHandles": [
                                ""
                            ],
                            "remarks": "",
                            "roles": [
                                "technical"
                            ],
                            "statuses": ""
                        },
                        {
                            "address": "TOT Public Company Limited\n89/2 Moo 3 Chaengwattana Rd, Laksi,Bangkok 10210 THAILAND          ",
                            "email": "apipolg@tot.co.th, abuse@totisp.net",
                            "events": [
                                {
                                    "action": "last changed",
                                    "actor": "null",
                                    "date": "2017-06-21T07:19:22Z",
                                    "links": []
                                }
                            ],
                            "firstRegistered": null,
                            "formattedName": "IRT-TOT-TH",
                            "handle": "IRT-TOT-TH",
                            "id": "3c5ef28b-64d7-3d1f-b343-a31078292b04",
                            "lastChanged": "2017-06-21",
                            "org": "",
                            "phone": "",
                            "relatedEntityHandles": [],
                            "remarks": "",
                            "roles": [
                                "abuse"
                            ],
                            "statuses": ""
                        }
                    ],
                    "remarks": "siam synthetic latex,Nong Khaem Province",
                    "startAddress": "1.179.133.116",
                    "updatedDate": "2020-09-22",
                    "whoisServer": "whois.apnic.net"
                }
            ],
            "responsiveIpCount": 0,
            "severityCounts": [
                {
                    "count": 0,
                    "type": "CRITICAL"
                },
                {
                    "count": 0,
                    "type": "ROUTINE"
                },
                {
                    "count": 0,
                    "type": "UNCATEGORIZED"
                },
                {
                    "count": 0,
                    "type": "WARNING"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Expanse IP Range List
>
>|annotations|attributionReasons|businessUnits|cidr|created|customChildRanges|id|ipVersion|locationInformation|modified|rangeIntroduced|rangeSize|rangeType|relatedRegistrationInformation|responsiveIpCount|severityCounts|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| tags: {'id': 'e00bc79d-d367-36f4-824c-042836fef5fc', 'created': '2020-12-07', 'modified': '2020-12-07', 'name': 'xsoar-test-pb-tag'}<br/>additionalNotes: <br/>pointsOfContact:  | {'reason': 'This parent range is attributed via IP network registration records for 1.179.133.116–1.179.133.119'},<br/>{'reason': 'This parent range is attributed via IP network registration records for 1.179.133.112–1.179.133.115'} | {'id': 'c94c50ca-124f-4983-8da5-1756138e2252', 'name': 'PANW Acme Latex Supply Dev'} | 1.179.133.112/29 | 2020-09-22 |  | 0a8f44f9-05dc-42a3-a395-c83dad49fadf | 4 |  | 2020-12-18 | 2020-09-22 | 8 | parent | {'handle': '1.179.133.112 - 1.179.133.115', 'startAddress': '1.179.133.112', 'endAddress': '1.179.133.115', 'ipVersion': '4', 'country': 'th', 'name': 'saim-synthetic-latex', 'parentHandle': '', 'whoisServer': 'whois.apnic.net', 'updatedDate': '2020-09-22', 'remarks': 'saim synthetic latex,Nong Khaem Province', 'registryEntities': [{'id': '125d112c-1169-3025-89e7-4c8c5a16db0b', 'handle': '', 'address': '', 'email': '', 'events': [], 'firstRegistered': None, 'formattedName': '', 'lastChanged': None, 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [''], 'roles': ['administrative']}, {'id': '13cb65ca-9572-394b-b385-b2bd15aceb95', 'handle': '', 'address': '', 'email': '', 'events': [], 'firstRegistered': None, 'formattedName': '', 'lastChanged': None, 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [''], 'roles': ['technical']}, {'id': '3c5ef28b-64d7-3d1f-b343-a31078292b04', 'handle': 'IRT-TOT-TH', 'address': 'TOT Public Company Limited\n89/2 Moo 3 Chaengwattana Rd, Laksi,Bangkok 10210 THAILAND          ', 'email': 'apipolg@tot.co.th, abuse@totisp.net', 'events': [{'action': 'last changed', 'actor': 'null', 'date': '2017-06-21T07:19:22Z', 'links': []}], 'firstRegistered': None, 'formattedName': 'IRT-TOT-TH', 'lastChanged': '2017-06-21', 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [], 'roles': ['abuse']}]},<br/>{'handle': '1.179.133.116 - 1.179.133.119', 'startAddress': '1.179.133.116', 'endAddress': '1.179.133.119', 'ipVersion': '4', 'country': 'th', 'name': 'siam-synthetic-latex', 'parentHandle': '', 'whoisServer': 'whois.apnic.net', 'updatedDate': '2020-09-22', 'remarks': 'siam synthetic latex,Nong Khaem Province', 'registryEntities': [{'id': '125d112c-1169-3025-89e7-4c8c5a16db0b', 'handle': '', 'address': '', 'email': '', 'events': [], 'firstRegistered': None, 'formattedName': '', 'lastChanged': None, 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [''], 'roles': ['administrative']}, {'id': '13cb65ca-9572-394b-b385-b2bd15aceb95', 'handle': '', 'address': '', 'email': '', 'events': [], 'firstRegistered': None, 'formattedName': '', 'lastChanged': None, 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [''], 'roles': ['technical']}, {'id': '3c5ef28b-64d7-3d1f-b343-a31078292b04', 'handle': 'IRT-TOT-TH', 'address': 'TOT Public Company Limited\n89/2 Moo 3 Chaengwattana Rd, Laksi,Bangkok 10210 THAILAND          ', 'email': 'apipolg@tot.co.th, abuse@totisp.net', 'events': [{'action': 'last changed', 'actor': 'null', 'date': '2017-06-21T07:19:22Z', 'links': []}], 'firstRegistered': None, 'formattedName': 'IRT-TOT-TH', 'lastChanged': '2017-06-21', 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [], 'roles': ['abuse']}]} | 0 | {'type': 'CRITICAL', 'count': 0},<br/>{'type': 'ROUTINE', 'count': 0},<br/>{'type': 'UNCATEGORIZED', 'count': 0},<br/>{'type': 'WARNING', 'count': 0} |


### expanse-get-domains-for-certificate

***
Returns all domains which have been seen with the specified certificate.

##### Required Permissions

**none**

##### Base Command

`expanse-get-domains-for-certificate`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| common_name | The certificate common name | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IPDomains.SearchTerm | string | The common name that was searched |
| Expanse.IPDomains.TotalDomainCount | number | The number of domains found matching the specified certificate |
| Expanse.IPDomains.FlatDomainList | number | An array of all domain names found. This is truncated at 50 |
| Expanse.IPDomains.DomainList | number | An array of domain objects. This is truncated at 50 |

##### Command Example

```!expanse-get-domains-for-certificate common_name="*.us.expanse.co"```

##### Context Example
<!-- disable-secrets-detection-start -->
```json
{
    "SearchTerm": "*.us.expanse.co",
    "TotalDomainCount": 2,
    "FlatDomainList": ["california.us.expanse.co", "dc.us.expanse.co"],
    "DomainList": [
        {
            "ip": "33.2.243.123",
            "domain": "california.us.expanse.co",
            "type": "DOMAIN_RESOLUTION",
            "assetType": "DOMAIN",
            "assetKey": "california.us.expanse.co",
            "provider": {
                "id": "AWS",
                "name": "Amazon Web Services"
            },
            "lastObserved": "2020-06-22T05:20:32.883Z",
            "tenant": {
                "id": "4b7efca7-c595-408e-b4d1-634080e48367",
                "name": "Palo Alto Networks",
                "tenantId": "4b7efca7-c595-408e-b4d1-634080e48367"
            },
            "businessUnits": [
                {
                    "id": "a1f0f39b-f358-3c8c-947b-926887871b88",
                    "name": "VanDelay Import-Export",
                    "tenantId": "a1f0f39b-f358-3c8c-947b-926887871b88"
                }
            ],
            "commonName": null
        },
        {
            "ip": "33.2.243.123",
            "domain": "dc.us.expanse.co",
            "type": "DOMAIN_RESOLUTION",
            "assetType": "DOMAIN",
            "assetKey": "dc.us.expanse.co",
            "provider": {
                "id": "AWS",
                "name": "Amazon Web Services"
            },
            "lastObserved": "2020-06-21T07:20:32.883Z",
            "tenant": {
                "id": "4b7efca7-c595-408e-b4d1-634080e48367",
                "name": "Palo Alto Networks",
                "tenantId": "4b7efca7-c595-408e-b4d1-634080e48367"
            },
            "businessUnits": [
                {
                    "id": "a1f0f39b-f358-3c8c-947b-926887871b88",
                    "name": "VanDelay Import-Export",
                    "tenantId": "a1f0f39b-f358-3c8c-947b-926887871b88"
                }
            ],
            "commonName": null
        }
    ]
}
```
<!-- disable-secrets-detection-start -->

##### Human Readable Output

### Expanse Domains matching Certificate Common Name: *.us.expanse.co

| FlatDomainList | SearchTerm | TotalDomainCount |
|---|---|---|
| california.us.expanse.co, dc.us.expanse.co | *.us.expanse.co | 2 |

