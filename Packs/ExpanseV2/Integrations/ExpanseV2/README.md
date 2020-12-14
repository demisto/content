Expanse Expander V2
This integration was integrated and tested with version Expanse Expander and Behavior
## Configure ExpanseV2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ExpanseV2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Your server URL | True |
    | apikey | API Key | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |
    | isFetch | Fetch incidents | False |
    | incidentType | Incident type | False |
    | fetch_details | Fetch additional incident data | False |
    | max_fetch | Maximum number of incidents per fetch | False |
    | first_fetch | First fetch time | False |
    | priority | Fetch issues with Priority | False |
    | activityStatus | Fetch issues with Activity Status | False |
    | progressStatus | Fetch issues with Progress Status | False |
    | businessUnit | Fetch issues with Business Units \(comma separated\) | False |
    | tag | Fetch issues with Tags \(comma separated\) | False |
    | issueType | Fetch issue with Types \(comma separated\) | False |
    | mirror_direction | Incident Mirroring Direction | False |
    | sync_owners | Sync Incident Owners | False |
    | incoming_tags | Tag\(s\) for mirrored comments | False |
    | sync_tags | Mirror out Entries with tag\(s\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| content_search | content_search. | Optional | 
| provider | provider. | Optional | 
| business_unit | business_unit. | Optional | 
| assignee | assignee. | Optional | 
| issue_type | issue_type. | Optional | 
| inet_search | inet_search. | Optional | 
| domain_search | domain_search. | Optional | 
| port_number | port_number. | Optional | 
| progress_status | progress_status. | Optional | 
| activity_status | activity_status. | Optional | 
| tag | tag. | Optional | 
| created_before | created_before. | Optional | 
| created_after | created_after. | Optional | 
| modified_before | modified_before. | Optional | 
| modified_after | modified_after. | Optional | 
| sort | sort. Possible values are: created, -created, modified, -modified, activityStatus, -assigneeUsername, priority, -priority, progressStatus, -progressStatus, activityStatus, -activityStatus, headline, -headline. Default is created. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Issue.activityStatus | String |  | 
| Expanse.Issue.assets.assetKey | String |  | 
| Expanse.Issue.assets.assetType | String |  | 
| Expanse.Issue.assets.displayName | String |  | 
| Expanse.Issue.assets.id | String |  | 
| Expanse.Issue.assigneeUsername | String |  | 
| Expanse.Issue.businessUnits.id | String |  | 
| Expanse.Issue.businessUnits.name | String |  | 
| Expanse.Issue.category | String |  | 
| Expanse.Issue.certificate.formattedIssuerOrg | String |  | 
| Expanse.Issue.certificate.id | String |  | 
| Expanse.Issue.certificate.issuer | String |  | 
| Expanse.Issue.certificate.issuerAlternativeNames | String |  | 
| Expanse.Issue.certificate.issuerCountry | String |  | 
| Expanse.Issue.certificate.issuerEmail | String |  | 
| Expanse.Issue.certificate.issuerLocality | String |  | 
| Expanse.Issue.certificate.issuerName | String |  | 
| Expanse.Issue.certificate.issuerOrg | String |  | 
| Expanse.Issue.certificate.issuerOrgUnit | String |  | 
| Expanse.Issue.certificate.issuerState | String |  | 
| Expanse.Issue.certificate.md5Hash | String |  | 
| Expanse.Issue.certificate.pemSha1 | String |  | 
| Expanse.Issue.certificate.pemSha256 | String |  | 
| Expanse.Issue.certificate.publicKey | String |  | 
| Expanse.Issue.certificate.publicKeyAlgorithm | String |  | 
| Expanse.Issue.certificate.publicKeyBits | Number |  | 
| Expanse.Issue.certificate.publicKeyModulus | String |  | 
| Expanse.Issue.certificate.publicKeyRsaExponent | Number |  | 
| Expanse.Issue.certificate.publicKeySpki | String |  | 
| Expanse.Issue.certificate.serialNumber | String |  | 
| Expanse.Issue.certificate.signatureAlgorithm | String |  | 
| Expanse.Issue.certificate.subject | String |  | 
| Expanse.Issue.certificate.subjectAlternativeNames | String |  | 
| Expanse.Issue.certificate.subjectCountry | String |  | 
| Expanse.Issue.certificate.subjectEmail | String |  | 
| Expanse.Issue.certificate.subjectLocality | String |  | 
| Expanse.Issue.certificate.subjectName | String |  | 
| Expanse.Issue.certificate.subjectOrg | String |  | 
| Expanse.Issue.certificate.subjectOrgUnit | String |  | 
| Expanse.Issue.certificate.subjectState | String |  | 
| Expanse.Issue.certificate.validNotAfter | Date |  | 
| Expanse.Issue.certificate.validNotBefore | Date |  | 
| Expanse.Issue.certificate.version | String |  | 
| Expanse.Issue.created | Date |  | 
| Expanse.Issue.headline | String |  | 
| Expanse.Issue.helpText | String |  | 
| Expanse.Issue.id | String |  | 
| Expanse.Issue.initialEvidence.certificate.formattedIssuerOrg | String |  | 
| Expanse.Issue.initialEvidence.certificate.id | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuer | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerAlternativeNames | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerCountry | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerEmail | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerLocality | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerName | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerOrg | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerOrgUnit | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerState | String |  | 
| Expanse.Issue.initialEvidence.certificate.md5Hash | String |  | 
| Expanse.Issue.initialEvidence.certificate.pemSha1 | String |  | 
| Expanse.Issue.initialEvidence.certificate.pemSha256 | String |  | 
| Expanse.Issue.initialEvidence.certificate.publicKey | String |  | 
| Expanse.Issue.initialEvidence.certificate.publicKeyAlgorithm | String |  | 
| Expanse.Issue.initialEvidence.certificate.publicKeyBits | Number |  | 
| Expanse.Issue.initialEvidence.certificate.publicKeyModulus | String |  | 
| Expanse.Issue.initialEvidence.certificate.publicKeyRsaExponent | Number |  | 
| Expanse.Issue.initialEvidence.certificate.publicKeySpki | String |  | 
| Expanse.Issue.initialEvidence.certificate.serialNumber | String |  | 
| Expanse.Issue.initialEvidence.certificate.signatureAlgorithm | String |  | 
| Expanse.Issue.initialEvidence.certificate.subject | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectAlternativeNames | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectCountry | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectEmail | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectLocality | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectName | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectOrg | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectOrgUnit | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectState | String |  | 
| Expanse.Issue.initialEvidence.certificate.validNotAfter | Date |  | 
| Expanse.Issue.initialEvidence.certificate.validNotBefore | Date |  | 
| Expanse.Issue.initialEvidence.certificate.version | String |  | 
| Expanse.Issue.initialEvidence.cipherSuite | String |  | 
| Expanse.Issue.initialEvidence.configuration._type | String |  | 
| Expanse.Issue.initialEvidence.configuration.validWhenScanned | Boolean |  | 
| Expanse.Issue.initialEvidence.discoveryType | String |  | 
| Expanse.Issue.initialEvidence.domain | String |  | 
| Expanse.Issue.initialEvidence.evidenceType | String |  | 
| Expanse.Issue.initialEvidence.exposureId | String |  | 
| Expanse.Issue.initialEvidence.exposureType | String |  | 
| Expanse.Issue.initialEvidence.geolocation.latitude | Number |  | 
| Expanse.Issue.initialEvidence.geolocation.longitude | Number |  | 
| Expanse.Issue.initialEvidence.geolocation.city | String |  | 
| Expanse.Issue.initialEvidence.geolocation.regionCode | String |  | 
| Expanse.Issue.initialEvidence.geolocation.countryCode | String |  | 
| Expanse.Issue.initialEvidence.ip | String |  | 
| Expanse.Issue.initialEvidence.portNumber | Number |  | 
| Expanse.Issue.initialEvidence.portProtocol | String |  | 
| Expanse.Issue.initialEvidence.serviceId | String |  | 
| Expanse.Issue.initialEvidence.serviceProperties.serviceProperties.name | String |  | 
| Expanse.Issue.initialEvidence.serviceProperties.serviceProperties.reason | String |  | 
| Expanse.Issue.initialEvidence.timestamp | Date |  | 
| Expanse.Issue.initialEvidence.tlsVersion | String |  | 
| Expanse.Issue.ip | String |  | 
| Expanse.Issue.issueType.id | String |  | 
| Expanse.Issue.issueType.name | String |  | 
| Expanse.Issue.latestEvidence.certificate.formattedIssuerOrg | String |  | 
| Expanse.Issue.latestEvidence.certificate.id | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuer | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerAlternativeNames | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerCountry | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerEmail | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerLocality | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerName | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerOrg | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerOrgUnit | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerState | String |  | 
| Expanse.Issue.latestEvidence.certificate.md5Hash | String |  | 
| Expanse.Issue.latestEvidence.certificate.pemSha1 | String |  | 
| Expanse.Issue.latestEvidence.certificate.pemSha256 | String |  | 
| Expanse.Issue.latestEvidence.certificate.publicKey | String |  | 
| Expanse.Issue.latestEvidence.certificate.publicKeyAlgorithm | String |  | 
| Expanse.Issue.latestEvidence.certificate.publicKeyBits | Number |  | 
| Expanse.Issue.latestEvidence.certificate.publicKeyModulus | String |  | 
| Expanse.Issue.latestEvidence.certificate.publicKeyRsaExponent | Number |  | 
| Expanse.Issue.latestEvidence.certificate.publicKeySpki | String |  | 
| Expanse.Issue.latestEvidence.certificate.serialNumber | String |  | 
| Expanse.Issue.latestEvidence.certificate.signatureAlgorithm | String |  | 
| Expanse.Issue.latestEvidence.certificate.subject | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectAlternativeNames | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectCountry | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectEmail | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectLocality | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectName | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectOrg | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectOrgUnit | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectState | String |  | 
| Expanse.Issue.latestEvidence.certificate.validNotAfter | Date |  | 
| Expanse.Issue.latestEvidence.certificate.validNotBefore | Date |  | 
| Expanse.Issue.latestEvidence.certificate.version | String |  | 
| Expanse.Issue.latestEvidence.cipherSuite | String |  | 
| Expanse.Issue.latestEvidence.configuration._type | String |  | 
| Expanse.Issue.latestEvidence.configuration.validWhenScanned | Boolean |  | 
| Expanse.Issue.latestEvidence.discoveryType | String |  | 
| Expanse.Issue.latestEvidence.domain | String |  | 
| Expanse.Issue.latestEvidence.evidenceType | String |  | 
| Expanse.Issue.latestEvidence.exposureId | String |  | 
| Expanse.Issue.latestEvidence.exposureType | String |  | 
| Expanse.Issue.latestEvidence.geolocation.latitude | Number |  | 
| Expanse.Issue.latestEvidence.geolocation.longitude | Number |  | 
| Expanse.Issue.latestEvidence.geolocation.city | String |  | 
| Expanse.Issue.latestEvidence.geolocation.regionCode | String |  | 
| Expanse.Issue.latestEvidence.geolocation.countryCode | String |  | 
| Expanse.Issue.latestEvidence.ip | String |  | 
| Expanse.Issue.latestEvidence.portNumber | Number |  | 
| Expanse.Issue.latestEvidence.portProtocol | String |  | 
| Expanse.Issue.latestEvidence.serviceId | String |  | 
| Expanse.Issue.latestEvidence.serviceProperties.serviceProperties.name | String |  | 
| Expanse.Issue.latestEvidence.serviceProperties.serviceProperties.reason | String |  | 
| Expanse.Issue.latestEvidence.timestamp | Date |  | 
| Expanse.Issue.latestEvidence.tlsVersion | String |  | 
| Expanse.Issue.modified | Date |  | 
| Expanse.Issue.portNumber | Number |  | 
| Expanse.Issue.portProtocol | String |  | 
| Expanse.Issue.priority | String |  | 
| Expanse.Issue.progressStatus | String |  | 
| Expanse.Issue.providers.id | String |  | 
| Expanse.Issue.providers.name | String |  | 


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
                "discoveryType": "Direct",
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
                "discoveryType": "Direct",
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
            "modified": "2020-12-07T12:02:49.335834Z",
            "portNumber": 443,
            "portProtocol": "TCP",
            "priority": "Medium",
            "progressStatus": "New",
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

>### Results
>|activityStatus|annotations|assets|assigneeUsername|businessUnits|category|certificate|created|domain|headline|helpText|id|initialEvidence|ip|issueType|latestEvidence|modified|portNumber|portProtocol|priority|progressStatus|providers|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Active | tags:  | {'id': '724a1137-ee3f-381f-95f2-ea0441db22d0', 'assetKey': 'gdRHmkxmGwWpaUtAuge6IQ==', 'assetType': 'Certificate', 'displayName': '*.thespeedyou.com'} | Unassigned | {'id': 'f738ace6-f451-4f31-898d-a12afa204b2a', 'name': 'PANW VanDelay Dev'} | Attack Surface Reduction | id: 81d4479a-4c66-3b05-a969-4b40ba07ba21<br/>md5Hash: gdRHmkxmGwWpaUtAuge6IQ==<br/>issuer: C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3<br/>issuerAlternativeNames: <br/>issuerCountry: US<br/>issuerEmail: null<br/>issuerLocality: null<br/>issuerName: GeoTrust SSL CA - G3<br/>issuerOrg: GeoTrust Inc.<br/>formattedIssuerOrg: GeoTrust<br/>issuerOrgUnit: null<br/>issuerState: null<br/>publicKey: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB<br/>publicKeyAlgorithm: RSA<br/>publicKeyRsaExponent: 65537<br/>signatureAlgorithm: SHA256withRSA<br/>subject: C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com<br/>subjectAlternativeNames: *.thespeedyou.com thespeedyou.com<br/>subjectCountry: IN<br/>subjectEmail: null<br/>subjectLocality: Pune<br/>subjectName: *.thespeedyou.com<br/>subjectOrg: Sears IT and Management Services India Pvt. Ltd.<br/>subjectOrgUnit: Management Services<br/>subjectState: Maharashtra<br/>serialNumber: 34287766128589078095374161204025316200<br/>validNotBefore: 2015-01-19T00:00:00Z<br/>validNotAfter: 2017-01-18T23:59:59Z<br/>version: 3<br/>publicKeyBits: 2048<br/>pemSha256: w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=<br/>pemSha1: p0y_sHlFdp5rPOw8aWrH2Qc331Q=<br/>publicKeyModulus: bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d<br/>publicKeySpki: 5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA= | 2020-09-23T01:44:37.415249Z |  | Insecure TLS at 52.6.192.223:443 | This service should not be visible on the public Internet. | 2b0ea80c-2277-34dd-9c55-005922ba640a | evidenceType: ScanEvidence<br/>timestamp: 2020-08-24T00:00:00Z<br/>ip: 52.6.192.223<br/>portNumber: 443<br/>portProtocol: TCP<br/>domain: null<br/>tlsVersion: TLS 1.2<br/>cipherSuite: TLS_ECDHE_RSA_WITH_RC4_128_SHA<br/>certificate: {"id": "81d4479a-4c66-3b05-a969-4b40ba07ba21", "md5Hash": "gdRHmkxmGwWpaUtAuge6IQ==", "issuer": "C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3", "issuerAlternativeNames": "", "issuerCountry": "US", "issuerEmail": null, "issuerLocality": null, "issuerName": "GeoTrust SSL CA - G3", "issuerOrg": "GeoTrust Inc.", "formattedIssuerOrg": null, "issuerOrgUnit": null, "issuerState": null, "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB", "publicKeyAlgorithm": "RSA", "publicKeyRsaExponent": 65537, "signatureAlgorithm": "SHA256withRSA", "subject": "C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com", "subjectAlternativeNames": "*.thespeedyou.com thespeedyou.com", "subjectCountry": "IN", "subjectEmail": null, "subjectLocality": "Pune", "subjectName": "*.thespeedyou.com", "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.", "subjectOrgUnit": "Management Services", "subjectState": "Maharashtra", "serialNumber": "34287766128589078095374161204025316200", "validNotBefore": "2015-01-19T00:00:00Z", "validNotAfter": "2017-01-18T23:59:59Z", "version": "3", "publicKeyBits": 2048, "pemSha256": "w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=", "pemSha1": "p0y_sHlFdp5rPOw8aWrH2Qc331Q=", "publicKeyModulus": "bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d", "publicKeySpki": "5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA="}<br/>configuration: {"_type": "WebServerConfiguration", "serverSoftware": "WSO2 Carbon Server", "applicationServerSoftware": "", "loadBalancer": "", "loadBalancerPool": "", "htmlPasswordField": "", "htmlPasswordAction": "", "httpAuthenticationMethod": "", "httpAuthenticationRealm": "", "httpHeaders": [{"name": "Set-Cookie", "value": "JSESSIONID=6E9656EFE98ED2DD7447C779504A4994; Path=/; Secure; HttpOnly"}, {"name": "X-FRAME-OPTIONS", "value": "DENY"}, {"name": "Content-Type", "value": "text/html;charset=UTF-8"}, {"name": "Content-Language", "value": "en-US"}, {"name": "Transfer-Encoding", "value": "chunked"}, {"name": "Vary", "value": "Accept-Encoding"}, {"name": "Date", "value": "xxxxxxxxxx"}, {"name": "Server", "value": "WSO2 Carbon Server"}], "certificateId": "74K3sPuBY6wi7US9poLZdg==", "httpStatusCode": "200", "hasServerSoftware": true, "hasApplicationServerSoftware": false, "isLoadBalancer": false, "hasUnencryptedLogin": false}<br/>exposureType: HTTP_SERVER<br/>exposureId: af2672a7-cf47-3a6d-9ecd-8c356d57d250<br/>serviceId: 355452a1-a39b-369e-9aad-4ca129ec9422<br/>serviceProperties: {"serviceProperties": [{"name": "ExpiredWhenScannedCertificate", "reason": "{\"validWhenScanned\":false}"}, {"name": "MissingCacheControlHeader", "reason": null}, {"name": "MissingContentSecurityPolicyHeader", "reason": null}, {"name": "MissingPublicKeyPinsHeader", "reason": null}, {"name": "MissingStrictTransportSecurityHeader", "reason": null}, {"name": "MissingXContentTypeOptionsHeader", "reason": null}, {"name": "MissingXXssProtectionHeader", "reason": null}, {"name": "ServerSoftware", "reason": "{\"serverSoftware\":\"WSO2 Carbon Server\"}"}, {"name": "WildcardCertificate", "reason": "{\"validWhenScanned\":false}"}]}<br/>geolocation: null<br/>discoveryType: Direct | 52.6.192.223 | id: InsecureTLS<br/>name: Insecure TLS<br/>archived: null | evidenceType: ScanEvidence<br/>timestamp: 2020-09-22T00:00:00Z<br/>ip: 52.6.192.223<br/>portNumber: 443<br/>portProtocol: TCP<br/>domain: null<br/>tlsVersion: TLS 1.2<br/>cipherSuite: TLS_ECDHE_RSA_WITH_RC4_128_SHA<br/>certificate: {"id": "81d4479a-4c66-3b05-a969-4b40ba07ba21", "md5Hash": "gdRHmkxmGwWpaUtAuge6IQ==", "issuer": "C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3", "issuerAlternativeNames": "", "issuerCountry": "US", "issuerEmail": null, "issuerLocality": null, "issuerName": "GeoTrust SSL CA - G3", "issuerOrg": "GeoTrust Inc.", "formattedIssuerOrg": null, "issuerOrgUnit": null, "issuerState": null, "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB", "publicKeyAlgorithm": "RSA", "publicKeyRsaExponent": 65537, "signatureAlgorithm": "SHA256withRSA", "subject": "C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com", "subjectAlternativeNames": "*.thespeedyou.com thespeedyou.com", "subjectCountry": "IN", "subjectEmail": null, "subjectLocality": "Pune", "subjectName": "*.thespeedyou.com", "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.", "subjectOrgUnit": "Management Services", "subjectState": "Maharashtra", "serialNumber": "34287766128589078095374161204025316200", "validNotBefore": "2015-01-19T00:00:00Z", "validNotAfter": "2017-01-18T23:59:59Z", "version": "3", "publicKeyBits": 2048, "pemSha256": "w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=", "pemSha1": "p0y_sHlFdp5rPOw8aWrH2Qc331Q=", "publicKeyModulus": "bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d", "publicKeySpki": "5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA="}<br/>configuration: {"_type": "WebServerConfiguration", "serverSoftware": "WSO2 Carbon Server", "applicationServerSoftware": "", "loadBalancer": "", "loadBalancerPool": "", "htmlPasswordField": "", "htmlPasswordAction": "", "httpAuthenticationMethod": "", "httpAuthenticationRealm": "", "httpHeaders": [{"name": "Set-Cookie", "value": "JSESSIONID=E5948E498E58CFB6413087A3D3D2908C; Path=/; Secure; HttpOnly"}, {"name": "Location", "value": "https://52.6.192.223/carbon/admin/index.jsp"}, {"name": "Content-Type", "value": "text/html;charset=UTF-8"}, {"name": "Content-Length", "value": "0"}, {"name": "Date", "value": "xxxxxxxxxx"}, {"name": "Server", "value": "WSO2 Carbon Server"}], "certificateId": "74K3sPuBY6wi7US9poLZdg==", "httpStatusCode": "302", "hasServerSoftware": true, "hasApplicationServerSoftware": false, "isLoadBalancer": false, "hasUnencryptedLogin": false}<br/>exposureType: HTTP_SERVER<br/>exposureId: af2672a7-cf47-3a6d-9ecd-8c356d57d250<br/>serviceId: 355452a1-a39b-369e-9aad-4ca129ec9422<br/>serviceProperties: {"serviceProperties": [{"name": "ExpiredWhenScannedCertificate", "reason": "{\"validWhenScanned\":false}"}, {"name": "ServerSoftware", "reason": "{\"serverSoftware\":\"WSO2 Carbon Server\"}"}, {"name": "WildcardCertificate", "reason": "{\"validWhenScanned\":false}"}]}<br/>geolocation: null<br/>discoveryType: Direct | 2020-12-07T12:02:49.335834Z | 443 | TCP | Medium | New | {'id': 'AWS', 'name': 'Amazon Web Services'} |


### expanse-get-issue-updates
***
Retrieve issue updates


#### Base Command

`expanse-get-issue-updates`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Expanse issue ID to retrieve updates for. | Required | 
| update_types | Update types (comma separated). Valid options are Assignee, Comment, Priority, ProgressStatus, ActivityStatus. | Optional | 
| created_after | Created after. | Optional | 
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IssueUpdate.created | Date |  | 
| Expanse.IssueUpdate.id | String |  | 
| Expanse.IssueUpdate.issueId | String |  | 
| Expanse.IssueUpdate.previousValue | String |  | 
| Expanse.IssueUpdate.updateType | String |  | 
| Expanse.IssueUpdate.user.username | String |  | 
| Expanse.IssueUpdate.value | String |  | 


#### Command Example
```!expanse-get-issue-updates issue_id="2b0ea80c-2277-34dd-9c55-005922ba640a" update_types="Comment,ProgressStatus" created_after="2020-12-07T09:34:36.20917328Z" limit="10"```

#### Context Example
```json
{
    "Expanse": {
        "IssueUpdate": [
            {
                "created": "2020-12-07T10:53:31.995739Z",
                "id": "7a3566eb-7c94-44b4-a08c-7285d5f58aca",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": "New",
                "updateType": "ProgressStatus",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "InProgress"
            },
            {
                "created": "2020-12-07T10:53:43.394272Z",
                "id": "056a8aaf-fa3e-4304-9f03-4c9033fa77ef",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": "InProgress",
                "updateType": "ProgressStatus",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "New"
            },
            {
                "created": "2020-12-07T11:03:05.724596Z",
                "id": "b51b0312-e2c0-41f3-b59c-fe5da4167ebd",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-07T11:03:08.966903Z",
                "id": "dc2e8b84-e86d-4ca6-b08a-f6d3c0d246cf",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": "New",
                "updateType": "ProgressStatus",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "InProgress"
            },
            {
                "created": "2020-12-07T11:03:17.680065Z",
                "id": "7d4801e1-f66b-4ebd-8cc9-ce6d9fa1b214",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": "InProgress",
                "updateType": "ProgressStatus",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "New"
            },
            {
                "created": "2020-12-07T12:02:37.202021Z",
                "id": "faf8840f-c41a-4049-9fd4-58e6bd039fc7",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-07T12:02:38.155620Z",
                "id": "1134f1d3-b31f-4846-8604-87145c76ad19",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": "New",
                "updateType": "ProgressStatus",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "InProgress"
            },
            {
                "created": "2020-12-07T12:02:49.335834Z",
                "id": "e9bb138a-affe-47bd-ac98-6595b9737d5e",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": "InProgress",
                "updateType": "ProgressStatus",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "New"
            },
            {
                "created": "2020-12-07T12:17:31.781217Z",
                "id": "dcf95534-851b-432b-afe6-8898f89043b2",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": null,
                "updateType": "Comment",
                "user": {
                    "username": "demo+api.external.vandelay+panw@expanseinc.com"
                },
                "value": "XSOAR Test Playbook Comment"
            },
            {
                "created": "2020-12-07T12:17:40.912083Z",
                "id": "49d86407-dc46-4122-b5b6-a9441a66b11b",
                "issueId": "2b0ea80c-2277-34dd-9c55-005922ba640a",
                "previousValue": "New",
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
>|created|id|issueId|previousValue|updateType|user|value|
>|---|---|---|---|---|---|---|
>| 2020-12-07T10:53:31.995739Z | 7a3566eb-7c94-44b4-a08c-7285d5f58aca | 2b0ea80c-2277-34dd-9c55-005922ba640a | New | ProgressStatus | username: demo+api.external.vandelay+panw@expanseinc.com | InProgress |
>| 2020-12-07T10:53:43.394272Z | 056a8aaf-fa3e-4304-9f03-4c9033fa77ef | 2b0ea80c-2277-34dd-9c55-005922ba640a | InProgress | ProgressStatus | username: demo+api.external.vandelay+panw@expanseinc.com | New |
>| 2020-12-07T11:03:05.724596Z | b51b0312-e2c0-41f3-b59c-fe5da4167ebd | 2b0ea80c-2277-34dd-9c55-005922ba640a |  | Comment | username: demo+api.external.vandelay+panw@expanseinc.com | XSOAR Test Playbook Comment |
>| 2020-12-07T11:03:08.966903Z | dc2e8b84-e86d-4ca6-b08a-f6d3c0d246cf | 2b0ea80c-2277-34dd-9c55-005922ba640a | New | ProgressStatus | username: demo+api.external.vandelay+panw@expanseinc.com | InProgress |
>| 2020-12-07T11:03:17.680065Z | 7d4801e1-f66b-4ebd-8cc9-ce6d9fa1b214 | 2b0ea80c-2277-34dd-9c55-005922ba640a | InProgress | ProgressStatus | username: demo+api.external.vandelay+panw@expanseinc.com | New |
>| 2020-12-07T12:02:37.202021Z | faf8840f-c41a-4049-9fd4-58e6bd039fc7 | 2b0ea80c-2277-34dd-9c55-005922ba640a |  | Comment | username: demo+api.external.vandelay+panw@expanseinc.com | XSOAR Test Playbook Comment |
>| 2020-12-07T12:02:38.155620Z | 1134f1d3-b31f-4846-8604-87145c76ad19 | 2b0ea80c-2277-34dd-9c55-005922ba640a | New | ProgressStatus | username: demo+api.external.vandelay+panw@expanseinc.com | InProgress |
>| 2020-12-07T12:02:49.335834Z | e9bb138a-affe-47bd-ac98-6595b9737d5e | 2b0ea80c-2277-34dd-9c55-005922ba640a | InProgress | ProgressStatus | username: demo+api.external.vandelay+panw@expanseinc.com | New |
>| 2020-12-07T12:17:31.781217Z | dcf95534-851b-432b-afe6-8898f89043b2 | 2b0ea80c-2277-34dd-9c55-005922ba640a |  | Comment | username: demo+api.external.vandelay+panw@expanseinc.com | XSOAR Test Playbook Comment |
>| 2020-12-07T12:17:40.912083Z | 49d86407-dc46-4122-b5b6-a9441a66b11b | 2b0ea80c-2277-34dd-9c55-005922ba640a | New | ProgressStatus | username: demo+api.external.vandelay+panw@expanseinc.com | InProgress |


### expanse-get-issue-comments
***
Retrieve issue comments (subset of updates)


#### Base Command

`expanse-get-issue-comments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Expanse issue ID to retrieve comments for. | Required | 
| created_after | Created after. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IssueComment.created | Date |  | 
| Expanse.IssueComment.id | String |  | 
| Expanse.IssueComment.issueId | String |  | 
| Expanse.IssueComment.previousValue | String |  | 
| Expanse.IssueComment.updateType | String |  | 
| Expanse.IssueComment.user.username | String |  | 
| Expanse.IssueComment.value | String |  | 


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
            }
        ]
    }
}
```

#### Human Readable Output

>### Expanse Issue Comments
>|User|Value|Created|
>|---|---|---|
>| demo+api.external.vandelay+panw@expanseinc.com | XSOAR Test Playbook Comment | 2020-12-07T10:53:31.168649Z |
>| demo+api.external.vandelay+panw@expanseinc.com | XSOAR Test Playbook Comment | 2020-12-07T11:03:05.724596Z |
>| demo+api.external.vandelay+panw@expanseinc.com | XSOAR Test Playbook Comment | 2020-12-07T12:02:37.202021Z |
>| demo+api.external.vandelay+panw@expanseinc.com | XSOAR Test Playbook Comment | 2020-12-07T12:17:31.781217Z |


### expanse-update-issue
***
Update Expanse issue.


#### Base Command

`expanse-update-issue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue ID to update. | Required | 
| update_type | Update type. Possible values are: Assignee, Comment, Priority, ProgressStatus. | Required | 
| value | New value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IssueUpdate.created | Date |  | 
| Expanse.IssueUpdate.id | String |  | 
| Expanse.IssueUpdate.issueId | String |  | 
| Expanse.IssueUpdate.previousValue | String |  | 
| Expanse.IssueUpdate.updateType | String |  | 
| Expanse.IssueUpdate.user.username | String |  | 
| Expanse.IssueUpdate.value | String |  | 


#### Command Example
```!expanse-update-issue issue_id="2b0ea80c-2277-34dd-9c55-005922ba640a" update_type="Comment" value="XSOAR Test Playbook Comment"```

#### Context Example
```json
{
    "Expanse": {
        "IssueUpdate": {
            "created": "2020-12-07T12:17:31.781217Z",
            "id": "dcf95534-851b-432b-afe6-8898f89043b2",
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
>|created|id|issueId|previousValue|updateType|user|value|
>|---|---|---|---|---|---|---|
>| 2020-12-07T12:17:31.781217Z | dcf95534-851b-432b-afe6-8898f89043b2 | 2b0ea80c-2277-34dd-9c55-005922ba640a |  | Comment | username: demo+api.external.vandelay+panw@expanseinc.com | XSOAR Test Playbook Comment |


### expanse-get-issue
***
Retrieve issue by ID


#### Base Command

`expanse-get-issue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Issue ID to retrieve. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Issue.activityStatus | String |  | 
| Expanse.Issue.assets.assetKey | String |  | 
| Expanse.Issue.assets.assetType | String |  | 
| Expanse.Issue.assets.displayName | String |  | 
| Expanse.Issue.assets.id | String |  | 
| Expanse.Issue.assigneeUsername | String |  | 
| Expanse.Issue.businessUnits.id | String |  | 
| Expanse.Issue.businessUnits.name | String |  | 
| Expanse.Issue.category | String |  | 
| Expanse.Issue.certificate.formattedIssuerOrg | String |  | 
| Expanse.Issue.certificate.id | String |  | 
| Expanse.Issue.certificate.issuer | String |  | 
| Expanse.Issue.certificate.issuerAlternativeNames | String |  | 
| Expanse.Issue.certificate.issuerCountry | String |  | 
| Expanse.Issue.certificate.issuerEmail | String |  | 
| Expanse.Issue.certificate.issuerLocality | String |  | 
| Expanse.Issue.certificate.issuerName | String |  | 
| Expanse.Issue.certificate.issuerOrg | String |  | 
| Expanse.Issue.certificate.issuerOrgUnit | String |  | 
| Expanse.Issue.certificate.issuerState | String |  | 
| Expanse.Issue.certificate.md5Hash | String |  | 
| Expanse.Issue.certificate.pemSha1 | String |  | 
| Expanse.Issue.certificate.pemSha256 | String |  | 
| Expanse.Issue.certificate.publicKey | String |  | 
| Expanse.Issue.certificate.publicKeyAlgorithm | String |  | 
| Expanse.Issue.certificate.publicKeyBits | Number |  | 
| Expanse.Issue.certificate.publicKeyModulus | String |  | 
| Expanse.Issue.certificate.publicKeyRsaExponent | Number |  | 
| Expanse.Issue.certificate.publicKeySpki | String |  | 
| Expanse.Issue.certificate.serialNumber | String |  | 
| Expanse.Issue.certificate.signatureAlgorithm | String |  | 
| Expanse.Issue.certificate.subject | String |  | 
| Expanse.Issue.certificate.subjectAlternativeNames | String |  | 
| Expanse.Issue.certificate.subjectCountry | String |  | 
| Expanse.Issue.certificate.subjectEmail | String |  | 
| Expanse.Issue.certificate.subjectLocality | String |  | 
| Expanse.Issue.certificate.subjectName | String |  | 
| Expanse.Issue.certificate.subjectOrg | String |  | 
| Expanse.Issue.certificate.subjectOrgUnit | String |  | 
| Expanse.Issue.certificate.subjectState | String |  | 
| Expanse.Issue.certificate.validNotAfter | Date |  | 
| Expanse.Issue.certificate.validNotBefore | Date |  | 
| Expanse.Issue.certificate.version | String |  | 
| Expanse.Issue.created | Date |  | 
| Expanse.Issue.headline | String |  | 
| Expanse.Issue.helpText | String |  | 
| Expanse.Issue.id | String |  | 
| Expanse.Issue.initialEvidence.certificate.formattedIssuerOrg | String |  | 
| Expanse.Issue.initialEvidence.certificate.id | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuer | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerAlternativeNames | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerCountry | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerEmail | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerLocality | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerName | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerOrg | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerOrgUnit | String |  | 
| Expanse.Issue.initialEvidence.certificate.issuerState | String |  | 
| Expanse.Issue.initialEvidence.certificate.md5Hash | String |  | 
| Expanse.Issue.initialEvidence.certificate.pemSha1 | String |  | 
| Expanse.Issue.initialEvidence.certificate.pemSha256 | String |  | 
| Expanse.Issue.initialEvidence.certificate.publicKey | String |  | 
| Expanse.Issue.initialEvidence.certificate.publicKeyAlgorithm | String |  | 
| Expanse.Issue.initialEvidence.certificate.publicKeyBits | Number |  | 
| Expanse.Issue.initialEvidence.certificate.publicKeyModulus | String |  | 
| Expanse.Issue.initialEvidence.certificate.publicKeyRsaExponent | Number |  | 
| Expanse.Issue.initialEvidence.certificate.publicKeySpki | String |  | 
| Expanse.Issue.initialEvidence.certificate.serialNumber | String |  | 
| Expanse.Issue.initialEvidence.certificate.signatureAlgorithm | String |  | 
| Expanse.Issue.initialEvidence.certificate.subject | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectAlternativeNames | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectCountry | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectEmail | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectLocality | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectName | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectOrg | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectOrgUnit | String |  | 
| Expanse.Issue.initialEvidence.certificate.subjectState | String |  | 
| Expanse.Issue.initialEvidence.certificate.validNotAfter | Date |  | 
| Expanse.Issue.initialEvidence.certificate.validNotBefore | Date |  | 
| Expanse.Issue.initialEvidence.certificate.version | String |  | 
| Expanse.Issue.initialEvidence.cipherSuite | String |  | 
| Expanse.Issue.initialEvidence.configuration._type | String |  | 
| Expanse.Issue.initialEvidence.configuration.validWhenScanned | Boolean |  | 
| Expanse.Issue.initialEvidence.discoveryType | String |  | 
| Expanse.Issue.initialEvidence.domain | String |  | 
| Expanse.Issue.initialEvidence.evidenceType | String |  | 
| Expanse.Issue.initialEvidence.exposureId | String |  | 
| Expanse.Issue.initialEvidence.exposureType | String |  | 
| Expanse.Issue.initialEvidence.geolocation.latitude | Number |  | 
| Expanse.Issue.initialEvidence.geolocation.longitude | Number |  | 
| Expanse.Issue.initialEvidence.geolocation.city | String |  | 
| Expanse.Issue.initialEvidence.geolocation.regionCode | String |  | 
| Expanse.Issue.initialEvidence.geolocation.countryCode | String |  | 
| Expanse.Issue.initialEvidence.ip | String |  | 
| Expanse.Issue.initialEvidence.portNumber | Number |  | 
| Expanse.Issue.initialEvidence.portProtocol | String |  | 
| Expanse.Issue.initialEvidence.serviceId | String |  | 
| Expanse.Issue.initialEvidence.serviceProperties.serviceProperties.name | String |  | 
| Expanse.Issue.initialEvidence.serviceProperties.serviceProperties.reason | String |  | 
| Expanse.Issue.initialEvidence.timestamp | Date |  | 
| Expanse.Issue.initialEvidence.tlsVersion | String |  | 
| Expanse.Issue.ip | String |  | 
| Expanse.Issue.issueType.id | String |  | 
| Expanse.Issue.issueType.name | String |  | 
| Expanse.Issue.latestEvidence.certificate.formattedIssuerOrg | String |  | 
| Expanse.Issue.latestEvidence.certificate.id | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuer | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerAlternativeNames | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerCountry | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerEmail | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerLocality | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerName | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerOrg | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerOrgUnit | String |  | 
| Expanse.Issue.latestEvidence.certificate.issuerState | String |  | 
| Expanse.Issue.latestEvidence.certificate.md5Hash | String |  | 
| Expanse.Issue.latestEvidence.certificate.pemSha1 | String |  | 
| Expanse.Issue.latestEvidence.certificate.pemSha256 | String |  | 
| Expanse.Issue.latestEvidence.certificate.publicKey | String |  | 
| Expanse.Issue.latestEvidence.certificate.publicKeyAlgorithm | String |  | 
| Expanse.Issue.latestEvidence.certificate.publicKeyBits | Number |  | 
| Expanse.Issue.latestEvidence.certificate.publicKeyModulus | String |  | 
| Expanse.Issue.latestEvidence.certificate.publicKeyRsaExponent | Number |  | 
| Expanse.Issue.latestEvidence.certificate.publicKeySpki | String |  | 
| Expanse.Issue.latestEvidence.certificate.serialNumber | String |  | 
| Expanse.Issue.latestEvidence.certificate.signatureAlgorithm | String |  | 
| Expanse.Issue.latestEvidence.certificate.subject | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectAlternativeNames | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectCountry | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectEmail | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectLocality | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectName | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectOrg | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectOrgUnit | String |  | 
| Expanse.Issue.latestEvidence.certificate.subjectState | String |  | 
| Expanse.Issue.latestEvidence.certificate.validNotAfter | Date |  | 
| Expanse.Issue.latestEvidence.certificate.validNotBefore | Date |  | 
| Expanse.Issue.latestEvidence.certificate.version | String |  | 
| Expanse.Issue.latestEvidence.cipherSuite | String |  | 
| Expanse.Issue.latestEvidence.configuration._type | String |  | 
| Expanse.Issue.latestEvidence.configuration.validWhenScanned | Boolean |  | 
| Expanse.Issue.latestEvidence.discoveryType | String |  | 
| Expanse.Issue.latestEvidence.domain | String |  | 
| Expanse.Issue.latestEvidence.evidenceType | String |  | 
| Expanse.Issue.latestEvidence.exposureId | String |  | 
| Expanse.Issue.latestEvidence.exposureType | String |  | 
| Expanse.Issue.latestEvidence.geolocation.latitude | Number |  | 
| Expanse.Issue.latestEvidence.geolocation.longitude | Number |  | 
| Expanse.Issue.latestEvidence.geolocation.city | String |  | 
| Expanse.Issue.latestEvidence.geolocation.regionCode | String |  | 
| Expanse.Issue.latestEvidence.geolocation.countryCode | String |  | 
| Expanse.Issue.latestEvidence.ip | String |  | 
| Expanse.Issue.latestEvidence.portNumber | Number |  | 
| Expanse.Issue.latestEvidence.portProtocol | String |  | 
| Expanse.Issue.latestEvidence.serviceId | String |  | 
| Expanse.Issue.latestEvidence.serviceProperties.serviceProperties.name | String |  | 
| Expanse.Issue.latestEvidence.serviceProperties.serviceProperties.reason | String |  | 
| Expanse.Issue.latestEvidence.timestamp | Date |  | 
| Expanse.Issue.latestEvidence.tlsVersion | String |  | 
| Expanse.Issue.modified | Date |  | 
| Expanse.Issue.portNumber | Number |  | 
| Expanse.Issue.portProtocol | String |  | 
| Expanse.Issue.priority | String |  | 
| Expanse.Issue.progressStatus | String |  | 
| Expanse.Issue.providers.id | String |  | 
| Expanse.Issue.providers.name | String |  | 


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
                "discoveryType": "Direct",
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
                "discoveryType": "Direct",
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
            "modified": "2020-12-07T12:17:40.912083Z",
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

>### Results
>|activityStatus|annotations|assets|assigneeUsername|businessUnits|category|certificate|created|domain|headline|helpText|id|initialEvidence|ip|issueType|latestEvidence|modified|portNumber|portProtocol|priority|progressStatus|providers|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Active | tags:  | {'id': '724a1137-ee3f-381f-95f2-ea0441db22d0', 'assetKey': 'gdRHmkxmGwWpaUtAuge6IQ==', 'assetType': 'Certificate', 'displayName': '*.thespeedyou.com'} | Unassigned | {'id': 'f738ace6-f451-4f31-898d-a12afa204b2a', 'name': 'PANW VanDelay Dev'} | Attack Surface Reduction | id: 81d4479a-4c66-3b05-a969-4b40ba07ba21<br/>md5Hash: gdRHmkxmGwWpaUtAuge6IQ==<br/>issuer: C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3<br/>issuerAlternativeNames: <br/>issuerCountry: US<br/>issuerEmail: null<br/>issuerLocality: null<br/>issuerName: GeoTrust SSL CA - G3<br/>issuerOrg: GeoTrust Inc.<br/>formattedIssuerOrg: GeoTrust<br/>issuerOrgUnit: null<br/>issuerState: null<br/>publicKey: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB<br/>publicKeyAlgorithm: RSA<br/>publicKeyRsaExponent: 65537<br/>signatureAlgorithm: SHA256withRSA<br/>subject: C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com<br/>subjectAlternativeNames: *.thespeedyou.com thespeedyou.com<br/>subjectCountry: IN<br/>subjectEmail: null<br/>subjectLocality: Pune<br/>subjectName: *.thespeedyou.com<br/>subjectOrg: Sears IT and Management Services India Pvt. Ltd.<br/>subjectOrgUnit: Management Services<br/>subjectState: Maharashtra<br/>serialNumber: 34287766128589078095374161204025316200<br/>validNotBefore: 2015-01-19T00:00:00Z<br/>validNotAfter: 2017-01-18T23:59:59Z<br/>version: 3<br/>publicKeyBits: 2048<br/>pemSha256: w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=<br/>pemSha1: p0y_sHlFdp5rPOw8aWrH2Qc331Q=<br/>publicKeyModulus: bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d<br/>publicKeySpki: 5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA= | 2020-09-23T01:44:37.415249Z |  | Insecure TLS at 52.6.192.223:443 | This service should not be visible on the public Internet. | 2b0ea80c-2277-34dd-9c55-005922ba640a | evidenceType: ScanEvidence<br/>timestamp: 2020-08-24T00:00:00Z<br/>ip: 52.6.192.223<br/>portNumber: 443<br/>portProtocol: TCP<br/>domain: null<br/>tlsVersion: TLS 1.2<br/>cipherSuite: TLS_ECDHE_RSA_WITH_RC4_128_SHA<br/>certificate: {"id": "81d4479a-4c66-3b05-a969-4b40ba07ba21", "md5Hash": "gdRHmkxmGwWpaUtAuge6IQ==", "issuer": "C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3", "issuerAlternativeNames": "", "issuerCountry": "US", "issuerEmail": null, "issuerLocality": null, "issuerName": "GeoTrust SSL CA - G3", "issuerOrg": "GeoTrust Inc.", "formattedIssuerOrg": null, "issuerOrgUnit": null, "issuerState": null, "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB", "publicKeyAlgorithm": "RSA", "publicKeyRsaExponent": 65537, "signatureAlgorithm": "SHA256withRSA", "subject": "C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com", "subjectAlternativeNames": "*.thespeedyou.com thespeedyou.com", "subjectCountry": "IN", "subjectEmail": null, "subjectLocality": "Pune", "subjectName": "*.thespeedyou.com", "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.", "subjectOrgUnit": "Management Services", "subjectState": "Maharashtra", "serialNumber": "34287766128589078095374161204025316200", "validNotBefore": "2015-01-19T00:00:00Z", "validNotAfter": "2017-01-18T23:59:59Z", "version": "3", "publicKeyBits": 2048, "pemSha256": "w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=", "pemSha1": "p0y_sHlFdp5rPOw8aWrH2Qc331Q=", "publicKeyModulus": "bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d", "publicKeySpki": "5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA="}<br/>configuration: {"_type": "WebServerConfiguration", "serverSoftware": "WSO2 Carbon Server", "applicationServerSoftware": "", "loadBalancer": "", "loadBalancerPool": "", "htmlPasswordField": "", "htmlPasswordAction": "", "httpAuthenticationMethod": "", "httpAuthenticationRealm": "", "httpHeaders": [{"name": "Set-Cookie", "value": "JSESSIONID=6E9656EFE98ED2DD7447C779504A4994; Path=/; Secure; HttpOnly"}, {"name": "X-FRAME-OPTIONS", "value": "DENY"}, {"name": "Content-Type", "value": "text/html;charset=UTF-8"}, {"name": "Content-Language", "value": "en-US"}, {"name": "Transfer-Encoding", "value": "chunked"}, {"name": "Vary", "value": "Accept-Encoding"}, {"name": "Date", "value": "xxxxxxxxxx"}, {"name": "Server", "value": "WSO2 Carbon Server"}], "certificateId": "74K3sPuBY6wi7US9poLZdg==", "httpStatusCode": "200", "hasServerSoftware": true, "hasApplicationServerSoftware": false, "isLoadBalancer": false, "hasUnencryptedLogin": false}<br/>exposureType: HTTP_SERVER<br/>exposureId: af2672a7-cf47-3a6d-9ecd-8c356d57d250<br/>serviceId: 355452a1-a39b-369e-9aad-4ca129ec9422<br/>serviceProperties: {"serviceProperties": [{"name": "ExpiredWhenScannedCertificate", "reason": "{\"validWhenScanned\":false}"}, {"name": "MissingCacheControlHeader", "reason": null}, {"name": "MissingContentSecurityPolicyHeader", "reason": null}, {"name": "MissingPublicKeyPinsHeader", "reason": null}, {"name": "MissingStrictTransportSecurityHeader", "reason": null}, {"name": "MissingXContentTypeOptionsHeader", "reason": null}, {"name": "MissingXXssProtectionHeader", "reason": null}, {"name": "ServerSoftware", "reason": "{\"serverSoftware\":\"WSO2 Carbon Server\"}"}, {"name": "WildcardCertificate", "reason": "{\"validWhenScanned\":false}"}]}<br/>geolocation: null<br/>discoveryType: Direct | 52.6.192.223 | id: InsecureTLS<br/>name: Insecure TLS<br/>archived: null | evidenceType: ScanEvidence<br/>timestamp: 2020-09-22T00:00:00Z<br/>ip: 52.6.192.223<br/>portNumber: 443<br/>portProtocol: TCP<br/>domain: null<br/>tlsVersion: TLS 1.2<br/>cipherSuite: TLS_ECDHE_RSA_WITH_RC4_128_SHA<br/>certificate: {"id": "81d4479a-4c66-3b05-a969-4b40ba07ba21", "md5Hash": "gdRHmkxmGwWpaUtAuge6IQ==", "issuer": "C=US,O=GeoTrust Inc.,CN=GeoTrust SSL CA - G3", "issuerAlternativeNames": "", "issuerCountry": "US", "issuerEmail": null, "issuerLocality": null, "issuerName": "GeoTrust SSL CA - G3", "issuerOrg": "GeoTrust Inc.", "formattedIssuerOrg": null, "issuerOrgUnit": null, "issuerState": null, "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv8cw0HvfztMNtUU6tK7TSo0Ij1k+MwL+cYSTEl7f5Lc/v0Db9Bg3YI7ALlw3VLnJ3oWxiwwCJMLbOBmVr7tSrPBU7dFUh0UIS6LulVYe16fKb1MBUmMq9WckGHF6+bnXrP/xb9X77RiqP0HhRbv7s/3m2ZruIHZ334mm1shnO65vyCvrOHXZQWl8SSk7fHBebRgEcqBM+w0VKV1Uy6U3b7AKWAsbibEHHCuGYFV+OaJxO7/18tJBNwJSX7lDnMOOxoCY2Jcafr/j5gb8O75OH2uxyg2bV7huwm7obYWP9Glw6b9KMdl55CsQHPNW3NW1AnCbAJFvDszl+Op96XNcHQIDAQAB", "publicKeyAlgorithm": "RSA", "publicKeyRsaExponent": 65537, "signatureAlgorithm": "SHA256withRSA", "subject": "C=IN,ST=Maharashtra,L=Pune,O=Sears IT and Management Services India Pvt. Ltd.,OU=Management Services,CN=*.thespeedyou.com", "subjectAlternativeNames": "*.thespeedyou.com thespeedyou.com", "subjectCountry": "IN", "subjectEmail": null, "subjectLocality": "Pune", "subjectName": "*.thespeedyou.com", "subjectOrg": "Sears IT and Management Services India Pvt. Ltd.", "subjectOrgUnit": "Management Services", "subjectState": "Maharashtra", "serialNumber": "34287766128589078095374161204025316200", "validNotBefore": "2015-01-19T00:00:00Z", "validNotAfter": "2017-01-18T23:59:59Z", "version": "3", "publicKeyBits": 2048, "pemSha256": "w_LuhDoJupBuXxDW5gzATkB6TL0IsdQK09fuQsLGj-g=", "pemSha1": "p0y_sHlFdp5rPOw8aWrH2Qc331Q=", "publicKeyModulus": "bfc730d07bdfced30db5453ab4aed34a8d088f593e3302fe718493125edfe4b73fbf40dbf41837608ec02e5c3754b9c9de85b18b0c0224c2db381995afbb52acf054edd1548745084ba2ee95561ed7a7ca6f530152632af5672418717af9b9d7acfff16fd5fbed18aa3f41e145bbfbb3fde6d99aee207677df89a6d6c8673bae6fc82beb3875d941697c49293b7c705e6d180472a04cfb0d15295d54cba5376fb00a580b1b89b1071c2b8660557e39a2713bbff5f2d2413702525fb9439cc38ec68098d8971a7ebfe3e606fc3bbe4e1f6bb1ca0d9b57b86ec26ee86d858ff46970e9bf4a31d979e42b101cf356dcd5b502709b00916f0ecce5f8ea7de9735c1d", "publicKeySpki": "5yD3VMYLV6A4CelOIlekrA1ByPGO769aG16XHfMixnA="}<br/>configuration: {"_type": "WebServerConfiguration", "serverSoftware": "WSO2 Carbon Server", "applicationServerSoftware": "", "loadBalancer": "", "loadBalancerPool": "", "htmlPasswordField": "", "htmlPasswordAction": "", "httpAuthenticationMethod": "", "httpAuthenticationRealm": "", "httpHeaders": [{"name": "Set-Cookie", "value": "JSESSIONID=E5948E498E58CFB6413087A3D3D2908C; Path=/; Secure; HttpOnly"}, {"name": "Location", "value": "https://52.6.192.223/carbon/admin/index.jsp"}, {"name": "Content-Type", "value": "text/html;charset=UTF-8"}, {"name": "Content-Length", "value": "0"}, {"name": "Date", "value": "xxxxxxxxxx"}, {"name": "Server", "value": "WSO2 Carbon Server"}], "certificateId": "74K3sPuBY6wi7US9poLZdg==", "httpStatusCode": "302", "hasServerSoftware": true, "hasApplicationServerSoftware": false, "isLoadBalancer": false, "hasUnencryptedLogin": false}<br/>exposureType: HTTP_SERVER<br/>exposureId: af2672a7-cf47-3a6d-9ecd-8c356d57d250<br/>serviceId: 355452a1-a39b-369e-9aad-4ca129ec9422<br/>serviceProperties: {"serviceProperties": [{"name": "ExpiredWhenScannedCertificate", "reason": "{\"validWhenScanned\":false}"}, {"name": "ServerSoftware", "reason": "{\"serverSoftware\":\"WSO2 Carbon Server\"}"}, {"name": "WildcardCertificate", "reason": "{\"validWhenScanned\":false}"}]}<br/>geolocation: null<br/>discoveryType: Direct | 2020-12-07T12:17:40.912083Z | 443 | TCP | Medium | InProgress | {'id': 'AWS', 'name': 'Amazon Web Services'} |


### expanse-list-businessunits
***
List available business units


#### Base Command

`expanse-list-businessunits`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.BusinessUnit.id | String | Business Unit ID | 
| Expanse.BusinessUnit.name | String | Business Unit Name | 


#### Command Example
```!expanse-list-businessunits limit="5"```

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
            },
            {
                "id": "f738ace6-f451-4f31-898d-a12afa204b2a",
                "name": "PANW VanDelay Dev"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|id|name|
>|---|---|
>| c4de7fad-cde1-46cf-8725-a5999533db59 | PANW VanDelay Import-Export Dev |
>| c94c50ca-124f-4983-8da5-1756138e2252 | PANW Acme Latex Supply Dev |
>| f738ace6-f451-4f31-898d-a12afa204b2a | PANW VanDelay Dev |


### expanse-list-providers
***
List available providers


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
| Expanse.Provider.name | String | Provider Name | 


#### Command Example
```!expanse-list-providers limit="5"```

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
            },
            {
                "id": "Cheetahmail",
                "name": "Cheetahmail"
            },
            {
                "id": "ChinaMobile",
                "name": "China Mobile"
            },
            {
                "id": "Chinanet",
                "name": "Chinanet"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|id|name|
>|---|---|
>| AlibabaCloud | Alibaba Cloud |
>| AWS | Amazon Web Services |
>| Cheetahmail | Cheetahmail |
>| ChinaMobile | China Mobile |
>| Chinanet | Chinanet |


### expanse-list-tags
***
List available tags


#### Base Command

`expanse-list-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Tag.created | Date | Tag created timestamp. | 
| Expanse.Tag.description | String | Tag description. | 
| Expanse.Tag.disabled | Boolean | Whether Tag is disabled. | 
| Expanse.Tag.id | String | Tag ID. | 
| Expanse.Tag.modified | Date | Tag last modified timestamp. | 
| Expanse.Tag.name | String | Tag name. | 
| Expanse.Tag.tenantId | String | Associated Tenant ID. | 


#### Command Example
```!expanse-list-tags limit="100"```

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
>|created|description|disabled|id|modified|name|tenantId|
>|---|---|---|---|---|---|---|
>| 2020-12-07T12:18:38.047826Z | XSOAR Test Tag | false | a96792e9-ac04-338e-bd7f-467e395c3739 | 2020-12-07T12:18:38.047826Z | xsoar-test-tag-new | f738ace6-f451-4f31-898d-a12afa204b2a |
>| 2020-12-07T09:42:40.456398Z | XSOAR Test Playbook Tag | false | e00bc79d-d367-36f4-824c-042836fef5fc | 2020-12-07T09:42:40.456398Z | xsoar-test-pb-tag | f738ace6-f451-4f31-898d-a12afa204b2a |


### expanse-assign-tags-to-asset
***
Assign tags to Asset.


#### Base Command

`expanse-assign-tags-to-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | Asset type. Possible values are: IpRange, Certificate, Domain. | Required | 
| asset_id | Asset ID. | Required | 
| tags | IDs of the tags. | Optional | 
| tagnames | Names of the tags. | Optional | 


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
Unassign tags from Asset.


#### Base Command

`expanse-unassign-tags-from-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | Asset type. Possible values are: IpRange, Certificate, Domain. | Required | 
| asset_id | Asset ID. | Required | 
| tags | IDs of the tags. | Optional | 
| tagnames | Names of the tags. | Optional | 


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
Assign tags to IP Range.


#### Base Command

`expanse-assign-tags-to-iprange`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | IP Range ID. | Required | 
| tags | IDs of the tags. | Optional | 
| tagnames | Names of the tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!expanse-assign-tags-to-iprange asset_id="0a8f44f9-05dc-42a3-a395-c83dad49fadf" tagnames="xsoar-test-pb-tag"```

#### Context Example
```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-unassign-tags-from-iprange
***
Unassign tags from IP Range.


#### Base Command

`expanse-unassign-tags-from-iprange`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | IP Range ID. | Required | 
| tags | IDs of the tags. | Optional | 
| tagnames | Names of the tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!expanse-unassign-tags-from-iprange asset_id="0a8f44f9-05dc-42a3-a395-c83dad49fadf" tagnames="xsoar-test-pb-tag"```

#### Context Example
```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-assign-tags-to-certificate
***
Assign tags to certificate.


#### Base Command

`expanse-assign-tags-to-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Certificate ID. | Required | 
| tags | IDs of the tags. | Optional | 
| tagnames | Names of the tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!expanse-assign-tags-to-certificate asset_id="30a111ae-39e2-3b82-b459-249bac0c6065" tagnames="xsoar-test-pb-tag"```

#### Context Example
```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-unassign-tags-from-certificate
***
Unassign tags from certificate.


#### Base Command

`expanse-unassign-tags-from-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Certificate ID. | Required | 
| tags | IDs of the tags. | Optional | 
| tagnames | Names of the tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!expanse-unassign-tags-from-certificate asset_id="30a111ae-39e2-3b82-b459-249bac0c6065" tagnames="xsoar-test-pb-tag"```

#### Context Example
```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-assign-tags-to-domain
***
Assign tags to domain.


#### Base Command

`expanse-assign-tags-to-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Domain ID. | Required | 
| tags | IDs of the tags. | Optional | 
| tagnames | Names of the tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!expanse-assign-tags-to-domain asset_id="142194a1-f443-3878-8dcc-540f4061c5f5" tagnames="xsoar-test-pb-tag"```

#### Context Example
```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-unassign-tags-from-domain
***
Unassign tags from domain.


#### Base Command

`expanse-unassign-tags-from-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Domain ID. | Required | 
| tags | IDs of the tags. | Optional | 
| tagnames | Names of the tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |


#### Command Example
```!expanse-unassign-tags-from-domain asset_id="142194a1-f443-3878-8dcc-540f4061c5f5" tagnames="xsoar-test-pb-tag"```

#### Context Example
```json
{}
```

#### Human Readable Output

>Operation complete

### expanse-create-tag
***
Create a new tag in Expanse.


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
| Expanse.Tag.created | Date | Tag created timestamp. | 
| Expanse.Tag.description | String | Tag description. | 
| Expanse.Tag.disabled | Boolean |  | 
| Expanse.Tag.id | String | Tag ID. | 
| Expanse.Tag.modified | Date | Tag last modified timestamp. | 
| Expanse.Tag.name | String | Tag name. | 
| Expanse.Tag.tenantId | String | Associated Tenant ID. | 


#### Command Example
```!expanse-create-tag name="xsoar-test-tag-new" description="XSOAR Test Tag"```

#### Context Example
```json
{
    "Expanse": {
        "Tag": {
            "created": "2020-12-07T12:18:38.047826Z",
            "description": "XSOAR Test Tag",
            "disabled": false,
            "id": "a96792e9-ac04-338e-bd7f-467e395c3739",
            "modified": "2020-12-07T12:18:38.047826Z",
            "name": "xsoar-test-tag-new",
            "tenantId": "f738ace6-f451-4f31-898d-a12afa204b2a"
        }
    }
}
```

#### Human Readable Output

>### Results
>|created|description|disabled|id|modified|name|tenantId|
>|---|---|---|---|---|---|---|
>| 2020-12-07T12:18:38.047826Z | XSOAR Test Tag | false | a96792e9-ac04-338e-bd7f-467e395c3739 | 2020-12-07T12:18:38.047826Z | xsoar-test-tag-new | f738ace6-f451-4f31-898d-a12afa204b2a |


### expanse-get-iprange
***
Get ip-range by id or search ip-ranges


#### Base Command

`expanse-get-iprange`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | IP Range ID. | Optional | 
| businessunits | Business Unit IDs. | Optional | 
| businessunitnames | Business Unit Names. | Optional | 
| inet | Search for a given IP, CIDR or IP Range. | Optional | 
| limit | Maximum number of entries to retrieve. | Optional | 
| tags | Tag IDs. | Optional | 
| tagnames | Tag Names. | Optional | 
| include | Include "none" or any of the following options (comma separated) - annotations, severityCounts, attributionReasons, relatedRegistrationInformation, locationInformation. Default is none. | Optional | 
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IPRange.annotations.additionalNotes | String |  | 
| Expanse.IPRange.annotations.tags | Unknown |  | 
| Expanse.IPRange.attributionReasons.reason | String | A reason why Expanse attributed the given resource to your organization. | 
| Expanse.IPRange.businessUnits.id | String | ID of the organization or subsidiary which Expanse has defined as being part of your public organizational structure. | 
| Expanse.IPRange.businessUnits.name | String | Name of the organization or subsidiary which Expanse has defined as being part of your public organizational structure. | 
| Expanse.IPRange.cidr | String |  | 
| Expanse.IPRange.created | Date |  | 
| Expanse.IPRange.id | String | IP Range unique identifier. | 
| Expanse.IPRange.ipVersion | String | IP version \(4 or 6\). | 
| Expanse.IPRange.locationInformation.geolocation.city | String | Geolocation city. | 
| Expanse.IPRange.locationInformation.geolocation.countryCode | String | Geolocation country code. | 
| Expanse.IPRange.locationInformation.geolocation.latitude | Number | Geolocation latitude. | 
| Expanse.IPRange.locationInformation.geolocation.longitude | Number | Geolocation longitude. | 
| Expanse.IPRange.locationInformation.geolocation.regionCode | String | Geolocation region code. | 
| Expanse.IPRange.locationInformation.ip | String | Location of the IP address. | 
| Expanse.IPRange.modified | Date |  | 
| Expanse.IPRange.rangeIntroduced | Date | Date when the IP range was added to Expanse. | 
| Expanse.IPRange.rangeSize | Number | IP range size. | 
| Expanse.IPRange.rangeType | String | IP range type \(parent or custom\) | 
| Expanse.IPRange.relatedRegistrationInformation.country | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.endAddress | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.handle | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.ipVersion | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.name | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.parentHandle | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.address | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.email | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.action | String | Registry entity event action. | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.actor | String | Registry entity event actor. | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.date | Date | Registry entity event date. | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.firstRegistered | Date | Registry entity first registered date. | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.formattedName | String | Registry entity formatted name. | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.handle | String | Registry entity handle. | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.id | String | Expanse ID of points of contact as maintained by the global internet registries \(ARIN, APNIC, etc.\), which identifies people or a role \(group of people\) within your organization that is responsible for the day-to-day management of this IP Network. | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.lastChanged | Date | Registry entity latest update date. | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.org | String | Registry entity organization. | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.phone | String | Registry entity phone number. | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.relatedEntityHandles | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.remarks | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.roles | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.statuses | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.remarks | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.startAddress | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.updatedDate | Date | Date when this IP Network was last processed by Expanse from the given global internet registry. | 
| Expanse.IPRange.relatedRegistrationInformation.whoisServer | String |  | 
| Expanse.IPRange.responsiveIpCount | Number | Count of responsive IP addresses in the range. | 
| Expanse.IPRange.severityCounts.count | Number | Count of issues of this type. | 
| Expanse.IPRange.severityCounts.type | String | Severity of related issues of this type \(CRITICAL, WARNING or ROUTINE\) | 
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
            "modified": "2020-12-07",
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
>|businessUnits|cidr|created|customChildRanges|id|ipVersion|modified|rangeIntroduced|rangeSize|rangeType|responsiveIpCount|
>|---|---|---|---|---|---|---|---|---|---|---|
>| {'id': 'c94c50ca-124f-4983-8da5-1756138e2252', 'name': 'PANW Acme Latex Supply Dev'} | 1.179.133.112/29 | 2020-09-22 |  | 0a8f44f9-05dc-42a3-a395-c83dad49fadf | 4 | 2020-12-07 | 2020-09-22 | 8 | parent | 0 |


### expanse-get-domain
***
Get domain details by domain name or search certificates


#### Base Command

`expanse-get-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain. | Optional | 
| last_observed_date | Last Observed Date (YYYY-MM-DD). | Optional | 
| search | List all domains with the specified substring. | Optional | 
| limit | Maximum number of entries to retrieve. | Optional | 
| has_dns_resolution | Retrieve only domains with or without resolution. Possible values are: true, false. | Optional | 
| has_active_service | Retrieve only domains with or without active service. Possible values are: true, false. | Optional | 
| has_related_cloud_resources | Retrieve only domains with or without cloud resources. Possible values are: true, false. | Optional | 
| tags | Retrieve only domains with one of the specified tag IDs. | Optional | 
| tagnames | Retrieve only domains with one of the specified tag names. | Optional | 
| businessunits | Retrieve only domains with one of the specified Business Unit IDs. | Optional | 
| businessunitnames | Retrieve only domains with one of the specified Business Unit names. | Optional | 
| providers | Retrieve only domains with one of the specified Provider IDs. | Optional | 
| providernames | Retrieve only domains with one of the specified Provider names. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Domain.annotations.note | String |  | 
| Expanse.Domain.annotations.tags | Unknown |  | 
| Expanse.Domain.businessUnits.id | String |  | 
| Expanse.Domain.businessUnits.name | String |  | 
| Expanse.Domain.businessUnits.tenantId | String |  | 
| Expanse.Domain.dateAdded | Date |  | 
| Expanse.Domain.details.recentIps.assetKey | String |  | 
| Expanse.Domain.details.recentIps.assetType | String |  | 
| Expanse.Domain.details.recentIps.businessUnits.id | String |  | 
| Expanse.Domain.details.recentIps.businessUnits.name | String |  | 
| Expanse.Domain.details.recentIps.businessUnits.tenantId | String |  | 
| Expanse.Domain.details.recentIps.commonName | String |  | 
| Expanse.Domain.details.recentIps.domain | String |  | 
| Expanse.Domain.details.recentIps.ip | String |  | 
| Expanse.Domain.details.recentIps.lastObserved | Date |  | 
| Expanse.Domain.details.recentIps.provider.id | String |  | 
| Expanse.Domain.details.recentIps.provider.name | String |  | 
| Expanse.Domain.details.recentIps.tenant.id | String |  | 
| Expanse.Domain.details.recentIps.tenant.name | String |  | 
| Expanse.Domain.details.recentIps.tenant.tenantId | String |  | 
| Expanse.Domain.details.recentIps.type | String |  | 
| Expanse.Domain.dnsResolutionStatus | String |  | 
| Expanse.Domain.domain | String |  | 
| Expanse.Domain.firstObserved | Date |  | 
| Expanse.Domain.hasLinkedCloudResources | Boolean |  | 
| Expanse.Domain.id | String |  | 
| Expanse.Domain.isCollapsed | Boolean |  | 
| Expanse.Domain.isPaidLevelDomain | Boolean |  | 
| Expanse.Domain.lastObserved | Date |  | 
| Expanse.Domain.lastSampledIp | String |  | 
| Expanse.Domain.lastSubdomainMetadata.dnsResolutionStatus | String |  | 
| Expanse.Domain.lastSubdomainMetadata.serviceStatus | String |  | 
| Expanse.Domain.lastSubdomainMetadata.isPaidLevelDomain | Boolean |  | 
| Expanse.Domain.providers.id | String |  | 
| Expanse.Domain.providers.name | String |  | 
| Expanse.Domain.serviceStatus | String |  | 
| Expanse.Domain.sourceDomain | String |  | 
| Expanse.Domain.tenant.id | String |  | 
| Expanse.Domain.tenant.name | String |  | 
| Expanse.Domain.tenant.tenantId | String |  | 
| Expanse.Domain.whois.admin.city | String |  | 
| Expanse.Domain.whois.admin.country | String |  | 
| Expanse.Domain.whois.admin.emailAddress | String |  | 
| Expanse.Domain.whois.admin.faxExtension | String |  | 
| Expanse.Domain.whois.admin.faxNumber | String |  | 
| Expanse.Domain.whois.admin.name | String |  | 
| Expanse.Domain.whois.admin.organization | String |  | 
| Expanse.Domain.whois.admin.phoneExtension | String |  | 
| Expanse.Domain.whois.admin.phoneNumber | String |  | 
| Expanse.Domain.whois.admin.postalCode | String |  | 
| Expanse.Domain.whois.admin.province | String |  | 
| Expanse.Domain.whois.admin.registryId | String |  | 
| Expanse.Domain.whois.admin.street | String |  | 
| Expanse.Domain.whois.creationDate | Date |  | 
| Expanse.Domain.whois.dnssec | String |  | 
| Expanse.Domain.whois.domain | String |  | 
| Expanse.Domain.whois.domainStatuses | String |  | 
| Expanse.Domain.whois.nameServers | String |  | 
| Expanse.Domain.whois.registrant.city | String |  | 
| Expanse.Domain.whois.registrant.country | String |  | 
| Expanse.Domain.whois.registrant.emailAddress | String |  | 
| Expanse.Domain.whois.registrant.faxExtension | String |  | 
| Expanse.Domain.whois.registrant.faxNumber | String |  | 
| Expanse.Domain.whois.registrant.name | String |  | 
| Expanse.Domain.whois.registrant.organization | String |  | 
| Expanse.Domain.whois.registrant.phoneExtension | String |  | 
| Expanse.Domain.whois.registrant.phoneNumber | String |  | 
| Expanse.Domain.whois.registrant.postalCode | String |  | 
| Expanse.Domain.whois.registrant.province | String |  | 
| Expanse.Domain.whois.registrant.registryId | String |  | 
| Expanse.Domain.whois.registrant.street | String |  | 
| Expanse.Domain.whois.registrar.abuseContactEmail | String |  | 
| Expanse.Domain.whois.registrar.abuseContactPhone | String |  | 
| Expanse.Domain.whois.registrar.formattedName | String |  | 
| Expanse.Domain.whois.registrar.ianaId | String |  | 
| Expanse.Domain.whois.registrar.name | String |  | 
| Expanse.Domain.whois.registrar.registrationExpirationDate | Date |  | 
| Expanse.Domain.whois.registrar.url | String |  | 
| Expanse.Domain.whois.registrar.whoisServer | String |  | 
| Expanse.Domain.whois.registryDomainId | String |  | 
| Expanse.Domain.whois.registryExpiryDate | Date |  | 
| Expanse.Domain.whois.reseller | String |  | 
| Expanse.Domain.whois.tech | String |  | 
| Expanse.Domain.whois.updatedDate | Date |  | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.DNS | String | A list of IP objects resolved by DNS. | 
| Domain.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| Domain.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| Domain.CreationDate | Date | The date that the domain was created. | 
| Domain.UpdatedDate | String | The date that the domain was last updated. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.DomainStatus | Date | The status of the domain. | 
| Domain.NameServers | String | \(List&lt;String&gt;\) Name servers of the domain. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.Subdomains | String | \(List&lt;String&gt;\) Subdomains of the domain. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Registrant.Email | String | The email address of the registrant. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.WHOIS.DomainStatus | String | The status of the domain. | 
| Domain.WHOIS.NameServers | String | \(List&lt;String&gt;\) Name servers of the domain. | 
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
| Domain.WHOIS/History | String | List of Whois objects | 
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
>|annotations|businessUnits|dateAdded|details|dnsResolutionStatus|domain|firstObserved|hasLinkedCloudResources|id|isCollapsed|isPaidLevelDomain|lastObserved|lastSampledIp|lastSubdomainMetadata|providers|serviceStatus|sourceDomain|tenant|whois|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| contacts: <br/>tags: <br/>note:  | {'id': 'c4de7fad-cde1-46cf-8725-a5999533db59', 'name': 'PANW VanDelay Import-Export Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'},<br/>{'id': 'f738ace6-f451-4f31-898d-a12afa204b2a', 'name': 'PANW VanDelay Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'} | 2020-09-22T21:23:02.372Z |  | HAS_DNS_RESOLUTION | *.108.pets.com | 2020-09-22T06:10:31.787Z | false | 142194a1-f443-3878-8dcc-540f4061c5f5 | false | false | 2020-09-22T06:10:31.787Z | 72.52.10.14 |  | {'id': 'Akamai', 'name': 'Akamai Technologies'} | NO_ACTIVE_SERVICE,<br/>NO_ACTIVE_ON_PREM_SERVICE,<br/>NO_ACTIVE_CLOUD_SERVICE | pets.com | id: f738ace6-f451-4f31-898d-a12afa204b2a<br/>name: PANW VanDelay Dev<br/>tenantId: f738ace6-f451-4f31-898d-a12afa204b2a | {'domain': 'pets.com', 'registryDomainId': None, 'updatedDate': '2016-10-19T09:12:50Z', 'creationDate': '1994-11-21T05:00:00Z', 'registryExpiryDate': '2018-11-20T05:00:00Z', 'reseller': None, 'registrar': {'name': 'MarkMonitor Inc.', 'formattedName': None, 'whoisServer': 'whois.markmonitor.com', 'url': None, 'ianaId': None, 'registrationExpirationDate': None, 'abuseContactEmail': None, 'abuseContactPhone': None}, 'domainStatuses': ['clientDeleteProhibited clientTransferProhibited clientUpdateProhibited'], 'nameServers': ['NS1.MARKMONITOR.COM', 'NS2.MARKMONITOR.COM', 'NS3.MARKMONITOR.COM', 'NS4.MARKMONITOR.COM', 'NS5.MARKMONITOR.COM', 'NS6.MARKMONITOR.COM', 'NS7.MARKMONITOR.COM'], 'registrant': {'name': 'Admin Contact', 'organization': 'PetSmart Home Office, Inc.', 'street': '19601 N 27th Ave,', 'city': 'Phoenix', 'province': 'AZ', 'postalCode': '85027', 'country': 'UNITED STATES', 'phoneNumber': '16235806100', 'phoneExtension': '', 'faxNumber': '16235806109', 'faxExtension': '', 'emailAddress': 'legal@petsmart.com', 'registryId': None}, 'admin': {'name': 'Admin Contact', 'organization': 'PetSmart Home Office, Inc.', 'street': '19601 N 27th Ave,', 'city': 'Phoenix', 'province': 'AZ', 'postalCode': '85027', 'country': 'UNITED STATES', 'phoneNumber': '16235806100', 'phoneExtension': '', 'faxNumber': '16235806109', 'faxExtension': '', 'emailAddress': 'legal@petsmart.com', 'registryId': None}, 'tech': {'name': None, 'organization': None, 'street': None, 'city': None, 'province': None, 'postalCode': None, 'country': None, 'phoneNumber': None, 'phoneExtension': None, 'faxNumber': None, 'faxExtension': None, 'emailAddress': None, 'registryId': None}, 'dnssec': None} |


### expanse-get-associated-domains
***
Returns all domains which have been seen with the specified certificate.


#### Base Command

`expanse-get-associated-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| common_name | The certificate common name. Fuzzy matching is done on this name, however query times can grow quite large when searching for short strings. Ex. "*.myhost.com" is a better search term than "host". | Optional | 
| ip | The IP address to search domains for. | Optional | 
| limit | Maximum number of matching certificates to retrieve. | Optional | 
| domains_limit | Maximum number of domains per certificate to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.AssociatedDomain.name | String | Name of the domain. | 
| Expanse.AssociatedDomain.IP | String | IP Address the domain resolved to. | 
| Expanse.AssociatedDomain.certificate | String | Expanse ID of the certificate associated to this domain. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!expanse-get-associated-domains ip="1.2.3.4"```

#### Context Example
```json
{}
```

#### Human Readable Output

>### Expanse Domains matching Certificate Common Name: None
>|name|IP|certificate|
>|---|---|---|
>|  |  | ## No Domains found |


### expanse-get-certificate
***
Get certificate details by certificate md5 hash or search certificates


#### Base Command

`expanse-get-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5_hash | MD5 Hash of the certificate. | Optional | 
| last_observed_date | Last Observed Date (YYYY-MM-DD), to be used with domain arg. | Optional | 
| search | List all certificates with the specified substring in common name. | Optional | 
| limit | Maximum number of entries to retrieve. | Optional | 
| has_certificate_advertisement | Retrieve only certificates actively/not actively advertised. | Optional | 
| has_active_service | Retrieve only certificates with or without active service. | Optional | 
| has_related_cloud_resources | Retrieve only certificates with or without cloud resources. | Optional | 
| tags | Retrieve only certificates with one of the specified tag IDs. | Optional | 
| tagnames | Retrieve only certificates with one of the specified tag names. | Optional | 
| businessunits | Retrieve only certificates with one of the specified Business Unit IDs. | Optional | 
| businessunitnames | Retrieve only certificates with one of the specified Business Unit names. | Optional | 
| providers | Retrieve only certificates with one of the specified Provider IDs. | Optional | 
| providernames | Retrieve only certificates with one of the specified Provider names. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Certificate.annotations.note | String |  | 
| Expanse.Certificate.annotations.tags | Unknown |  | 
| Expanse.Certificate.businessUnits.id | String |  | 
| Expanse.Certificate.businessUnits.name | String |  | 
| Expanse.Certificate.businessUnits.tenantId | String |  | 
| Expanse.Certificate.certificate.formattedIssuerOrg | String |  | 
| Expanse.Certificate.certificate.id | String |  | 
| Expanse.Certificate.certificate.issuer | String |  | 
| Expanse.Certificate.certificate.issuerAlternativeNames | String |  | 
| Expanse.Certificate.certificate.issuerCountry | String |  | 
| Expanse.Certificate.certificate.issuerEmail | Unknown |  | 
| Expanse.Certificate.certificate.issuerLocality | Unknown |  | 
| Expanse.Certificate.certificate.issuerName | String |  | 
| Expanse.Certificate.certificate.issuerOrg | String |  | 
| Expanse.Certificate.certificate.issuerOrgUnit | Unknown |  | 
| Expanse.Certificate.certificate.issuerState | Unknown |  | 
| Expanse.Certificate.certificate.md5Hash | String |  | 
| Expanse.Certificate.certificate.pemSha1 | String |  | 
| Expanse.Certificate.certificate.pemSha256 | String |  | 
| Expanse.Certificate.certificate.publicKey | String |  | 
| Expanse.Certificate.certificate.publicKeyAlgorithm | String |  | 
| Expanse.Certificate.certificate.publicKeyBits | Number |  | 
| Expanse.Certificate.certificate.publicKeyModulus | String |  | 
| Expanse.Certificate.certificate.publicKeyRsaExponent | Number |  | 
| Expanse.Certificate.certificate.publicKeySpki | String |  | 
| Expanse.Certificate.certificate.serialNumber | String |  | 
| Expanse.Certificate.certificate.signatureAlgorithm | String |  | 
| Expanse.Certificate.certificate.subject | String |  | 
| Expanse.Certificate.certificate.subjectAlternativeNames | String |  | 
| Expanse.Certificate.certificate.subjectCountry | Unknown |  | 
| Expanse.Certificate.certificate.subjectEmail | Unknown |  | 
| Expanse.Certificate.certificate.subjectLocality | Unknown |  | 
| Expanse.Certificate.certificate.subjectName | String |  | 
| Expanse.Certificate.certificate.subjectOrg | Unknown |  | 
| Expanse.Certificate.certificate.subjectOrgUnit | Unknown |  | 
| Expanse.Certificate.certificate.subjectState | Unknown |  | 
| Expanse.Certificate.certificate.validNotAfter | Date |  | 
| Expanse.Certificate.certificate.validNotBefore | Date |  | 
| Expanse.Certificate.certificate.version | String |  | 
| Expanse.Certificate.certificateAdvertisementStatus | String |  | 
| Expanse.Certificate.commonName | String |  | 
| Expanse.Certificate.dateAdded | Date |  | 
| Expanse.Certificate.details.base64Encoded | String |  | 
| Expanse.Certificate.details.recentIps.assetKey | String |  | 
| Expanse.Certificate.details.recentIps.assetType | String |  | 
| Expanse.Certificate.details.recentIps.businessUnits.id | String |  | 
| Expanse.Certificate.details.recentIps.businessUnits.name | String |  | 
| Expanse.Certificate.details.recentIps.businessUnits.tenantId | String |  | 
| Expanse.Certificate.details.recentIps.commonName | String |  | 
| Expanse.Certificate.details.recentIps.domain | Unknown |  | 
| Expanse.Certificate.details.recentIps.ip | String |  | 
| Expanse.Certificate.details.recentIps.lastObserved | Date |  | 
| Expanse.Certificate.details.recentIps.provider.id | String |  | 
| Expanse.Certificate.details.recentIps.provider.name | String |  | 
| Expanse.Certificate.details.recentIps.tenant.id | String |  | 
| Expanse.Certificate.details.recentIps.tenant.name | String |  | 
| Expanse.Certificate.details.recentIps.tenant.tenantId | String |  | 
| Expanse.Certificate.details.recentIps.type | String |  | 
| Expanse.Certificate.firstObserved | Date |  | 
| Expanse.Certificate.hasLinkedCloudResources | Boolean |  | 
| Expanse.Certificate.id | String |  | 
| Expanse.Certificate.lastObserved | Date |  | 
| Expanse.Certificate.properties | String |  | 
| Expanse.Certificate.providers.id | String |  | 
| Expanse.Certificate.providers.name | String |  | 
| Expanse.Certificate.serviceStatus | String |  | 
| Expanse.Certificate.tenant.id | String |  | 
| Expanse.Certificate.tenant.name | String |  | 
| Expanse.Certificate.tenant.tenantId | String |  | 
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
>|annotations|businessUnits|certificate|certificateAdvertisementStatus|commonName|dateAdded|details|firstObserved|hasLinkedCloudResources|id|lastObserved|properties|providers|serviceStatus|tenant|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| contacts: <br/>tags: <br/>note:  | {'id': 'c94c50ca-124f-4983-8da5-1756138e2252', 'name': 'PANW Acme Latex Supply Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'} | md5Hash: 1MZVcFeLBLab3jC-_z9t5Q==<br/>id: d4c65570-578b-34b6-9bde-30beff3f6de5<br/>issuer: C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254<br/>issuerAlternativeNames: <br/>issuerCountry: CN<br/>issuerEmail: null<br/>issuerLocality: GD<br/>issuerName: 10.254.254.254<br/>issuerOrg: CHINA-ISI<br/>formattedIssuerOrg: null<br/>issuerOrgUnit: CHINA-ISI<br/>issuerState: GZ<br/>publicKey: MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgHPWslRc21vG0EqmNyHPiI3Mger5AEXJE1YUS2V4nnSEngE9f5GhjXsbmlytoKPQt7tyf3lm0+SVO8z7/wiuYiqhsDQr4Iwmb0t9pIjF+Fn/H6Du9MfIgYeodk4k+JBUzp38Qi1A84QGnUZDjxgQ35UtVNxX444NMvr17gf2hkQIDAQAB<br/>publicKeyAlgorithm: RSA<br/>publicKeyRsaExponent: 65537<br/>signatureAlgorithm: SHA256withRSA<br/>subject: C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254<br/>subjectAlternativeNames: <br/>subjectCountry: CN<br/>subjectEmail: null<br/>subjectLocality: GD<br/>subjectName: 10.254.254.254<br/>subjectOrg: CHINA-ISI<br/>subjectOrgUnit: CHINA-ISI<br/>subjectState: GZ<br/>serialNumber: 12064359<br/>validNotBefore: 2013-11-18T00:39:31Z<br/>validNotAfter: 2112-06-12T00:39:31Z<br/>version: 3<br/>publicKeyBits: 1024<br/>pemSha256: y7D-d2yoCGlN_ZnPWfTPknjaSvT6tJtXtqqDBnIj_Zs=<br/>pemSha1: mGe0fWnNVjKzlkKugxEe1MzeoFo=<br/>publicKeyModulus: a01cf5ac951736d6f1b412a98dc873e22373207abe40117244d58512d95e279d2127804f5fe468635ec6e6972b6828f42deedc9fde59b4f9254ef33effc22b988aa86c0d0af823099bd2df6922317e167fc7e83bbd31f22061ea1d93893e241533a77f108b503ce101a75190e3c60437e54b553715f8e3834cbebd7b81fda191<br/>publicKeySpki: Yx3GXaDr00CS1YiWnaceyvTYNIsmYOGOT3G4I3SxCa0= | NO_CERTIFICATE_ADVERTISEMENT | 10.254.254.254 | 2020-09-22T21:23:06.866Z |  |  | false | 30a111ae-39e2-3b82-b459-249bac0c6065 |  | LONG_EXPIRATION,<br/>SELF_SIGNED,<br/>SHORT_KEY | {'id': 'Unknown', 'name': 'None'} | NO_ACTIVE_SERVICE,<br/>NO_ACTIVE_ON_PREM_SERVICE,<br/>NO_ACTIVE_CLOUD_SERVICE | id: f738ace6-f451-4f31-898d-a12afa204b2a<br/>name: PANW VanDelay Dev<br/>tenantId: f738ace6-f451-4f31-898d-a12afa204b2a |


### certificate
***
Provides data enrichment for an X509 Certificate from Expanse.


#### Base Command

`certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificate | MD5, SHA-1, SHA-256 or SHA-512 hash of the certificate to enrich.<br/>If MD5 is given, the command will check directly with Expanse API otherwise<br/>the script looks first for an indicator with the given hash to retrieve the<br/>corresponding MD5 hash.<br/>. | Optional | 
| set_expanse_fields | If set to true, the command updates the Expanse custom fields of the indicator.<br/>Only if an indicator already exists.<br/>. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Certificate.annotations.note | String |  | 
| Expanse.Certificate.annotations.tags | Unknown |  | 
| Expanse.Certificate.businessUnits.id | String |  | 
| Expanse.Certificate.businessUnits.name | String |  | 
| Expanse.Certificate.businessUnits.tenantId | String |  | 
| Expanse.Certificate.certificate.formattedIssuerOrg | String |  | 
| Expanse.Certificate.certificate.id | String |  | 
| Expanse.Certificate.certificate.issuer | String |  | 
| Expanse.Certificate.certificate.issuerAlternativeNames | String |  | 
| Expanse.Certificate.certificate.issuerCountry | String |  | 
| Expanse.Certificate.certificate.issuerEmail | Unknown |  | 
| Expanse.Certificate.certificate.issuerLocality | Unknown |  | 
| Expanse.Certificate.certificate.issuerName | String |  | 
| Expanse.Certificate.certificate.issuerOrg | String |  | 
| Expanse.Certificate.certificate.issuerOrgUnit | Unknown |  | 
| Expanse.Certificate.certificate.issuerState | Unknown |  | 
| Expanse.Certificate.certificate.md5Hash | String |  | 
| Expanse.Certificate.certificate.pemSha1 | String |  | 
| Expanse.Certificate.certificate.pemSha256 | String |  | 
| Expanse.Certificate.certificate.publicKey | String |  | 
| Expanse.Certificate.certificate.publicKeyAlgorithm | String |  | 
| Expanse.Certificate.certificate.publicKeyBits | Number |  | 
| Expanse.Certificate.certificate.publicKeyModulus | String |  | 
| Expanse.Certificate.certificate.publicKeyRsaExponent | Number |  | 
| Expanse.Certificate.certificate.publicKeySpki | String |  | 
| Expanse.Certificate.certificate.serialNumber | String |  | 
| Expanse.Certificate.certificate.signatureAlgorithm | String |  | 
| Expanse.Certificate.certificate.subject | String |  | 
| Expanse.Certificate.certificate.subjectAlternativeNames | String |  | 
| Expanse.Certificate.certificate.subjectCountry | Unknown |  | 
| Expanse.Certificate.certificate.subjectEmail | Unknown |  | 
| Expanse.Certificate.certificate.subjectLocality | Unknown |  | 
| Expanse.Certificate.certificate.subjectName | String |  | 
| Expanse.Certificate.certificate.subjectOrg | Unknown |  | 
| Expanse.Certificate.certificate.subjectOrgUnit | Unknown |  | 
| Expanse.Certificate.certificate.subjectState | Unknown |  | 
| Expanse.Certificate.certificate.validNotAfter | Date |  | 
| Expanse.Certificate.certificate.validNotBefore | Date |  | 
| Expanse.Certificate.certificate.version | String |  | 
| Expanse.Certificate.certificateAdvertisementStatus | String |  | 
| Expanse.Certificate.commonName | String |  | 
| Expanse.Certificate.dateAdded | Date |  | 
| Expanse.Certificate.details.base64Encoded | String |  | 
| Expanse.Certificate.details.recentIps.assetKey | String |  | 
| Expanse.Certificate.details.recentIps.assetType | String |  | 
| Expanse.Certificate.details.recentIps.businessUnits.id | String |  | 
| Expanse.Certificate.details.recentIps.businessUnits.name | String |  | 
| Expanse.Certificate.details.recentIps.businessUnits.tenantId | String |  | 
| Expanse.Certificate.details.recentIps.commonName | String |  | 
| Expanse.Certificate.details.recentIps.domain | Unknown |  | 
| Expanse.Certificate.details.recentIps.ip | String |  | 
| Expanse.Certificate.details.recentIps.lastObserved | Date |  | 
| Expanse.Certificate.details.recentIps.provider.id | String |  | 
| Expanse.Certificate.details.recentIps.provider.name | String |  | 
| Expanse.Certificate.details.recentIps.tenant.id | String |  | 
| Expanse.Certificate.details.recentIps.tenant.name | String |  | 
| Expanse.Certificate.details.recentIps.tenant.tenantId | String |  | 
| Expanse.Certificate.details.recentIps.type | String |  | 
| Expanse.Certificate.firstObserved | Date |  | 
| Expanse.Certificate.hasLinkedCloudResources | Boolean |  | 
| Expanse.Certificate.id | String |  | 
| Expanse.Certificate.lastObserved | Date |  | 
| Expanse.Certificate.properties | String |  | 
| Expanse.Certificate.providers.id | String |  | 
| Expanse.Certificate.providers.name | String |  | 
| Expanse.Certificate.serviceStatus | String |  | 
| Expanse.Certificate.tenant.id | String |  | 
| Expanse.Certificate.tenant.name | String |  | 
| Expanse.Certificate.tenant.tenantId | String |  | 
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
        "PEM": "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----",
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
>|annotations|businessUnits|certificate|certificateAdvertisementStatus|commonName|dateAdded|details|firstObserved|hasLinkedCloudResources|id|lastObserved|properties|providers|serviceStatus|tenant|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| contacts: <br/>tags: {'id': 'e00bc79d-d367-36f4-824c-042836fef5fc', 'name': 'xsoar-test-pb-tag'}<br/>note:  | {'id': 'c94c50ca-124f-4983-8da5-1756138e2252', 'name': 'PANW Acme Latex Supply Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'} | md5Hash: 1MZVcFeLBLab3jC-_z9t5Q==<br/>id: d4c65570-578b-34b6-9bde-30beff3f6de5<br/>issuer: C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254<br/>issuerAlternativeNames: <br/>issuerCountry: CN<br/>issuerEmail: null<br/>issuerLocality: GD<br/>issuerName: 10.254.254.254<br/>issuerOrg: CHINA-ISI<br/>formattedIssuerOrg: null<br/>issuerOrgUnit: CHINA-ISI<br/>issuerState: GZ<br/>publicKey: MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgHPWslRc21vG0EqmNyHPiI3Mger5AEXJE1YUS2V4nnSEngE9f5GhjXsbmlytoKPQt7tyf3lm0+SVO8z7/wiuYiqhsDQr4Iwmb0t9pIjF+Fn/H6Du9MfIgYeodk4k+JBUzp38Qi1A84QGnUZDjxgQ35UtVNxX444NMvr17gf2hkQIDAQAB<br/>publicKeyAlgorithm: RSA<br/>publicKeyRsaExponent: 65537<br/>signatureAlgorithm: SHA256withRSA<br/>subject: C=CN,ST=GZ,L=GD,O=CHINA-ISI,OU=CHINA-ISI,CN=10.254.254.254<br/>subjectAlternativeNames: <br/>subjectCountry: CN<br/>subjectEmail: null<br/>subjectLocality: GD<br/>subjectName: 10.254.254.254<br/>subjectOrg: CHINA-ISI<br/>subjectOrgUnit: CHINA-ISI<br/>subjectState: GZ<br/>serialNumber: 12064359<br/>validNotBefore: 2013-11-18T00:39:31Z<br/>validNotAfter: 2112-06-12T00:39:31Z<br/>version: 3<br/>publicKeyBits: 1024<br/>pemSha256: y7D-d2yoCGlN_ZnPWfTPknjaSvT6tJtXtqqDBnIj_Zs=<br/>pemSha1: mGe0fWnNVjKzlkKugxEe1MzeoFo=<br/>publicKeyModulus: a01cf5ac951736d6f1b412a98dc873e22373207abe40117244d58512d95e279d2127804f5fe468635ec6e6972b6828f42deedc9fde59b4f9254ef33effc22b988aa86c0d0af823099bd2df6922317e167fc7e83bbd31f22061ea1d93893e241533a77f108b503ce101a75190e3c60437e54b553715f8e3834cbebd7b81fda191<br/>publicKeySpki: Yx3GXaDr00CS1YiWnaceyvTYNIsmYOGOT3G4I3SxCa0= | NO_CERTIFICATE_ADVERTISEMENT | 10.254.254.254 | 2020-09-22T21:23:06.866Z | recentIps: <br/>cloudResources: <br/>base64Encoded:  |  | false | 30a111ae-39e2-3b82-b459-249bac0c6065 |  | LONG_EXPIRATION,<br/>SELF_SIGNED,<br/>SHORT_KEY | {'id': 'Unknown', 'name': 'None'} | NO_ACTIVE_SERVICE,<br/>NO_ACTIVE_ON_PREM_SERVICE,<br/>NO_ACTIVE_CLOUD_SERVICE | id: f738ace6-f451-4f31-898d-a12afa204b2a<br/>name: PANW VanDelay Dev<br/>tenantId: f738ace6-f451-4f31-898d-a12afa204b2a |


### expanse-get-risky-flows
***
Retrieve Expanse Behavior Risky Flows


#### Base Command

`expanse-get-risky-flows`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of flows to retrieve. | Optional | 
| risk_rule | Risk rule. | Optional | 
| internal_ip_range | Internal IP range. Supported formats a.b.c.d, a.b.c.d/e, a.b.c.d-a.b.c.d, a., a.*. | Optional | 
| tagnames | Tag names. | Optional | 
| created_before | Created Before date. | Optional | 
| created_after | Created AFter date. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.RiskyFlow.acked | Boolean |  | 
| Expanse.RiskyFlow.businessUnit.id | String |  | 
| Expanse.RiskyFlow.businessUnit.name | String |  | 
| Expanse.RiskyFlow.created | Date |  | 
| Expanse.RiskyFlow.externalAddress | String |  | 
| Expanse.RiskyFlow.externalCountryCode | String |  | 
| Expanse.RiskyFlow.externalCountryCodes | String |  | 
| Expanse.RiskyFlow.externalPort | Number |  | 
| Expanse.RiskyFlow.flowDirection | String |  | 
| Expanse.RiskyFlow.id | String |  | 
| Expanse.RiskyFlow.internalAddress | String |  | 
| Expanse.RiskyFlow.internalCountryCode | String |  | 
| Expanse.RiskyFlow.internalCountryCodes | String |  | 
| Expanse.RiskyFlow.internalPort | Number |  | 
| Expanse.RiskyFlow.internalTags.ipRange | String |  | 
| Expanse.RiskyFlow.observationTimestamp | Date |  | 
| Expanse.RiskyFlow.protocol | String |  | 
| Expanse.RiskyFlow.riskRule.additionalDataFields | String |  | 
| Expanse.RiskyFlow.riskRule.description | String |  | 
| Expanse.RiskyFlow.riskRule.id | String |  | 
| Expanse.RiskyFlow.riskRule.name | String |  | 
| Expanse.RiskyFlow.tenantBusinessUnitId | String |  | 
| Expanse.RiskyFlow.internalDomains | String |  | 
| Expanse.RiskyFlow.internalExposureTypes | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### expanse-list-risk-rules
***
List Behavior Risk Rules


#### Base Command

`expanse-list-risk-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of entries to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.RiskRule.abbreviatedName | String | Risk rule abbreviated name. | 
| Expanse.RiskRule.businessUnits.id | String | ID of the business unit associated to the risk rule. | 
| Expanse.RiskRule.dataFields | String | Risk rule data fields. | 
| Expanse.RiskRule.description | String | Risk rule description. | 
| Expanse.RiskRule.direction | String | Risk rule direction \(INBOUND or OUTBOUND\). | 
| Expanse.RiskRule.id | String | Risk rule ID. | 
| Expanse.RiskRule.name | String | Risk rule name. | 


#### Command Example
``` ```

#### Human Readable Output



### domain
***
Provides data enrichment for domains.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to enrich. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Domain.annotations.note | String |  | 
| Expanse.Domain.annotations.tags | Unknown |  | 
| Expanse.Domain.businessUnits.id | String |  | 
| Expanse.Domain.businessUnits.name | String |  | 
| Expanse.Domain.businessUnits.tenantId | String |  | 
| Expanse.Domain.dateAdded | Date |  | 
| Expanse.Domain.details.recentIps.assetKey | String |  | 
| Expanse.Domain.details.recentIps.assetType | String |  | 
| Expanse.Domain.details.recentIps.businessUnits.id | String |  | 
| Expanse.Domain.details.recentIps.businessUnits.name | String |  | 
| Expanse.Domain.details.recentIps.businessUnits.tenantId | String |  | 
| Expanse.Domain.details.recentIps.commonName | String |  | 
| Expanse.Domain.details.recentIps.domain | String |  | 
| Expanse.Domain.details.recentIps.ip | String |  | 
| Expanse.Domain.details.recentIps.lastObserved | Date |  | 
| Expanse.Domain.details.recentIps.provider.id | String |  | 
| Expanse.Domain.details.recentIps.provider.name | String |  | 
| Expanse.Domain.details.recentIps.tenant.id | String |  | 
| Expanse.Domain.details.recentIps.tenant.name | String |  | 
| Expanse.Domain.details.recentIps.tenant.tenantId | String |  | 
| Expanse.Domain.details.recentIps.type | String |  | 
| Expanse.Domain.dnsResolutionStatus | String |  | 
| Expanse.Domain.domain | String |  | 
| Expanse.Domain.firstObserved | Date |  | 
| Expanse.Domain.hasLinkedCloudResources | Boolean |  | 
| Expanse.Domain.id | String |  | 
| Expanse.Domain.isCollapsed | Boolean |  | 
| Expanse.Domain.isPaidLevelDomain | Boolean |  | 
| Expanse.Domain.lastObserved | Date |  | 
| Expanse.Domain.lastSampledIp | String |  | 
| Expanse.Domain.lastSubdomainMetadata.dnsResolutionStatus | String |  | 
| Expanse.Domain.lastSubdomainMetadata.serviceStatus | String |  | 
| Expanse.Domain.lastSubdomainMetadata.isPaidLevelDomain | Boolean |  | 
| Expanse.Domain.providers.id | String |  | 
| Expanse.Domain.providers.name | String |  | 
| Expanse.Domain.serviceStatus | String |  | 
| Expanse.Domain.sourceDomain | String |  | 
| Expanse.Domain.tenant.id | String |  | 
| Expanse.Domain.tenant.name | String |  | 
| Expanse.Domain.tenant.tenantId | String |  | 
| Expanse.Domain.whois.admin.city | String |  | 
| Expanse.Domain.whois.admin.country | String |  | 
| Expanse.Domain.whois.admin.emailAddress | String |  | 
| Expanse.Domain.whois.admin.faxExtension | String |  | 
| Expanse.Domain.whois.admin.faxNumber | String |  | 
| Expanse.Domain.whois.admin.name | String |  | 
| Expanse.Domain.whois.admin.organization | String |  | 
| Expanse.Domain.whois.admin.phoneExtension | String |  | 
| Expanse.Domain.whois.admin.phoneNumber | String |  | 
| Expanse.Domain.whois.admin.postalCode | String |  | 
| Expanse.Domain.whois.admin.province | String |  | 
| Expanse.Domain.whois.admin.registryId | String |  | 
| Expanse.Domain.whois.admin.street | String |  | 
| Expanse.Domain.whois.creationDate | Date |  | 
| Expanse.Domain.whois.dnssec | String |  | 
| Expanse.Domain.whois.domain | String |  | 
| Expanse.Domain.whois.domainStatuses | String |  | 
| Expanse.Domain.whois.nameServers | String |  | 
| Expanse.Domain.whois.registrant.city | String |  | 
| Expanse.Domain.whois.registrant.country | String |  | 
| Expanse.Domain.whois.registrant.emailAddress | String |  | 
| Expanse.Domain.whois.registrant.faxExtension | String |  | 
| Expanse.Domain.whois.registrant.faxNumber | String |  | 
| Expanse.Domain.whois.registrant.name | String |  | 
| Expanse.Domain.whois.registrant.organization | String |  | 
| Expanse.Domain.whois.registrant.phoneExtension | String |  | 
| Expanse.Domain.whois.registrant.phoneNumber | String |  | 
| Expanse.Domain.whois.registrant.postalCode | String |  | 
| Expanse.Domain.whois.registrant.province | String |  | 
| Expanse.Domain.whois.registrant.registryId | String |  | 
| Expanse.Domain.whois.registrant.street | String |  | 
| Expanse.Domain.whois.registrar.abuseContactEmail | String |  | 
| Expanse.Domain.whois.registrar.abuseContactPhone | String |  | 
| Expanse.Domain.whois.registrar.formattedName | String |  | 
| Expanse.Domain.whois.registrar.ianaId | String |  | 
| Expanse.Domain.whois.registrar.name | String |  | 
| Expanse.Domain.whois.registrar.registrationExpirationDate | Date |  | 
| Expanse.Domain.whois.registrar.url | String |  | 
| Expanse.Domain.whois.registrar.whoisServer | String |  | 
| Expanse.Domain.whois.registryDomainId | String |  | 
| Expanse.Domain.whois.registryExpiryDate | Date |  | 
| Expanse.Domain.whois.reseller | String |  | 
| Expanse.Domain.whois.tech | String |  | 
| Expanse.Domain.whois.updatedDate | Date |  | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.DNS | String | A list of IP objects resolved by DNS. | 
| Domain.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| Domain.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| Domain.CreationDate | Date | The date that the domain was created. | 
| Domain.UpdatedDate | String | The date that the domain was last updated. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.DomainStatus | Date | The status of the domain. | 
| Domain.NameServers | String | \(List&lt;String&gt;\) Name servers of the domain. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.Subdomains | String | \(List&lt;String&gt;\) Subdomains of the domain. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Registrant.Email | String | The email address of the registrant. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.WHOIS.DomainStatus | String | The status of the domain. | 
| Domain.WHOIS.NameServers | String | \(List&lt;String&gt;\) Name servers of the domain. | 
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
| Domain.WHOIS/History | String | List of Whois objects | 
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
>|annotations|businessUnits|dateAdded|details|dnsResolutionStatus|domain|firstObserved|hasLinkedCloudResources|id|isCollapsed|isPaidLevelDomain|lastObserved|lastSampledIp|lastSubdomainMetadata|providers|serviceStatus|sourceDomain|tenant|whois|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| contacts: <br/>tags: {'id': 'e00bc79d-d367-36f4-824c-042836fef5fc', 'name': 'xsoar-test-pb-tag'}<br/>note:  | {'id': 'c4de7fad-cde1-46cf-8725-a5999533db59', 'name': 'PANW VanDelay Import-Export Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'},<br/>{'id': 'f738ace6-f451-4f31-898d-a12afa204b2a', 'name': 'PANW VanDelay Dev', 'tenantId': 'f738ace6-f451-4f31-898d-a12afa204b2a'} | 2020-09-22T21:23:02.372Z | recentIps: <br/>cloudResources:  | HAS_DNS_RESOLUTION | *.108.pets.com | 2020-09-22T06:10:31.787Z | false | 142194a1-f443-3878-8dcc-540f4061c5f5 | false | false | 2020-09-22T06:10:31.787Z | 72.52.10.14 |  | {'id': 'Akamai', 'name': 'Akamai Technologies'} | NO_ACTIVE_SERVICE,<br/>NO_ACTIVE_ON_PREM_SERVICE,<br/>NO_ACTIVE_CLOUD_SERVICE | pets.com | id: f738ace6-f451-4f31-898d-a12afa204b2a<br/>name: PANW VanDelay Dev<br/>tenantId: f738ace6-f451-4f31-898d-a12afa204b2a | {'domain': 'pets.com', 'registryDomainId': None, 'updatedDate': '2016-10-19T09:12:50Z', 'creationDate': '1994-11-21T05:00:00Z', 'registryExpiryDate': '2018-11-20T05:00:00Z', 'reseller': None, 'registrar': {'name': 'MarkMonitor Inc.', 'formattedName': None, 'whoisServer': 'whois.markmonitor.com', 'url': None, 'ianaId': None, 'registrationExpirationDate': None, 'abuseContactEmail': None, 'abuseContactPhone': None}, 'domainStatuses': ['clientDeleteProhibited clientTransferProhibited clientUpdateProhibited'], 'nameServers': ['NS1.MARKMONITOR.COM', 'NS2.MARKMONITOR.COM', 'NS3.MARKMONITOR.COM', 'NS4.MARKMONITOR.COM', 'NS5.MARKMONITOR.COM', 'NS6.MARKMONITOR.COM', 'NS7.MARKMONITOR.COM'], 'registrant': {'name': 'Admin Contact', 'organization': 'PetSmart Home Office, Inc.', 'street': '19601 N 27th Ave,', 'city': 'Phoenix', 'province': 'AZ', 'postalCode': '85027', 'country': 'UNITED STATES', 'phoneNumber': '16235806100', 'phoneExtension': '', 'faxNumber': '16235806109', 'faxExtension': '', 'emailAddress': 'legal@petsmart.com', 'registryId': None}, 'admin': {'name': 'Admin Contact', 'organization': 'PetSmart Home Office, Inc.', 'street': '19601 N 27th Ave,', 'city': 'Phoenix', 'province': 'AZ', 'postalCode': '85027', 'country': 'UNITED STATES', 'phoneNumber': '16235806100', 'phoneExtension': '', 'faxNumber': '16235806109', 'faxExtension': '', 'emailAddress': 'legal@petsmart.com', 'registryId': None}, 'tech': {'name': None, 'organization': None, 'street': None, 'city': None, 'province': None, 'postalCode': None, 'country': None, 'phoneNumber': None, 'phoneExtension': None, 'faxNumber': None, 'faxExtension': None, 'emailAddress': None, 'registryId': None}, 'dnssec': None} |


### ip
***
Provides data enrichment for ips.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The ip to enrich. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IP.assetKey | String |  | 
| Expanse.IP.assetType | String |  | 
| Expanse.IP.businessUnits.id | String |  | 
| Expanse.IP.businessUnits.name | String |  | 
| Expanse.IP.businessUnits.tenantId | String |  | 
| Expanse.IP.commonName | String |  | 
| Expanse.IP.domain | String |  | 
| Expanse.IP.ip | String |  | 
| Expanse.IP.lastObserved | Date |  | 
| Expanse.IP.provider.id | String |  | 
| Expanse.IP.provider.name | String |  | 
| Expanse.IP.tenant.id | String |  | 
| Expanse.IP.tenant.name | String |  | 
| Expanse.IP.tenant.tenantId | String |  | 
| Expanse.IP.type | String |  | 
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
```!ip ip="1.2.3.4"```

#### Context Example
```json
{}
```

#### Human Readable Output

>## No IPs found

### cidr
***
Provides data enrichment for CIDR blocks using Expanse IP Range.


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
| Expanse.IPRange.annotations.additionalNotes | String |  | 
| Expanse.IPRange.annotations.tags | Unknown |  | 
| Expanse.IPRange.attributionReasons.reason | String |  | 
| Expanse.IPRange.businessUnits.id | String |  | 
| Expanse.IPRange.businessUnits.name | String |  | 
| Expanse.IPRange.cidr | String |  | 
| Expanse.IPRange.created | Date |  | 
| Expanse.IPRange.id | String |  | 
| Expanse.IPRange.ipVersion | String |  | 
| Expanse.IPRange.locationInformation.geolocation.city | String |  | 
| Expanse.IPRange.locationInformation.geolocation.countryCode | String |  | 
| Expanse.IPRange.locationInformation.geolocation.latitude | Number |  | 
| Expanse.IPRange.locationInformation.geolocation.longitude | Number |  | 
| Expanse.IPRange.locationInformation.geolocation.regionCode | String |  | 
| Expanse.IPRange.locationInformation.ip | String |  | 
| Expanse.IPRange.modified | Date |  | 
| Expanse.IPRange.rangeIntroduced | Date |  | 
| Expanse.IPRange.rangeSize | Number |  | 
| Expanse.IPRange.rangeType | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.country | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.endAddress | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.handle | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.ipVersion | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.name | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.parentHandle | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.address | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.email | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.action | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.actor | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.events.date | Date |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.firstRegistered | Date |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.formattedName | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.handle | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.id | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.lastChanged | Date |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.org | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.phone | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.relatedEntityHandles | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.remarks | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.roles | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.registryEntities.statuses | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.remarks | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.startAddress | String |  | 
| Expanse.IPRange.relatedRegistrationInformation.updatedDate | Date |  | 
| Expanse.IPRange.relatedRegistrationInformation.whoisServer | String |  | 
| Expanse.IPRange.responsiveIpCount | Number |  | 
| Expanse.IPRange.severityCounts.count | Number |  | 
| Expanse.IPRange.severityCounts.type | String |  | 
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
            "modified": "2020-12-07",
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
                            "relatedEntityHandles": [],
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
                            "relatedEntityHandles": [],
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
                            "relatedEntityHandles": [],
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
                            "relatedEntityHandles": [],
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
>|annotations|attributionReasons|businessUnits|cidr|created|customChildRanges|id|ipVersion|locationInformation|modified|rangeIntroduced|rangeSize|rangeType|relatedRegistrationInformation|responsiveIpCount|severityCounts|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| tags: {'id': 'e00bc79d-d367-36f4-824c-042836fef5fc', 'created': '2020-12-07', 'modified': '2020-12-07', 'name': 'xsoar-test-pb-tag'}<br/>additionalNotes: <br/>pointsOfContact:  | {'reason': 'This parent range is attributed via IP network registration records for 1.179.133.116–1.179.133.119'},<br/>{'reason': 'This parent range is attributed via IP network registration records for 1.179.133.112–1.179.133.115'} | {'id': 'c94c50ca-124f-4983-8da5-1756138e2252', 'name': 'PANW Acme Latex Supply Dev'} | 1.179.133.112/29 | 2020-09-22 |  | 0a8f44f9-05dc-42a3-a395-c83dad49fadf | 4 |  | 2020-12-07 | 2020-09-22 | 8 | parent | {'handle': '1.179.133.112 - 1.179.133.115', 'startAddress': '1.179.133.112', 'endAddress': '1.179.133.115', 'ipVersion': '4', 'country': 'th', 'name': 'saim-synthetic-latex', 'parentHandle': '', 'whoisServer': 'whois.apnic.net', 'updatedDate': '2020-09-22', 'remarks': 'saim synthetic latex,Nong Khaem Province', 'registryEntities': [{'id': '125d112c-1169-3025-89e7-4c8c5a16db0b', 'handle': '', 'address': '', 'email': '', 'events': [], 'firstRegistered': None, 'formattedName': '', 'lastChanged': None, 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [], 'roles': ['administrative']}, {'id': '13cb65ca-9572-394b-b385-b2bd15aceb95', 'handle': '', 'address': '', 'email': '', 'events': [], 'firstRegistered': None, 'formattedName': '', 'lastChanged': None, 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [], 'roles': ['technical']}, {'id': '3c5ef28b-64d7-3d1f-b343-a31078292b04', 'handle': 'IRT-TOT-TH', 'address': 'TOT Public Company Limited\n89/2 Moo 3 Chaengwattana Rd, Laksi,Bangkok 10210 THAILAND          ', 'email': 'apipolg@tot.co.th, abuse@totisp.net', 'events': [{'action': 'last changed', 'actor': 'null', 'date': '2017-06-21T07:19:22Z', 'links': []}], 'firstRegistered': None, 'formattedName': 'IRT-TOT-TH', 'lastChanged': '2017-06-21', 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [], 'roles': ['abuse']}]},<br/>{'handle': '1.179.133.116 - 1.179.133.119', 'startAddress': '1.179.133.116', 'endAddress': '1.179.133.119', 'ipVersion': '4', 'country': 'th', 'name': 'siam-synthetic-latex', 'parentHandle': '', 'whoisServer': 'whois.apnic.net', 'updatedDate': '2020-09-22', 'remarks': 'siam synthetic latex,Nong Khaem Province', 'registryEntities': [{'id': '125d112c-1169-3025-89e7-4c8c5a16db0b', 'handle': '', 'address': '', 'email': '', 'events': [], 'firstRegistered': None, 'formattedName': '', 'lastChanged': None, 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [], 'roles': ['administrative']}, {'id': '13cb65ca-9572-394b-b385-b2bd15aceb95', 'handle': '', 'address': '', 'email': '', 'events': [], 'firstRegistered': None, 'formattedName': '', 'lastChanged': None, 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [], 'roles': ['technical']}, {'id': '3c5ef28b-64d7-3d1f-b343-a31078292b04', 'handle': 'IRT-TOT-TH', 'address': 'TOT Public Company Limited\n89/2 Moo 3 Chaengwattana Rd, Laksi,Bangkok 10210 THAILAND          ', 'email': 'apipolg@tot.co.th, abuse@totisp.net', 'events': [{'action': 'last changed', 'actor': 'null', 'date': '2017-06-21T07:19:22Z', 'links': []}], 'firstRegistered': None, 'formattedName': 'IRT-TOT-TH', 'lastChanged': '2017-06-21', 'org': '', 'phone': '', 'remarks': '', 'statuses': '', 'relatedEntityHandles': [], 'roles': ['abuse']}]} | 0 | {'type': 'CRITICAL', 'count': 0},<br/>{'type': 'ROUTINE', 'count': 0},<br/>{'type': 'UNCATEGORIZED', 'count': 0},<br/>{'type': 'WARNING', 'count': 0} |

