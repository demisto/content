Search, inspect and enrich certificates held in CyberArk Certificate Manager SaaS, including where each certificate is installed and which application owns it.
This integration was built against the CyberArk Certificate Manager SaaS GraphQL surface (`POST /graphql`) and the v1 REST surface.

## Configure Certificate Manager SaaS in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The regional API host for your tenant. US is the bare host \(https://api.venafi.cloud\); the other regions are subdomains - https://api.eu.venafi.cloud, https://api.uk.venafi.cloud, https://api.au.venafi.cloud, https://api.sg.venafi.cloud, https://api.ca.venafi.cloud. An API key issued in one region is rejected by every other region. | True |
| API Key | The Certificate Manager SaaS API key. Only the password half of the credential is used - leave the user name empty, or pick a saved credential from the vault. | True |
| Keystore passphrase | Encrypts the private key in a keystore download when the command gets no passphrase argument. Pick a saved credential from the vault; only the password is used. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Score reported key compromise as | The verdict for a KEY_COMPROMISE revocation that is reported but not done - failed, waiting for approval, or still not revoked on the CA's revocation list. A confirmed or unverifiable key-compromise revocation is always Malicious. | False |
| Incidents Fetch Interval | How often the platform polls this instance for expiring certificates, in minutes. | False |
| Fetch incidents | When selected, expiring certificates and failed key-compromise revocations are polled for and turned into incidents. | False |
| Incident type |  | False |
| First fetch time | How far back the first fetch reaches. An incident occurs when a certificate crosses an expiry threshold, so a value at least as large as "Expiry window \(days\)" picks up every certificate already inside the window on the first run - with one incident per certificate, for the most severe threshold it has crossed. | False |
| Expiry window (days) | Watch certificates expiring within this many days (current, active versions only; a renewed certificate's old version raises no incident). One incident is created per threshold crossed - 30 days \(High\) and 7 days \(Critical\); a wider window adds a Medium incident when it is entered. Applied as a server-side filter, so the size of the tenant does not affect the cost of a fetch. | False |
| Maximum number of incidents per fetch |  | False |
| Look back (minutes) | How far before the last run to re-scan, in minutes. A certificate starts matching the expiry filter at the moment it crosses the threshold, which can be before the fetch that first returns it; without a look back those certificates are skipped permanently. Already-created incidents are deduplicated, so a larger value costs bookkeeping rather than duplicates. | False |

## Fetched incidents

One incident is created **per expiry threshold a certificate crosses**:

- Crossing **30 days** before expiry creates a **High** incident; crossing **7 days** creates a separate **Critical** incident. An *Expiry window* wider than 30 days adds a **Medium** incident when the certificate enters it; a narrower one moves the High rung to the window's edge.
- Severity comes from the threshold crossed, not from the days remaining at fetch time. It never drops below Medium.
- An incident's *occurred* time is the moment of the crossing. Each crossing is deduplicated on `fingerprint:threshold`, so a re-fetch never duplicates it.
- On the first fetch, a certificate that has already crossed both thresholds produces only the Critical incident.
- The crossed threshold is carried in the incident's raw JSON as `CrossedThresholdDays`; the *CertManagerSaaS - Fetch Incoming Mapper* maps it and the certificate fields onto the incident.
- The raw JSON also carries `IssueType`, the incident type; the *CertManagerSaaS - Fetch Classifier* types the incident from it, because XSIAM ignores the type an integration sets.
- The raw JSON also carries `SourceBrand` (`CertificateManagerSaaS`), the integration that found the certificate, so a playbook can send follow-up commands to that integration.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### certificate

***
Enriches certificate indicators from the Certificate Manager SaaS inventory. Accepts certificate fingerprints (hexadecimal digests, with or without separators).

#### Base Command

`certificate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificate | A comma-separated list of certificate fingerprints. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. |
| Certificate.SubjectDN | String | The subject distinguished name of the certificate. |
| Certificate.IssuerDN | String | The issuer distinguished name of the certificate. |
| Certificate.Name | String | The names of the certificate. |
| Certificate.SerialNumber | String | The serial number of the certificate. |
| Certificate.ValidityNotBefore | Date | The timestamp from which the certificate is valid. |
| Certificate.ValidityNotAfter | Date | The timestamp at which the certificate expires. |
| Certificate.SHA256 | String | The SHA-256 digest of the certificate. |
| Certificate.SHA1 | String | The SHA-1 digest of the certificate. |
| Certificate.MD5 | String | The MD5 digest of the certificate. |
| Certificate.SignatureAlgorithm | String | The signature algorithm of the certificate. |
| Certificate.SubjectAlternativeName.Value | String | A subject alternative name of the certificate. |
| Certificate.PublicKey.Algorithm | String | The public key algorithm of the certificate. |
| Certificate.PublicKey.Length | Number | The public key length of the certificate. |
| CertManagerSaaS.Certificate.ID | String | The Certificate Manager SaaS identifier of the certificate. |
| CertManagerSaaS.Certificate.Fingerprint | String | The fingerprint of the certificate. |
| CertManagerSaaS.Certificate.CommonName | String | The first subject common name of the certificate. |
| CertManagerSaaS.Certificate.Status | String | The Certificate Manager SaaS status of the certificate. |
| CertManagerSaaS.Certificate.ValidTo | Date | The timestamp at which the certificate expires. |
| CertManagerSaaS.Certificate.DaysUntilExpiry | Number | Whole days remaining until the certificate expires. Negative once expired. |
| CertManagerSaaS.Certificate.SourceBrand | String | The brand of the integration that returned the certificate. Route follow-up commands for this certificate to that integration. |
| CertManagerSaaS.Certificate.SourceInstance | String | The name of the integration instance that returned the certificate. Pass it as using= to send follow-up commands to the tenant that holds the certificate. |
| CertManagerSaaS.UnresolvedCertificate.Fingerprint | String | A fingerprint that could not be enriched. |
| CertManagerSaaS.UnresolvedCertificate.Reason | String | Why the fingerprint could not be enriched. No reputation is produced for these. |

#### Command example

```!certificate certificate="A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Certificate": {
            "CommonName": "shop.example.com",
            "DaysUntilExpiry": 144,
            "Fingerprint": "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
            "ID": "4a2b7c10-3333-11ef-9a11-0242ac120002",
            "InstallationLocations": [
                "Panorama 01 (Palo Alto Panorama Decryption profiles (Preview))"
            ],
            "Installations": [
                {
                    "ID": "9c2d6f33-2222-11ef-9a11-0242ac120002",
                    "MachineID": "8b1c5e22-1111-11ef-9a11-0242ac120002",
                    "MachineName": "Panorama 01",
                    "PluginName": "Palo Alto Panorama Decryption profiles (Preview)",
                    "Status": "VALIDATED"
                }
            ],
            "IsCA": false,
            "IsSelfSigned": false,
            "IssuerCommonName": "Example Issuing CA",
            "IssuerDN": "cn=Example Issuing CA",
            "KeyUsages": [
                "DIGITAL_SIGNATURE",
                "KEY_ENCIPHERMENT"
            ],
            "LastModifiedTime": "2026-02-18T18:19:45Z",
            "Name": "shop.example.com",
            "Origins": [
                "MACHINE_DISCOVERY"
            ],
            "PublicKey": {
                "Algorithm": "RSA",
                "Length": 2048
            },
            "SerialNumber": "5A6B7C8D",
            "SignatureAlgorithm": "SHA-256withRSA",
            "SignatureHashAlgorithm": "SHA256",
            "SourceBrand": "CertificateManagerSaaS",
            "Status": "ACTIVE",
            "SubjectDN": "cn=shop.example.com",
            "ValidFrom": "2026-02-16T02:59:04Z",
            "ValidTo": "2027-02-16T02:59:04Z",
            "ValidityPeriodSeconds": 31536000
        }
    },
    "Certificate": {
        "IssuerDN": "cn=Example Issuing CA",
        "Name": [
            "shop.example.com"
        ],
        "PublicKey": {
            "Algorithm": "RSA",
            "Length": 2048
        },
        "SHA1": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        "SerialNumber": "5A6B7C8D",
        "Signature": {
            "Algorithm": "SHA-256withRSA"
        },
        "SubjectDN": "cn=shop.example.com",
        "ValidityNotAfter": "2027-02-16T02:59:04Z",
        "ValidityNotBefore": "2026-02-16T02:59:04Z"
    },
    "DBotScore": {
        "Indicator": "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "certificate",
        "Vendor": "Certificate Manager SaaS"
    }
}
```

#### Human Readable Output

>### Certificate A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
>
>|Fingerprint|CommonName|IssuerCommonName|Status|ValidTo|DaysUntilExpiry|
>|---|---|---|---|---|---|
>| A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 | shop.example.com | Example Issuing CA | ACTIVE | 2027-02-16T02:59:04Z | 144 |

### cmsaas-certificate-search

***
Searches the Certificate Manager SaaS certificate inventory. Only "fingerprint" is filtered server-side; the remaining criteria are applied client-side while paging through the inventory, so a broad search may need "max_pages" raised.

#### Base Command

`cmsaas-certificate-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fingerprint | An exact certificate fingerprint. Filtered server-side. | Optional |
| common_name | A case-insensitive substring matched against the subject common name and the subject alternative names. | Optional |
| issuer | A case-insensitive substring matched against the issuer common name and the issuer distinguished name. | Optional |
| status | The certificate status, matched exactly and case-insensitively. | Optional |
| expires_in_days | Keep only certificates expiring within this many days. | Optional |
| limit | Maximum number of certificates to return. Default is 50. | Optional |
| max_pages | Maximum number of 100-certificate pages to scan while applying the client-side criteria. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.Certificate.ID | String | The Certificate Manager SaaS identifier of the certificate. |
| CertManagerSaaS.Certificate.Name | String | The Certificate Manager SaaS name of the certificate. |
| CertManagerSaaS.Certificate.Fingerprint | String | The fingerprint of the certificate. |
| CertManagerSaaS.Certificate.SerialNumber | String | The serial number of the certificate. |
| CertManagerSaaS.Certificate.Status | String | The Certificate Manager SaaS status of the certificate. |
| CertManagerSaaS.Certificate.CommonName | String | The first subject common name of the certificate. |
| CertManagerSaaS.Certificate.SubjectDN | String | The subject distinguished name of the certificate. |
| CertManagerSaaS.Certificate.IssuerCommonName | String | The first issuer common name of the certificate. |
| CertManagerSaaS.Certificate.IssuerDN | String | The issuer distinguished name of the certificate. |
| CertManagerSaaS.Certificate.ValidFrom | Date | The timestamp from which the certificate is valid. |
| CertManagerSaaS.Certificate.ValidTo | Date | The timestamp at which the certificate expires. |
| CertManagerSaaS.Certificate.ValidityPeriodSeconds | Number | The validity period of the certificate, in seconds. |
| CertManagerSaaS.Certificate.DaysUntilExpiry | Number | Whole days remaining until the certificate expires. Negative once expired. |
| CertManagerSaaS.Certificate.IsSelfSigned | Boolean | Whether the certificate is self-signed. |
| CertManagerSaaS.Certificate.IsCA | Boolean | Whether the certificate is a certificate authority certificate. |
| CertManagerSaaS.Certificate.IsPublic | Boolean | Whether the certificate was issued by a public certificate authority. Can be absent. |
| CertManagerSaaS.Certificate.SignatureAlgorithm | String | The signature algorithm of the certificate. |
| CertManagerSaaS.Certificate.SignatureHashAlgorithm | String | The signature hash algorithm of the certificate. |
| CertManagerSaaS.Certificate.KeyUsages | String | The key usage extension values of the certificate. |
| CertManagerSaaS.Certificate.Origins | String | How the certificate entered the Certificate Manager SaaS inventory. |
| CertManagerSaaS.Certificate.LastModifiedTime | Date | When the certificate record was last modified. |
| CertManagerSaaS.Certificate.SubjectAlternativeNames | String | The subject alternative names of the certificate. |
| CertManagerSaaS.Certificate.PublicKey.Algorithm | String | The public key algorithm of the certificate. |
| CertManagerSaaS.Certificate.PublicKey.Length | Number | The public key length of the certificate. |
| CertManagerSaaS.Certificate.PublicKey.Curve | String | The elliptic curve of the certificate public key. |
| CertManagerSaaS.Certificate.Applications.ID | String | The identifier of an application the certificate is assigned to. |
| CertManagerSaaS.Certificate.Applications.Name | String | The name of an application the certificate is assigned to. |
| CertManagerSaaS.Certificate.Installations.ID | String | The identifier of a machine installation of the certificate. |
| CertManagerSaaS.Certificate.Installations.Status | String | The status of a machine installation of the certificate. |
| CertManagerSaaS.Certificate.Installations.MachineID | String | The identifier of the machine the certificate is installed on. |
| CertManagerSaaS.Certificate.Installations.MachineName | String | The operator-assigned label of the machine the certificate is installed on. |
| CertManagerSaaS.Certificate.Installations.PluginName | String | The name of the machine plugin that manages the installation. |
| CertManagerSaaS.Certificate.CloudInstallations.ID | String | The identifier of a cloud keystore installation of the certificate. |
| CertManagerSaaS.Certificate.CloudInstallations.Status | String | The status of a cloud keystore installation of the certificate. |
| CertManagerSaaS.Certificate.CloudInstallations.KeystoreID | String | The identifier of the cloud keystore holding the certificate. |
| CertManagerSaaS.Certificate.CloudInstallations.KeystoreName | String | The name of the cloud keystore holding the certificate. |
| CertManagerSaaS.Certificate.CloudInstallations.KeystoreType | String | The type of the cloud keystore holding the certificate, for example AWS Certificate Manager or Azure Key Vault. |
| CertManagerSaaS.Certificate.CloudInstallations.ProviderName | String | The name of the cloud provider connection the keystore belongs to. |
| CertManagerSaaS.Certificate.InstallationLocations | String | Where the certificate is installed, one readable entry per machine or cloud keystore installation. |
| CertManagerSaaS.Certificate.Revocation.Status | String | The revocation status of the certificate. Absent when the certificate was never revoked. |
| CertManagerSaaS.Certificate.Revocation.Reason | String | The reason the certificate was revoked. |
| CertManagerSaaS.Certificate.Revocation.Comment | String | The comment stored with the revocation. |
| CertManagerSaaS.Certificate.Revocation.Error | String | The error the CA returned for a failed revocation. |
| CertManagerSaaS.Certificate.GlobalRevocation.Status | String | Whether the issuing CA's revocation list shows the certificate revoked (REVOKED, NOT_REVOKED or UNKNOWN). Checked against public CAs' revocation lists about every six hours; usually UNKNOWN for private CAs. |
| CertManagerSaaS.Certificate.GlobalRevocation.Reason | String | The revocation reason on the CA's revocation list. |
| CertManagerSaaS.Certificate.GlobalRevocation.RevokedTime | Date | When the CA revoked the certificate, from its revocation list. |
| CertManagerSaaS.Certificate.TLSEndpoints.ID | String | The identifier of a TLS server endpoint serving the certificate. |
| CertManagerSaaS.Certificate.TLSEndpoints.ServerName | String | The server name of a TLS server endpoint serving the certificate. |
| CertManagerSaaS.Certificate.TLSEndpoints.IPAddress | String | The IP address of a TLS server endpoint serving the certificate. |
| CertManagerSaaS.Certificate.TLSEndpoints.Port | Number | The port of a TLS server endpoint serving the certificate. |
| CertManagerSaaS.Certificate.TLSEndpoints.DeploymentStatus | String | The deployment status of a TLS server endpoint serving the certificate. |
| CertManagerSaaS.Certificate.SourceBrand | String | The brand of the integration that returned the certificate. Route follow-up commands for this certificate to that integration. |
| CertManagerSaaS.Certificate.SourceInstance | String | The name of the integration instance that returned the certificate. Pass it as using= to send follow-up commands to the tenant that holds the certificate. |

#### Command example

```!cmsaas-certificate-search common_name="example.com" limit="2"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Certificate": [
            {
                "CommonName": "portal.example.com",
                "DaysUntilExpiry": -136,
                "Fingerprint": "C1D2E3F405162738495A6B7C8D9EAFB0C1D2E3F4",
                "ID": "4a2b7c10-3333-11ef-9a11-0242ac120003",
                "IsCA": false,
                "IsSelfSigned": false,
                "IssuerCommonName": "CyberArk CM SaaS Built-In Intermediate CA - G1",
                "IssuerDN": "cn=CyberArk CM SaaS Built-In Intermediate CA - G1,ou=Built-in,o=CyberArk Software Ltd.,c=IL",
                "KeyUsages": [
                    "DIGITAL_SIGNATURE",
                    "KEY_ENCIPHERMENT",
                    "KEY_AGREEMENT"
                ],
                "LastModifiedTime": "2026-02-11T12:37:08Z",
                "Name": "portal.example.com",
                "Origins": [
                    "USER_PROVIDED"
                ],
                "PublicKey": {
                    "Algorithm": "RSA",
                    "Length": 2048
                },
                "SerialNumber": "0F1E2D3C4B5A69788796A5B4C3D2E1F0",
                "SignatureAlgorithm": "SHA-256withRSA",
                "SignatureHashAlgorithm": "SHA256",
                "SourceBrand": "CertificateManagerSaaS",
                "Status": "ACTIVE",
                "SubjectDN": "cn=portal.example.com,o=Example Ltd,c=US,st=UT,l=SLC",
                "ValidFrom": "2026-02-11T12:36:37Z",
                "ValidTo": "2026-05-12T12:37:07Z",
                "ValidityPeriodSeconds": 7776030
            },
            {
                "CommonName": "internal-api.example.com",
                "DaysUntilExpiry": -135,
                "Fingerprint": "D1E2F3A4B5C6D7E8F9012345678A1B2C3D4E5F60",
                "ID": "4a2b7c10-3333-11ef-9a11-0242ac120004",
                "IsCA": false,
                "IsSelfSigned": false,
                "IssuerCommonName": "CyberArk CM SaaS Built-In Intermediate CA - G1",
                "IssuerDN": "cn=CyberArk CM SaaS Built-In Intermediate CA - G1,ou=Built-in,o=CyberArk Software Ltd.,c=IL",
                "KeyUsages": [
                    "DIGITAL_SIGNATURE",
                    "KEY_ENCIPHERMENT",
                    "KEY_AGREEMENT"
                ],
                "LastModifiedTime": "2026-02-11T16:24:23Z",
                "Name": "internal-api.example.com",
                "Origins": [
                    "USER_PROVIDED"
                ],
                "PublicKey": {
                    "Algorithm": "RSA",
                    "Length": 2048
                },
                "SerialNumber": "1122334455667788",
                "SignatureAlgorithm": "SHA-256withRSA",
                "SignatureHashAlgorithm": "SHA256",
                "SourceBrand": "CertificateManagerSaaS",
                "Status": "ACTIVE",
                "SubjectDN": "cn=internal-api.example.com,o=Example Ltd,c=US,st=UT,l=SLC",
                "ValidFrom": "2026-02-11T16:23:52Z",
                "ValidTo": "2026-05-12T16:24:22Z",
                "ValidityPeriodSeconds": 7776030
            }
        ]
    }
}
```

#### Human Readable Output

>### Certificate Manager SaaS certificates
>
>|Fingerprint|CommonName|IssuerCommonName|Status|ValidTo|DaysUntilExpiry|
>|---|---|---|---|---|---|
>| C1D2E3F405162738495A6B7C8D9EAFB0C1D2E3F4 | portal.example.com | CyberArk CM SaaS Built-In Intermediate CA - G1 | ACTIVE | 2026-05-12T12:37:07Z | -136 |
>| D1E2F3A4B5C6D7E8F9012345678A1B2C3D4E5F60 | internal-api.example.com | CyberArk CM SaaS Built-In Intermediate CA - G1 | ACTIVE | 2026-05-12T16:24:22Z | -135 |
>
>**Note:** the result was truncated. Raise `limit` / `max_pages`, or narrow the search.

### cmsaas-certificate-get

***
Retrieves a single certificate by fingerprint, including its machine installations and TLS server endpoints.

#### Base Command

`cmsaas-certificate-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fingerprint | The certificate fingerprint, with or without separators. | Required |
| include_machine_details | Whether to resolve each installation's device host from the machine detail endpoint. Roughly half of machines carry no host - cloud connectors expose a vault name instead. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.Certificate.ID | String | The Certificate Manager SaaS identifier of the certificate. |
| CertManagerSaaS.Certificate.Fingerprint | String | The fingerprint of the certificate. |
| CertManagerSaaS.Certificate.CommonName | String | The first subject common name of the certificate. |
| CertManagerSaaS.Certificate.SubjectDN | String | The subject distinguished name of the certificate. |
| CertManagerSaaS.Certificate.IssuerDN | String | The issuer distinguished name of the certificate. |
| CertManagerSaaS.Certificate.Status | String | The Certificate Manager SaaS status of the certificate. |
| CertManagerSaaS.Certificate.ValidTo | Date | The timestamp at which the certificate expires. |
| CertManagerSaaS.Certificate.DaysUntilExpiry | Number | Whole days remaining until the certificate expires. Negative once expired. |
| CertManagerSaaS.Certificate.Installations.MachineID | String | The identifier of the machine the certificate is installed on. |
| CertManagerSaaS.Certificate.Installations.MachineName | String | The operator-assigned label of the machine the certificate is installed on. |
| CertManagerSaaS.Certificate.Installations.PluginName | String | The name of the machine plugin that manages the installation. |
| CertManagerSaaS.Certificate.CloudInstallations.ID | String | The identifier of a cloud keystore installation of the certificate. |
| CertManagerSaaS.Certificate.CloudInstallations.Status | String | The status of a cloud keystore installation of the certificate. |
| CertManagerSaaS.Certificate.CloudInstallations.KeystoreID | String | The identifier of the cloud keystore holding the certificate. |
| CertManagerSaaS.Certificate.CloudInstallations.KeystoreName | String | The name of the cloud keystore holding the certificate. |
| CertManagerSaaS.Certificate.CloudInstallations.KeystoreType | String | The type of the cloud keystore holding the certificate, for example AWS Certificate Manager or Azure Key Vault. |
| CertManagerSaaS.Certificate.CloudInstallations.ProviderName | String | The name of the cloud provider connection the keystore belongs to. |
| CertManagerSaaS.Certificate.InstallationLocations | String | Where the certificate is installed, one readable entry per machine or cloud keystore installation. |
| CertManagerSaaS.Certificate.Revocation.Status | String | The revocation status of the certificate. Absent when the certificate was never revoked. |
| CertManagerSaaS.Certificate.Revocation.Reason | String | The reason the certificate was revoked. |
| CertManagerSaaS.Certificate.Revocation.Comment | String | The comment stored with the revocation. |
| CertManagerSaaS.Certificate.Revocation.Error | String | The error the CA returned for a failed revocation. |
| CertManagerSaaS.Certificate.GlobalRevocation.Status | String | Whether the issuing CA's revocation list shows the certificate revoked (REVOKED, NOT_REVOKED or UNKNOWN). Checked against public CAs' revocation lists about every six hours; usually UNKNOWN for private CAs. |
| CertManagerSaaS.Certificate.GlobalRevocation.Reason | String | The revocation reason on the CA's revocation list. |
| CertManagerSaaS.Certificate.GlobalRevocation.RevokedTime | Date | When the CA revoked the certificate, from its revocation list. |
| CertManagerSaaS.Certificate.Installations.Host | String | The normalized device host of the installation. Present only when "include_machine_details" is true and the machine exposes one. |
| CertManagerSaaS.Certificate.SourceBrand | String | The brand of the integration that returned the certificate. Route follow-up commands for this certificate to that integration. |
| CertManagerSaaS.Certificate.SourceInstance | String | The name of the integration instance that returned the certificate. Pass it as using= to send follow-up commands to the tenant that holds the certificate. |

#### Command example

```!cmsaas-certificate-get fingerprint="A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" include_machine_details="true"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Certificate": {
            "CommonName": "shop.example.com",
            "DaysUntilExpiry": 144,
            "Fingerprint": "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
            "ID": "4a2b7c10-3333-11ef-9a11-0242ac120002",
            "InstallationLocations": [
                "Panorama 01 (Palo Alto Panorama Decryption profiles (Preview))"
            ],
            "Installations": [
                {
                    "Host": "203.0.113.10",
                    "ID": "9c2d6f33-2222-11ef-9a11-0242ac120002",
                    "MachineID": "8b1c5e22-1111-11ef-9a11-0242ac120002",
                    "MachineName": "Panorama 01",
                    "PluginName": "Palo Alto Panorama Decryption profiles (Preview)",
                    "Status": "VALIDATED"
                }
            ],
            "IsCA": false,
            "IsSelfSigned": false,
            "IssuerCommonName": "Example Issuing CA",
            "IssuerDN": "cn=Example Issuing CA",
            "KeyUsages": [
                "DIGITAL_SIGNATURE",
                "KEY_ENCIPHERMENT"
            ],
            "LastModifiedTime": "2026-02-18T18:19:45Z",
            "Name": "shop.example.com",
            "Origins": [
                "MACHINE_DISCOVERY"
            ],
            "PublicKey": {
                "Algorithm": "RSA",
                "Length": 2048
            },
            "SerialNumber": "5A6B7C8D",
            "SignatureAlgorithm": "SHA-256withRSA",
            "SignatureHashAlgorithm": "SHA256",
            "SourceBrand": "CertificateManagerSaaS",
            "Status": "ACTIVE",
            "SubjectDN": "cn=shop.example.com",
            "ValidFrom": "2026-02-16T02:59:04Z",
            "ValidTo": "2027-02-16T02:59:04Z",
            "ValidityPeriodSeconds": 31536000
        }
    }
}
```

#### Human Readable Output

>### Certificate A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
>
>|CommonName|DaysUntilExpiry|Fingerprint|ID|InstallationLocations|IsCA|IsSelfSigned|IssuerCommonName|IssuerDN|KeyUsages|LastModifiedTime|Name|Origins|PublicKey|SerialNumber|SignatureAlgorithm|SignatureHashAlgorithm|SourceBrand|Status|SubjectDN|ValidFrom|ValidTo|ValidityPeriodSeconds|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| shop.example.com | 144 | A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 | 4a2b7c10-3333-11ef-9a11-0242ac120002 | Panorama 01 (Palo Alto Panorama Decryption profiles (Preview)) | false | false | Example Issuing CA | cn=Example Issuing CA | DIGITAL_SIGNATURE,<br>KEY_ENCIPHERMENT | 2026-02-18T18:19:45Z | shop.example.com | MACHINE_DISCOVERY | Algorithm: RSA<br>Length: 2048 | 5A6B7C8D | SHA-256withRSA | SHA256 | CertificateManagerSaaS | ACTIVE | cn=shop.example.com | 2026-02-16T02:59:04Z | 2027-02-16T02:59:04Z | 31536000 |
>
>### Machine installations
>
>|MachineName|Host|PluginName|Status|
>|---|---|---|---|
>| Panorama 01 | 203.0.113.10 | Palo Alto Panorama Decryption profiles (Preview) | VALIDATED |

### cmsaas-certificate-list-expiring

***
Lists certificates expiring within a window, soonest first. Only the current, active version of each certificate is listed; replaced (renewed) and retired versions are left out. The window is applied as a server-side filter, so the size of the tenant does not affect the cost of the search.

#### Base Command

`cmsaas-certificate-list-expiring`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| days | The expiry window, in days. Default is 30. | Optional |
| include_expired | Whether to include certificates that have already expired. Possible values are: true, false. Default is false. | Optional |
| limit | Maximum number of certificates to return. Default is 50. | Optional |
| max_pages | Maximum number of 100-certificate pages to scan. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.Certificate.ID | String | The Certificate Manager SaaS identifier of the certificate. |
| CertManagerSaaS.Certificate.Fingerprint | String | The fingerprint of the certificate. |
| CertManagerSaaS.Certificate.CommonName | String | The first subject common name of the certificate. |
| CertManagerSaaS.Certificate.IssuerCommonName | String | The first issuer common name of the certificate. |
| CertManagerSaaS.Certificate.Status | String | The Certificate Manager SaaS status of the certificate. |
| CertManagerSaaS.Certificate.ValidTo | Date | The timestamp at which the certificate expires. |
| CertManagerSaaS.Certificate.DaysUntilExpiry | Number | Whole days remaining until the certificate expires. Negative once expired. |
| CertManagerSaaS.Certificate.Applications.Name | String | The name of an application the certificate is assigned to. |
| CertManagerSaaS.Certificate.SourceBrand | String | The brand of the integration that returned the certificate. Route follow-up commands for this certificate to that integration. |
| CertManagerSaaS.Certificate.SourceInstance | String | The name of the integration instance that returned the certificate. Pass it as using= to send follow-up commands to the tenant that holds the certificate. |

#### Command example

```!cmsaas-certificate-list-expiring days="30" limit="2"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Certificate": [
            {
                "CommonName": "api.example.com",
                "DaysUntilExpiry": 22,
                "Fingerprint": "B1C2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E",
                "ID": "4a2b7c10-3333-11ef-9a11-0242ac120005",
                "IsCA": false,
                "IsPublic": true,
                "IsSelfSigned": false,
                "IssuerCommonName": "Amazon RSA 2048 M01",
                "IssuerDN": "cn=Amazon RSA 2048 M01,o=Amazon,c=US",
                "KeyUsages": [
                    "DIGITAL_SIGNATURE",
                    "KEY_ENCIPHERMENT"
                ],
                "LastModifiedTime": "2026-01-26T18:24:19Z",
                "Name": "api.example.com",
                "Origins": [
                    "EXTERNAL_SCAN"
                ],
                "PublicKey": {
                    "Algorithm": "RSA",
                    "Length": 2048
                },
                "SerialNumber": "0A1B2C3D4E5F60718293A4B5C6D7E8F9",
                "SignatureAlgorithm": "SHA-256withRSA",
                "SignatureHashAlgorithm": "SHA256",
                "SourceBrand": "CertificateManagerSaaS",
                "Status": "ACTIVE",
                "SubjectAlternativeNames": [
                    "api.example.com"
                ],
                "SubjectDN": "cn=api.example.com",
                "ValidFrom": "2025-09-18T00:00:00Z",
                "ValidTo": "2026-10-16T23:59:59Z",
                "ValidityPeriodSeconds": 34041599
            },
            {
                "CommonName": "login.example.com",
                "DaysUntilExpiry": 28,
                "Fingerprint": "E1F2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4",
                "ID": "4a2b7c10-3333-11ef-9a11-0242ac120006",
                "IsCA": false,
                "IsSelfSigned": false,
                "IssuerCommonName": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                "IssuerDN": "cn=DigiCert Global G2 TLS RSA SHA256 2020 CA1,o=DigiCert Inc,c=US",
                "KeyUsages": [
                    "DIGITAL_SIGNATURE",
                    "KEY_ENCIPHERMENT"
                ],
                "LastModifiedTime": "2026-02-09T15:10:25Z",
                "Name": "login.example.com",
                "Origins": [
                    "ON_PREM_CA_IMPORT"
                ],
                "PublicKey": {
                    "Algorithm": "RSA",
                    "Length": 2048
                },
                "SerialNumber": "5A6B7C8D9E0F",
                "SignatureAlgorithm": "SHA-256withRSA",
                "SignatureHashAlgorithm": "SHA256",
                "SourceBrand": "CertificateManagerSaaS",
                "Status": "ACTIVE",
                "SubjectAlternativeNames": [
                    "login.example.com",
                    "www.login.example.com"
                ],
                "SubjectDN": "cn=login.example.com,o=Example Ltd,c=US,st=Utah,l=Salt Lake City",
                "ValidFrom": "2025-10-22T00:00:00Z",
                "ValidTo": "2026-10-22T23:59:59Z",
                "ValidityPeriodSeconds": 31622399
            }
        ]
    }
}
```

#### Human Readable Output

>### Certificate Manager SaaS certificates expiring within 30 day(s)
>
>|Fingerprint|CommonName|IssuerCommonName|Status|ValidTo|DaysUntilExpiry|
>|---|---|---|---|---|---|
>| B1C2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E | api.example.com | Amazon RSA 2048 M01 | ACTIVE | 2026-10-16T23:59:59Z | 22 |
>| E1F2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B4 | login.example.com | DigiCert Global G2 TLS RSA SHA256 2020 CA1 | ACTIVE | 2026-10-22T23:59:59Z | 28 |
>
>**Note:** the result was truncated. Raise `limit` / `max_pages`, or narrow the search.

### cmsaas-application-list

***
Lists the applications defined in Certificate Manager SaaS.

#### Base Command

`cmsaas-application-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of applications to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.Application.ID | String | The identifier of the application. |
| CertManagerSaaS.Application.Name | String | The name of the application. |
| CertManagerSaaS.Application.Description | String | The description of the application. |

#### Command example

```!cmsaas-application-list limit="2"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Application": [
            {
                "ID": "1f0a9d70-0000-11ef-9a11-0242ac120002",
                "Name": "Storefront"
            },
            {
                "ID": "2f0a9d70-0000-11ef-9a11-0242ac120002",
                "Name": "Internal APIs"
            }
        ]
    }
}
```

#### Human Readable Output

>### Certificate Manager SaaS applications
>
>|ID|Name|
>|---|---|
>| 1f0a9d70-0000-11ef-9a11-0242ac120002 | Storefront |
>| 2f0a9d70-0000-11ef-9a11-0242ac120002 | Internal APIs |

### cmsaas-machine-list

***
Lists the machines known to Certificate Manager SaaS. This endpoint returns metadata only - use cmsaas-machine-get for a machine's connection details.

#### Base Command

`cmsaas-machine-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of machines to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.Machine.ID | String | The identifier of the machine. |
| CertManagerSaaS.Machine.Name | String | The operator-assigned label of the machine. |
| CertManagerSaaS.Machine.Status | String | The status of the machine. |
| CertManagerSaaS.Machine.PluginID | String | The identifier of the plugin that manages the machine. |
| CertManagerSaaS.Machine.EdgeInstanceID | String | The identifier of the VSatellite the machine is reached through. |
| CertManagerSaaS.Machine.CreationDate | Date | When the machine record was created. |
| CertManagerSaaS.Machine.ModificationDate | Date | When the machine record was last modified. |

#### Command example

```!cmsaas-machine-list limit="2"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Machine": [
            {
                "CreationDate": "2026-08-27T14:07:25.445+00:00",
                "ID": "5c1e8a40-b79e-11f1-aaca-000000000001",
                "ModificationDate": "2026-08-27T14:07:25.883+00:00",
                "Name": "Load Balancer 01",
                "PluginID": "0b7f4c20-0000-11f1-aaca-000000000003",
                "Status": "VERIFIED"
            },
            {
                "CreationDate": "2026-08-27T14:08:02.937+00:00",
                "ID": "5c1e8a40-b79e-11f1-aaca-000000000002",
                "ModificationDate": "2026-08-27T14:08:03.412+00:00",
                "Name": "Load Balancer 02",
                "PluginID": "0b7f4c20-0000-11f1-aaca-000000000003",
                "Status": "VERIFIED"
            }
        ]
    }
}
```

#### Human Readable Output

>### Certificate Manager SaaS machines
>
>|ID|Name|Status|PluginID|
>|---|---|---|---|
>| 5c1e8a40-b79e-11f1-aaca-000000000001 | Load Balancer 01 | VERIFIED | 0b7f4c20-0000-11f1-aaca-000000000003 |
>| 5c1e8a40-b79e-11f1-aaca-000000000002 | Load Balancer 02 | VERIFIED | 0b7f4c20-0000-11f1-aaca-000000000003 |

### cmsaas-machine-get

***
Retrieves a single machine, including its connection details. This is the only place a device host is exposed.

#### Base Command

`cmsaas-machine-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_identifier | The identifier of the machine. Matches CertManagerSaaS.Certificate.Installations.MachineID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.Machine.ID | String | The identifier of the machine. |
| CertManagerSaaS.Machine.Name | String | The operator-assigned label of the machine. |
| CertManagerSaaS.Machine.Status | String | The status of the machine. |
| CertManagerSaaS.Machine.PluginID | String | The identifier of the plugin that manages the machine. |
| CertManagerSaaS.Machine.Host | String | The normalized device host. Absent for cloud connectors, which expose a vault name instead of an address. |
| CertManagerSaaS.Machine.Port | Number | The port used to reach the machine. |
| CertManagerSaaS.Machine.ConnectionDetails | Unknown | The non-secret connection details of the machine (address, port, vault or project identifiers). Only allow-listed keys are returned. |

#### Command example

```!cmsaas-machine-get machine_identifier="8b1c5e22-1111-11ef-9a11-0242ac120002"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Machine": {
            "ConnectionDetails": {
                "credentialType": "shared",
                "hostnameOrAddress": "203.0.113.10"
            },
            "CreationDate": "2026-02-24T20:55:26.074+00:00",
            "EdgeInstanceID": "0b7f4c20-0000-11f1-aaca-000000000001",
            "Host": "203.0.113.10",
            "ID": "8b1c5e22-1111-11ef-9a11-0242ac120002",
            "ModificationDate": "2026-05-11T15:41:46.644+00:00",
            "Name": "Panorama 01",
            "PluginID": "0b7f4c20-0000-11f1-aaca-000000000002",
            "Status": "VERIFIED"
        }
    }
}
```

#### Human Readable Output

>### Machine 8b1c5e22-1111-11ef-9a11-0242ac120002
>
>|ConnectionDetails|CreationDate|EdgeInstanceID|Host|ID|ModificationDate|Name|PluginID|Status|
>|---|---|---|---|---|---|---|---|---|
>| credentialType: shared<br>hostnameOrAddress: 203.0.113.10 | 2026-02-24T20:55:26.074+00:00 | 0b7f4c20-0000-11f1-aaca-000000000001 | 203.0.113.10 | 8b1c5e22-1111-11ef-9a11-0242ac120002 | 2026-05-11T15:41:46.644+00:00 | Panorama 01 | 0b7f4c20-0000-11f1-aaca-000000000002 | VERIFIED |

### cmsaas-certificate-revoke

***
Revokes a certificate. This command is destructive and cannot be undone: restrict it through Integration Permissions if only some analysts should be able to run it.

#### Base Command

`cmsaas-certificate-revoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fingerprint | The SHA-1 fingerprint of the certificate to revoke, with or without separators. Certificate Manager SaaS keys revocation on the SHA-1 fingerprint; a digest of any other length is rejected before the call is made. | Required |
| reason | The revocation reason recorded with the certificate authority. Possible values are: UNSPECIFIED, KEY_COMPROMISE, AFFILIATION_CHANGED, SUPERSEDED, CESSATION_OF_OPERATION. Default is UNSPECIFIED. | Optional |
| comment | Free text stored on the revocation. Use it to record the case or incident this revocation was performed for, so the action is traceable from Certificate Manager SaaS back to Cortex. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.Certificate.ID | String | The Certificate Manager SaaS identifier of the certificate. |
| CertManagerSaaS.Certificate.Fingerprint | String | The fingerprint of the certificate. |
| CertManagerSaaS.Certificate.CommonName | String | The first subject common name of the certificate. |
| CertManagerSaaS.Certificate.Status | String | The Certificate Manager SaaS status of the certificate. |
| CertManagerSaaS.Certificate.ValidTo | Date | The timestamp at which the certificate expires. |
| CertManagerSaaS.Certificate.Revocation.Status | String | The revocation status of the certificate. |
| CertManagerSaaS.Certificate.Revocation.Reason | String | The reason the certificate was revoked. |
| CertManagerSaaS.Certificate.Revocation.Comment | String | The comment stored with the revocation. |
| CertManagerSaaS.Certificate.Revocation.Error | String | The error the CA returned for a failed revocation. |
| CertManagerSaaS.Certificate.GlobalRevocation.Status | String | Whether the issuing CA's revocation list shows the certificate revoked (REVOKED, NOT_REVOKED or UNKNOWN). Checked against public CAs' revocation lists about every six hours; usually UNKNOWN for private CAs. |
| CertManagerSaaS.Certificate.GlobalRevocation.Reason | String | The revocation reason on the CA's revocation list. |
| CertManagerSaaS.Certificate.GlobalRevocation.RevokedTime | Date | When the CA revoked the certificate, from its revocation list. |
| CertManagerSaaS.Certificate.SourceBrand | String | The brand of the integration that returned the certificate. Route follow-up commands for this certificate to that integration. |
| CertManagerSaaS.Certificate.SourceInstance | String | The name of the integration instance that returned the certificate. Pass it as using= to send follow-up commands to the tenant that holds the certificate. |

#### Command example

```!cmsaas-certificate-revoke fingerprint="A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" reason="KEY_COMPROMISE" comment="Revoked by Cortex (case 4210)."```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Certificate": {
            "CommonName": "shop.example.com",
            "DaysUntilExpiry": 144,
            "Fingerprint": "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
            "ID": "4a2b7c10-3333-11ef-9a11-0242ac120002",
            "InstallationLocations": [
                "Panorama 01 (Palo Alto Panorama Decryption profiles (Preview))"
            ],
            "Installations": [
                {
                    "ID": "9c2d6f33-2222-11ef-9a11-0242ac120002",
                    "MachineID": "8b1c5e22-1111-11ef-9a11-0242ac120002",
                    "MachineName": "Panorama 01",
                    "PluginName": "Palo Alto Panorama Decryption profiles (Preview)",
                    "Status": "VALIDATED"
                }
            ],
            "IsCA": false,
            "IsSelfSigned": false,
            "IssuerCommonName": "Example Issuing CA",
            "IssuerDN": "cn=Example Issuing CA,o=Example Ltd",
            "KeyUsages": [
                "DIGITAL_SIGNATURE",
                "KEY_ENCIPHERMENT"
            ],
            "LastModifiedTime": "2026-02-18T18:19:45Z",
            "Name": "shop.example.com",
            "Origins": [
                "MACHINE_DISCOVERY"
            ],
            "PublicKey": {
                "Algorithm": "RSA",
                "Length": 2048
            },
            "Revocation": {
                "Comment": "Revoked by Cortex (case 4210).",
                "Reason": "KEY_COMPROMISE",
                "Status": "SUBMITTED"
            },
            "SerialNumber": "5A6B7C8D",
            "SignatureAlgorithm": "SHA-256withRSA",
            "SignatureHashAlgorithm": "SHA256",
            "SourceBrand": "CertificateManagerSaaS",
            "Status": "ACTIVE",
            "SubjectDN": "cn=shop.example.com",
            "ValidFrom": "2026-02-16T02:59:04Z",
            "ValidTo": "2027-02-16T02:59:04Z",
            "ValidityPeriodSeconds": 31536000
        }
    }
}
```

#### Human Readable Output

>### Revoked certificate A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
>
>|Fingerprint|CommonName|Status|ValidTo|Revocation|
>|---|---|---|---|---|
>| A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 | shop.example.com | ACTIVE | 2027-02-16T02:59:04Z | Status: SUBMITTED<br>Reason: KEY_COMPROMISE<br>Comment: Revoked by Cortex (case 4210). |

### cmsaas-certificate-request

***
Requests a new certificate. Supply "certificate_signing_request" to submit your own CSR, or "common_name" to have Certificate Manager SaaS generate the key pair and the CSR.

#### Base Command

`cmsaas-certificate-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | The identifier of the application the certificate is requested for. Matches CertManagerSaaS.Application.ID. | Required |
| certificate_issuing_template_id | The identifier of the certificate issuing template to issue under. | Required |
| common_name | The subject common name. Required unless a certificate signing request is supplied. | Optional |
| sans | A comma-separated list of DNS subject alternative names. | Optional |
| ip_sans | A comma-separated list of IP address subject alternative names. | Optional |
| organization | The subject organization. | Optional |
| organizational_units | A comma-separated list of subject organizational units. | Optional |
| locality | The subject locality. | Optional |
| state | The subject state or province. | Optional |
| country | The subject country, as a two-letter code. | Optional |
| key_type | The key algorithm. Only used when Certificate Manager SaaS generates the key pair. Possible values are: RSA, EC. | Optional |
| key_length | The RSA key length, in bits. | Optional |
| key_curve | The elliptic curve, used when "key_type" is EC. Possible values are: P256, P384, P521, ED25519. | Optional |
| validity_period | The requested validity, as an ISO 8601 duration: P1Y for one year, P90D for ninety days, PT2880H for one hundred and twenty days. Omit it to use the issuing template default. | Optional |
| certificate_signing_request | A certificate signing request in PEM format. Supplying it switches the request to "client provides the CSR" mode. | Optional |
| existing_certificate_id | The identifier of the certificate being renewed. Mutually exclusive with "existing_certificate_fingerprint". | Optional |
| existing_certificate_fingerprint | The SHA-1 fingerprint of the certificate being renewed. Mutually exclusive with "existing_certificate_id". A renewal with a service-generated key keeps the old certificate's subject and subject alternative names; only the key settings apply. | Optional |
| tags | A comma-separated list of tags to store on the request. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.CertificateRequest.ID | String | The identifier of the certificate request. |
| CertManagerSaaS.CertificateRequest.Status | String | The status of the certificate request. |
| CertManagerSaaS.CertificateRequest.ApplicationID | String | The identifier of the application the certificate was requested for. |
| CertManagerSaaS.CertificateRequest.CertificateIssuingTemplateID | String | The identifier of the certificate issuing template the request was issued under. |
| CertManagerSaaS.CertificateRequest.CertificateIDs | String | The identifiers of the certificates the request produced. |
| CertManagerSaaS.CertificateRequest.SubjectDN | String | The subject distinguished name of the certificate request. |
| CertManagerSaaS.CertificateRequest.CreationDate | Date | When the certificate request was created. |

#### Command example

```!cmsaas-certificate-request application_id="1f0a9d70-0000-11ef-9a11-0242ac120002" certificate_issuing_template_id="3e5a7b90-4444-11ef-9a11-0242ac120002" common_name="shop.example.com" organization="Example Ltd" validity_period="P90D"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "CertificateRequest": {
            "ApplicationID": "1f0a9d70-0000-11ef-9a11-0242ac120002",
            "CertificateIssuingTemplateID": "3e5a7b90-4444-11ef-9a11-0242ac120002",
            "CreationDate": "2026-09-24T09:00:00.000+00:00",
            "ID": "7d3f1a20-2222-11ef-9a11-0242ac120002",
            "KeyLength": 2048,
            "KeyType": "RSA",
            "Status": "REQUESTED",
            "SubjectDN": "cn=shop.example.com,o=Example Ltd",
            "ValidityPeriod": "P90D"
        }
    }
}
```

#### Human Readable Output

>### Certificate request submitted
>
>|ID|Status|ApplicationID|SubjectDN|CreationDate|
>|---|---|---|---|---|
>| 7d3f1a20-2222-11ef-9a11-0242ac120002 | REQUESTED | 1f0a9d70-0000-11ef-9a11-0242ac120002 | cn=shop.example.com,o=Example Ltd | 2026-09-24T09:00:00.000+00:00 |

### cmsaas-certificate-request-status

***
Retrieves the status of a certificate request, including the identifiers of any certificates it produced and the reason it failed.

#### Base Command

`cmsaas-certificate-request-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The identifier of the certificate request. Matches CertManagerSaaS.CertificateRequest.ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.CertificateRequest.ID | String | The identifier of the certificate request. |
| CertManagerSaaS.CertificateRequest.Status | String | The status of the certificate request: NEW, PENDING, PENDING_APPROVAL, PENDING_FINAL_APPROVAL, REJECTED_APPROVAL, REQUESTED, ISSUED, REJECTED, CANCELLED, REVOKED, FAILED or DELETED. |
| CertManagerSaaS.CertificateRequest.CertificateIDs | String | The identifiers of the certificates the request produced. Use one of these with cmsaas-certificate-download. |
| CertManagerSaaS.CertificateRequest.SubjectDN | String | The subject distinguished name of the certificate request. |
| CertManagerSaaS.CertificateRequest.KeyType | String | The key algorithm of the certificate request. |
| CertManagerSaaS.CertificateRequest.KeyLength | Number | The key length of the certificate request. |
| CertManagerSaaS.CertificateRequest.KeyCurve | String | The elliptic curve of the certificate request. |
| CertManagerSaaS.CertificateRequest.ValidityPeriod | String | The validity period of the certificate request, as an ISO 8601 duration. |
| CertManagerSaaS.CertificateRequest.CreationDate | Date | When the certificate request was created. |
| CertManagerSaaS.CertificateRequest.ModificationDate | Date | When the certificate request was last modified. |
| CertManagerSaaS.CertificateRequest.CertificateAuthorityOrderID | String | The order identifier assigned by the certificate authority. |
| CertManagerSaaS.CertificateRequest.ErrorCode | Number | The error code, when the request failed. |
| CertManagerSaaS.CertificateRequest.ErrorMessage | String | The error message, when the request failed. |

#### Command example

```!cmsaas-certificate-request-status request_id="7d3f1a20-2222-11ef-9a11-0242ac120002"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "CertificateRequest": {
            "CertificateIDs": [
                "4a2b7c10-3333-11ef-9a11-0242ac120002",
                "4a2b7c10-3333-11ef-9a11-0242ac120007",
                "4a2b7c10-3333-11ef-9a11-0242ac120008"
            ],
            "CertificateIssuingTemplateID": "3e5a7b90-4444-11ef-9a11-0242ac120002",
            "CreationDate": "2025-12-10T10:36:41.203+00:00",
            "ID": "7d3f1a20-2222-11ef-9a11-0242ac120002",
            "KeyLength": 2048,
            "KeyType": "RSA",
            "ModificationDate": "2026-06-07T10:37:59.284+00:00",
            "Status": "ISSUED",
            "SubjectDN": "cn=shop.example.com,ou=Network Services,o=Example Ltd,c=US,st=UT,l=SLC",
            "ValidityPeriod": "P90D"
        }
    }
}
```

#### Human Readable Output

>### Certificate request 7d3f1a20-2222-11ef-9a11-0242ac120002
>
>|CertificateIDs|CertificateIssuingTemplateID|CreationDate|ID|KeyLength|KeyType|ModificationDate|Status|SubjectDN|ValidityPeriod|
>|---|---|---|---|---|---|---|---|---|---|
>| 4a2b7c10-3333-11ef-9a11-0242ac120002,<br>4a2b7c10-3333-11ef-9a11-0242ac120007,<br>4a2b7c10-3333-11ef-9a11-0242ac120008 | 3e5a7b90-4444-11ef-9a11-0242ac120002 | 2025-12-10T10:36:41.203+00:00 | 7d3f1a20-2222-11ef-9a11-0242ac120002 | 2048 | RSA | 2026-06-07T10:37:59.284+00:00 | ISSUED | cn=shop.example.com,ou=Network Services,o=Example Ltd,c=US,st=UT,l=SLC | P90D |

### cmsaas-certificate-download

***
Downloads a certificate as a war-room file. This endpoint is keyed on the certificate identifier, not the fingerprint - take it from CertManagerSaaS.Certificate.ID or from a completed certificate request.

#### Base Command

`cmsaas-certificate-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificate_id | The identifier of the certificate. Matches CertManagerSaaS.Certificate.ID. | Required |
| format | The encoding of the downloaded payload. PEM is text and is also placed in the context; DER is binary and is returned as a file only. Possible values are: PEM, DER. Default is PEM. | Optional |
| chain_order | Which certificates of the chain to include, and in what order. Only meaningful for PEM. Omit it to use the tenant default. Possible values are: EE_ONLY, EE_FIRST, ROOT_FIRST. | Optional |
| container_format | The container the certificate is exported in. Omit it to use the tenant default. Possible values are: RAW, PKCS7. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.CertificateContents.ID | String | The identifier of the downloaded certificate. |
| CertManagerSaaS.CertificateContents.Format | String | The encoding of the downloaded payload. |
| CertManagerSaaS.CertificateContents.FileName | String | The name of the war-room file entry. |
| CertManagerSaaS.CertificateContents.Contents | String | The PEM payload. Present only when "format" is PEM. |
| File.Name | String | The name of the downloaded file. |
| File.EntryID | String | The war-room entry identifier of the downloaded file. |
| File.Size | Number | The size of the downloaded file, in bytes. |
| File.SHA256 | String | The SHA-256 digest of the downloaded file. |
| File.Type | String | The type of the downloaded file. |

#### Command example

```!cmsaas-certificate-download certificate_id="4a2b7c10-3333-11ef-9a11-0242ac120002" format="PEM" chain_order="EE_FIRST"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "CertificateContents": {
            "Contents": "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIUExampleOnly...\n-----END CERTIFICATE-----\n",
            "FileName": "4a2b7c10-3333-11ef-9a11-0242ac120002.pem",
            "Format": "PEM",
            "ID": "4a2b7c10-3333-11ef-9a11-0242ac120002"
        }
    }
}
```

#### Human Readable Output

>Downloaded certificate 4a2b7c10-3333-11ef-9a11-0242ac120002 as 4a2b7c10-3333-11ef-9a11-0242ac120002.pem.

### cmsaas-certificate-keystore-download

***
Downloads a certificate with its private key as war-room files. The private key is encrypted with the passphrase and never goes into the context. Works only for a private key that a VSatellite generated. Restrict this command through Integration Permissions: anyone who can see the war room and knows the passphrase can use the key.

#### Base Command

`cmsaas-certificate-keystore-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificate_id | The identifier of the certificate. Matches CertManagerSaaS.Certificate.ID, or a certificate ID of a completed certificate request. | Required |
| passphrase | The passphrase that encrypts the private key (and the PKCS12 file). Leave it empty to use the instance's Keystore passphrase setting, which can come from a saved credential. Anyone who knows it can use the key. | Optional |
| format | The keystore format. PEM returns two files: the encrypted private key (.key) and the certificate chain, leaf first (.pem). PKCS12 returns one .p12 file. Possible values are: PEM, PKCS12. Default is PEM. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.Keystore.CertificateID | String | The identifier of the certificate. |
| CertManagerSaaS.Keystore.Format | String | The keystore format (PEM or PKCS12). |
| CertManagerSaaS.Keystore.PrivateKeyFileName | String | The name of the war-room file with the encrypted private key. PEM only. |
| CertManagerSaaS.Keystore.ChainFileName | String | The name of the war-room file with the certificate chain, leaf first. PEM only. |
| CertManagerSaaS.Keystore.KeystoreFileName | String | The name of the war-room PKCS12 file. PKCS12 only. |
| File.Name | String | The name of the file. |
| File.EntryID | String | The war-room entry identifier of the file. |
| File.Size | Number | The size of the file, in bytes. |
| File.Extension | String | The extension of the file. |
| File.Type | String | The type of the file. |
| File.Info | String | Information about the file. |
| File.MD5 | String | The MD5 hash of the file. |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |

#### Command example

```!cmsaas-certificate-keystore-download certificate_id="4a2b7c10-3333-11ef-9a11-0242ac120002" passphrase="example-passphrase" format="PEM"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Keystore": {
            "CertificateID": "4a2b7c10-3333-11ef-9a11-0242ac120002",
            "ChainFileName": "shop.example.com.pem",
            "Format": "PEM",
            "PrivateKeyFileName": "shop.example.com.key"
        }
    }
}
```

#### Human Readable Output

>### Keystore of certificate 4a2b7c10-3333-11ef-9a11-0242ac120002
>
>|CertificateID|Format|PrivateKeyFileName|ChainFileName|
>|---|---|---|---|
>| 4a2b7c10-3333-11ef-9a11-0242ac120002 | PEM | shop.example.com.key | shop.example.com.pem |
>
>The private key is encrypted with the passphrase you supplied (or with the instance's Keystore passphrase setting when the passphrase argument is empty).
