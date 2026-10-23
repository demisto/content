Search, inspect and enrich certificates held in Next-Gen Trust Security, reached through the Strata Cloud Manager API gateway, including where each certificate is installed and which tenant service group owns it.
Next-Gen Trust Security is CyberArk Certificate Manager SaaS served through the Strata Cloud Manager gateway. This integration shares its code, its `CertManagerSaaS.*` context, its incident type and its fetch mapper with the Certificate Manager SaaS integration.

## Before you start

You need a Strata Cloud Manager **service account** (client ID and client secret) and the **TSG ID** of the tenant that holds Next-Gen Trust Security. The integration exchanges the client credentials for an access token scoped to that TSG, caches it in the integration context, refreshes it about a minute before it expires, and retries a request once with a fresh token if the gateway rejects the cached one. Changing the client secret, the Token URL or the Server URL invalidates the cached token, and **Test** always requests a new one.

### Service account scope

Use a **tenant-wide service account** and the tenant's TSG ID. NGTS workspaces aren't separate TSGs: they divide the certificates inside one tenant, and the service account's role scope decides which workspaces it can reach. The integration works at tenant level, so an account limited to some workspaces can miss certificates and machines: searches, the expiry fetch and `!certificate` silently leave them out. `CertManagerSaaS.Certificate.TSGID` shows the owner that NGTS reports for each certificate.

### Least-privilege roles

| Setup | Role | Covers |
| --- | --- | --- |
| Read-only | Built-in **View Only Administrator**, or a custom role with the NGTS permission sets `ngts.insights_certificate_inventory`, `ngts.insights_machines_page` and `ngts.configuration_certificate_lifecycle`, all read | Test, fetch, `certificate`, search, get, list-expiring, download, keystore download, machine list and get |
| Full | A custom role with `ngts.insights_certificate_inventory` **write**, `ngts.insights_certificate_requests` **write**, and `ngts.insights_machines_page` and `ngts.configuration_certificate_lifecycle` read | Everything, including request, request-status and revoke |

Revocation needs `ngts.insights_certificate_inventory` write. A missing permission is reported as HTTP 403.

## Configure Next-Gen Trust Security in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Strata Cloud Manager API gateway, including the /ngts path. | True |
| Token URL | The Strata Cloud Manager OAuth2 token endpoint. Change it only together with the Server URL, for a non-production environment. | True |
| Client ID | The client ID and client secret of a Strata Cloud Manager service account. See the integration help for the roles it needs. | True |
| Client Secret |  | True |
| TSG ID | The tenant service group \(TSG\) ID the access token is scoped to. Use the tenant's TSG ID; NGTS workspaces aren't separate TSGs. | True |
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

Fetching works exactly as in the Certificate Manager SaaS integration: one incident of type **CertManagerSaaS Certificate Expiry** per expiry threshold a certificate crosses - 30 days (High) and 7 days (Critical) - deduplicated on `fingerprint:threshold`, and mapped by *CertManagerSaaS - Fetch Incoming Mapper*. The raw JSON carries `SourceBrand` (`NextGenTrustSecurity`), so a playbook can send follow-up commands to the integration that found the certificate.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### certificate

***
Enriches certificate indicators from the Next-Gen Trust Security inventory. Accepts certificate fingerprints (hexadecimal digests, with or without separators).

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
| CertManagerSaaS.Certificate.ID | String | The Next-Gen Trust Security identifier of the certificate. |
| CertManagerSaaS.Certificate.Fingerprint | String | The fingerprint of the certificate. |
| CertManagerSaaS.Certificate.CommonName | String | The first subject common name of the certificate. |
| CertManagerSaaS.Certificate.Status | String | The Next-Gen Trust Security status of the certificate. |
| CertManagerSaaS.Certificate.ValidTo | Date | The timestamp at which the certificate expires. |
| CertManagerSaaS.Certificate.DaysUntilExpiry | Number | Whole days remaining until the certificate expires. Negative once expired. |
| CertManagerSaaS.Certificate.TSGID | String | The owner of the certificate - the TSG ID for a tenant-owned certificate, otherwise the workspace ID. |
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
            "DaysUntilExpiry": 19,
            "Fingerprint": "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
            "ID": "4a2b7c10-3333-11ef-9a11-0242ac120002",
            "IsCA": false,
            "IsSelfSigned": false,
            "IssuerCommonName": "CyberArk CM SaaS Built-In Intermediate CA - G1",
            "IssuerDN": "cn=CyberArk CM SaaS Built-In Intermediate CA - G1,ou=Built-in,o=CyberArk Software Ltd.,c=IL",
            "KeyUsages": [
                "DIGITAL_SIGNATURE",
                "KEY_ENCIPHERMENT",
                "KEY_AGREEMENT"
            ],
            "LastModifiedTime": "2026-09-23T22:07:34Z",
            "Name": "shop.example.com",
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
            "SourceBrand": "NextGenTrustSecurity",
            "Status": "ACTIVE",
            "SubjectAlternativeNames": [
                "shop.example.com"
            ],
            "SubjectDN": "cn=shop.example.com,o=Example Ltd",
            "TSGID": "1234567890",
            "ValidFrom": "2026-09-23T22:07:04Z",
            "ValidTo": "2026-10-13T22:07:34Z",
            "ValidityPeriodSeconds": 1728030
        }
    },
    "Certificate": {
        "IssuerDN": "cn=CyberArk CM SaaS Built-In Intermediate CA - G1,ou=Built-in,o=CyberArk Software Ltd.,c=IL",
        "Name": [
            "shop.example.com"
        ],
        "PublicKey": {
            "Algorithm": "RSA",
            "Length": 2048
        },
        "SHA1": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
        "SerialNumber": "0F1E2D3C4B5A69788796A5B4C3D2E1F0",
        "Signature": {
            "Algorithm": "SHA-256withRSA"
        },
        "SubjectAlternativeName": [
            {
                "Value": "shop.example.com"
            }
        ],
        "SubjectDN": "cn=shop.example.com,o=Example Ltd",
        "ValidityNotAfter": "2026-10-13T22:07:34Z",
        "ValidityNotBefore": "2026-09-23T22:07:04Z"
    },
    "DBotScore": {
        "Indicator": "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "certificate",
        "Vendor": "Next-Gen Trust Security"
    }
}
```

#### Human Readable Output

>### Certificate A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
>
>|Fingerprint|CommonName|IssuerCommonName|Status|ValidTo|DaysUntilExpiry|
>|---|---|---|---|---|---|
>| A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 | shop.example.com | CyberArk CM SaaS Built-In Intermediate CA - G1 | ACTIVE | 2026-10-13T22:07:34Z | 19 |

### ngts-certificate-search

***
Searches the Next-Gen Trust Security certificate inventory. Only "fingerprint" is filtered server-side; the remaining criteria are applied client-side while paging through the inventory, so a broad search may need "max_pages" raised.

#### Base Command

`ngts-certificate-search`

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
| CertManagerSaaS.Certificate.ID | String | The Next-Gen Trust Security identifier of the certificate. |
| CertManagerSaaS.Certificate.Name | String | The Next-Gen Trust Security name of the certificate. |
| CertManagerSaaS.Certificate.Fingerprint | String | The fingerprint of the certificate. |
| CertManagerSaaS.Certificate.SerialNumber | String | The serial number of the certificate. |
| CertManagerSaaS.Certificate.Status | String | The Next-Gen Trust Security status of the certificate. |
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
| CertManagerSaaS.Certificate.Origins | String | How the certificate entered the Next-Gen Trust Security inventory. |
| CertManagerSaaS.Certificate.LastModifiedTime | Date | When the certificate record was last modified. |
| CertManagerSaaS.Certificate.SubjectAlternativeNames | String | The subject alternative names of the certificate. |
| CertManagerSaaS.Certificate.PublicKey.Algorithm | String | The public key algorithm of the certificate. |
| CertManagerSaaS.Certificate.PublicKey.Length | Number | The public key length of the certificate. |
| CertManagerSaaS.Certificate.PublicKey.Curve | String | The elliptic curve of the certificate public key. |
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
| CertManagerSaaS.Certificate.TSGID | String | The owner of the certificate - the TSG ID for a tenant-owned certificate, otherwise the workspace ID. |
| CertManagerSaaS.Certificate.SourceBrand | String | The brand of the integration that returned the certificate. Route follow-up commands for this certificate to that integration. |
| CertManagerSaaS.Certificate.SourceInstance | String | The name of the integration instance that returned the certificate. Pass it as using= to send follow-up commands to the tenant that holds the certificate. |

#### Command example

```!ngts-certificate-search common_name="example.com" limit="2"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Certificate": [
            {
                "CommonName": "shop.example.com",
                "DaysUntilExpiry": 19,
                "Fingerprint": "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
                "ID": "4a2b7c10-3333-11ef-9a11-0242ac120002",
                "IsCA": false,
                "IsSelfSigned": false,
                "IssuerCommonName": "CyberArk CM SaaS Built-In Intermediate CA - G1",
                "IssuerDN": "cn=CyberArk CM SaaS Built-In Intermediate CA - G1,ou=Built-in,o=CyberArk Software Ltd.,c=IL",
                "KeyUsages": [
                    "DIGITAL_SIGNATURE",
                    "KEY_ENCIPHERMENT",
                    "KEY_AGREEMENT"
                ],
                "LastModifiedTime": "2026-09-23T22:07:34Z",
                "Name": "shop.example.com",
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
                "SourceBrand": "NextGenTrustSecurity",
                "Status": "ACTIVE",
                "SubjectAlternativeNames": [
                    "shop.example.com"
                ],
                "SubjectDN": "cn=shop.example.com,o=Example Ltd",
                "TSGID": "1234567890",
                "ValidFrom": "2026-09-23T22:07:04Z",
                "ValidTo": "2026-10-13T22:07:34Z",
                "ValidityPeriodSeconds": 1728030
            },
            {
                "CommonName": "portal.example.com",
                "DaysUntilExpiry": 4,
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
                "LastModifiedTime": "2026-09-23T22:07:34Z",
                "Name": "portal.example.com",
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
                "SourceBrand": "NextGenTrustSecurity",
                "Status": "ACTIVE",
                "SubjectAlternativeNames": [
                    "portal.example.com"
                ],
                "SubjectDN": "cn=portal.example.com,o=Example Ltd",
                "TSGID": "1234567890",
                "ValidFrom": "2026-09-23T22:07:03Z",
                "ValidTo": "2026-09-28T22:07:33Z",
                "ValidityPeriodSeconds": 432030
            }
        ]
    }
}
```

#### Human Readable Output

>### Next-Gen Trust Security certificates
>
>|Fingerprint|CommonName|IssuerCommonName|Status|ValidTo|DaysUntilExpiry|
>|---|---|---|---|---|---|
>| A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 | shop.example.com | CyberArk CM SaaS Built-In Intermediate CA - G1 | ACTIVE | 2026-10-13T22:07:34Z | 19 |
>| C1D2E3F405162738495A6B7C8D9EAFB0C1D2E3F4 | portal.example.com | CyberArk CM SaaS Built-In Intermediate CA - G1 | ACTIVE | 2026-09-28T22:07:33Z | 4 |
>
>**Note:** the result was truncated. Raise `limit` / `max_pages`, or narrow the search.

### ngts-certificate-get

***
Retrieves a single certificate by fingerprint, including its machine installations and TLS server endpoints.

#### Base Command

`ngts-certificate-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fingerprint | The certificate fingerprint, with or without separators. | Required |
| include_machine_details | Whether to resolve each installation's device host from the machine detail endpoint. Roughly half of machines carry no host - cloud connectors expose a vault name instead. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.Certificate.ID | String | The Next-Gen Trust Security identifier of the certificate. |
| CertManagerSaaS.Certificate.Fingerprint | String | The fingerprint of the certificate. |
| CertManagerSaaS.Certificate.CommonName | String | The first subject common name of the certificate. |
| CertManagerSaaS.Certificate.SubjectDN | String | The subject distinguished name of the certificate. |
| CertManagerSaaS.Certificate.IssuerDN | String | The issuer distinguished name of the certificate. |
| CertManagerSaaS.Certificate.Status | String | The Next-Gen Trust Security status of the certificate. |
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
| CertManagerSaaS.Certificate.TSGID | String | The owner of the certificate - the TSG ID for a tenant-owned certificate, otherwise the workspace ID. |
| CertManagerSaaS.Certificate.SourceBrand | String | The brand of the integration that returned the certificate. Route follow-up commands for this certificate to that integration. |
| CertManagerSaaS.Certificate.SourceInstance | String | The name of the integration instance that returned the certificate. Pass it as using= to send follow-up commands to the tenant that holds the certificate. |

#### Command example

```!ngts-certificate-get fingerprint="B1C2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E" include_machine_details="true"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Certificate": {
            "CommonName": "Example Root CA",
            "DaysUntilExpiry": 500,
            "Fingerprint": "B1C2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E",
            "ID": "4a2b7c10-3333-11ef-9a11-0242ac120005",
            "InstallationLocations": [
                "Keystore 01 (Common KeyStore (PEM, JKS, PKCS#12))"
            ],
            "Installations": [
                {
                    "Host": "203.0.113.10",
                    "ID": "9c2d6f33-2222-11ef-9a11-0242ac120002",
                    "MachineID": "8b1c5e22-1111-11ef-9a11-0242ac120002",
                    "MachineName": "Keystore 01",
                    "PluginName": "Common KeyStore (PEM, JKS, PKCS#12)",
                    "Status": "DISCOVERED"
                }
            ],
            "IsCA": true,
            "IsSelfSigned": true,
            "IssuerCommonName": "Example Root CA",
            "IssuerDN": "cn=Example Root CA,0.9.2342.19200300.100.1.25=com,0.9.2342.19200300.100.1.25=example",
            "KeyUsages": [
                "DIGITAL_SIGNATURE",
                "KEY_CERT_SIGN",
                "CRL_SIGN"
            ],
            "LastModifiedTime": "2026-09-23T23:06:56Z",
            "Name": "Example Root CA",
            "Origins": [
                "MACHINE_DISCOVERY"
            ],
            "PublicKey": {
                "Algorithm": "RSA",
                "Length": 2048
            },
            "SerialNumber": "0A1B2C3D4E5F60718293A4B5C6D7E8F9",
            "SignatureAlgorithm": "SHA-256withRSA",
            "SignatureHashAlgorithm": "SHA256",
            "SourceBrand": "NextGenTrustSecurity",
            "Status": "ACTIVE",
            "SubjectDN": "cn=Example Root CA,0.9.2342.19200300.100.1.25=com,0.9.2342.19200300.100.1.25=example",
            "TSGID": "1234567890",
            "ValidFrom": "2022-02-07T10:50:48Z",
            "ValidTo": "2028-02-07T11:00:48Z",
            "ValidityPeriodSeconds": 189303000
        }
    }
}
```

#### Human Readable Output

>### Certificate B1C2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E
>
>|CommonName|DaysUntilExpiry|Fingerprint|ID|InstallationLocations|IsCA|IsSelfSigned|IssuerCommonName|IssuerDN|KeyUsages|LastModifiedTime|Name|Origins|PublicKey|SerialNumber|SignatureAlgorithm|SignatureHashAlgorithm|SourceBrand|Status|SubjectDN|TSGID|ValidFrom|ValidTo|ValidityPeriodSeconds|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Example Root CA | 500 | B1C2D3E4F5061728394A5B6C7D8E9F0A1B2C3D4E | 4a2b7c10-3333-11ef-9a11-0242ac120005 | Keystore 01 (Common KeyStore (PEM, JKS, PKCS#12)) | true | true | Example Root CA | cn=Example Root CA,0.9.2342.19200300.100.1.25=com,0.9.2342.19200300.100.1.25=example | DIGITAL_SIGNATURE,<br>KEY_CERT_SIGN,<br>CRL_SIGN | 2026-09-23T23:06:56Z | Example Root CA | MACHINE_DISCOVERY | Algorithm: RSA<br>Length: 2048 | 0A1B2C3D4E5F60718293A4B5C6D7E8F9 | SHA-256withRSA | SHA256 | NextGenTrustSecurity | ACTIVE | cn=Example Root CA,0.9.2342.19200300.100.1.25=com,0.9.2342.19200300.100.1.25=example | 1234567890 | 2022-02-07T10:50:48Z | 2028-02-07T11:00:48Z | 189303000 |
>
>### Machine installations
>
>|MachineName|Host|PluginName|Status|
>|---|---|---|---|
>| Keystore 01 | 203.0.113.10 | Common KeyStore (PEM, JKS, PKCS#12) | DISCOVERED |

### ngts-certificate-list-expiring

***
Lists certificates expiring within a window, soonest first. Only the current, active version of each certificate is listed; replaced (renewed) and retired versions are left out. The window is applied as a server-side filter, so the size of the tenant does not affect the cost of the search.

#### Base Command

`ngts-certificate-list-expiring`

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
| CertManagerSaaS.Certificate.ID | String | The Next-Gen Trust Security identifier of the certificate. |
| CertManagerSaaS.Certificate.Fingerprint | String | The fingerprint of the certificate. |
| CertManagerSaaS.Certificate.CommonName | String | The first subject common name of the certificate. |
| CertManagerSaaS.Certificate.IssuerCommonName | String | The first issuer common name of the certificate. |
| CertManagerSaaS.Certificate.Status | String | The Next-Gen Trust Security status of the certificate. |
| CertManagerSaaS.Certificate.ValidTo | Date | The timestamp at which the certificate expires. |
| CertManagerSaaS.Certificate.DaysUntilExpiry | Number | Whole days remaining until the certificate expires. Negative once expired. |
| CertManagerSaaS.Certificate.TSGID | String | The owner of the certificate - the TSG ID for a tenant-owned certificate, otherwise the workspace ID. |
| CertManagerSaaS.Certificate.SourceBrand | String | The brand of the integration that returned the certificate. Route follow-up commands for this certificate to that integration. |
| CertManagerSaaS.Certificate.SourceInstance | String | The name of the integration instance that returned the certificate. Pass it as using= to send follow-up commands to the tenant that holds the certificate. |

#### Command example

```!ngts-certificate-list-expiring days="30" limit="2"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Certificate": [
            {
                "CommonName": "portal.example.com",
                "DaysUntilExpiry": 4,
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
                "LastModifiedTime": "2026-09-23T22:07:34Z",
                "Name": "portal.example.com",
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
                "SourceBrand": "NextGenTrustSecurity",
                "Status": "ACTIVE",
                "SubjectAlternativeNames": [
                    "portal.example.com"
                ],
                "SubjectDN": "cn=portal.example.com,o=Example Ltd",
                "TSGID": "1234567890",
                "ValidFrom": "2026-09-23T22:07:03Z",
                "ValidTo": "2026-09-28T22:07:33Z",
                "ValidityPeriodSeconds": 432030
            },
            {
                "CommonName": "shop.example.com",
                "DaysUntilExpiry": 19,
                "Fingerprint": "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
                "ID": "4a2b7c10-3333-11ef-9a11-0242ac120002",
                "IsCA": false,
                "IsSelfSigned": false,
                "IssuerCommonName": "CyberArk CM SaaS Built-In Intermediate CA - G1",
                "IssuerDN": "cn=CyberArk CM SaaS Built-In Intermediate CA - G1,ou=Built-in,o=CyberArk Software Ltd.,c=IL",
                "KeyUsages": [
                    "DIGITAL_SIGNATURE",
                    "KEY_ENCIPHERMENT",
                    "KEY_AGREEMENT"
                ],
                "LastModifiedTime": "2026-09-23T22:07:34Z",
                "Name": "shop.example.com",
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
                "SourceBrand": "NextGenTrustSecurity",
                "Status": "ACTIVE",
                "SubjectAlternativeNames": [
                    "shop.example.com"
                ],
                "SubjectDN": "cn=shop.example.com,o=Example Ltd",
                "TSGID": "1234567890",
                "ValidFrom": "2026-09-23T22:07:04Z",
                "ValidTo": "2026-10-13T22:07:34Z",
                "ValidityPeriodSeconds": 1728030
            }
        ]
    }
}
```

#### Human Readable Output

>### Next-Gen Trust Security certificates expiring within 30 day(s)
>
>|Fingerprint|CommonName|IssuerCommonName|Status|ValidTo|DaysUntilExpiry|
>|---|---|---|---|---|---|
>| C1D2E3F405162738495A6B7C8D9EAFB0C1D2E3F4 | portal.example.com | CyberArk CM SaaS Built-In Intermediate CA - G1 | ACTIVE | 2026-09-28T22:07:33Z | 4 |
>| A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 | shop.example.com | CyberArk CM SaaS Built-In Intermediate CA - G1 | ACTIVE | 2026-10-13T22:07:34Z | 19 |
>
>**Note:** the result was truncated. Raise `limit` / `max_pages`, or narrow the search.

### ngts-machine-list

***
Lists the machines known to Next-Gen Trust Security. This endpoint returns metadata only - use ngts-machine-get for a machine's connection details.

#### Base Command

`ngts-machine-list`

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

```!ngts-machine-list limit="2"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Machine": {
            "CreationDate": "2026-09-23T23:06:44.118+00:00",
            "EdgeInstanceID": "0b7f4c20-0000-11f1-aaca-000000000001",
            "ID": "8b1c5e22-1111-11ef-9a11-0242ac120002",
            "ModificationDate": "2026-09-23T23:06:45.786+00:00",
            "Name": "Keystore 01",
            "PluginID": "0b7f4c20-0000-11f1-aaca-000000000002",
            "Status": "VERIFIED"
        }
    }
}
```

#### Human Readable Output

>### Next-Gen Trust Security machines
>
>|ID|Name|Status|PluginID|
>|---|---|---|---|
>| 8b1c5e22-1111-11ef-9a11-0242ac120002 | Keystore 01 | VERIFIED | 0b7f4c20-0000-11f1-aaca-000000000002 |

### ngts-machine-get

***
Retrieves a single machine, including its connection details. This is the only place a device host is exposed.

#### Base Command

`ngts-machine-get`

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
| CertManagerSaaS.Machine.ConnectionDetails | Unknown | The non-secret connection details of the machine \(address, port, vault or project identifiers\). Only allow-listed keys are returned. |

#### Command example

```!ngts-machine-get machine_identifier="8b1c5e22-1111-11ef-9a11-0242ac120002"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Machine": {
            "ConnectionDetails": {
                "protocol": "ssh2",
                "protocolSsh": {
                    "hostnameOrAddress": "203.0.113.10",
                    "port": 22
                }
            },
            "CreationDate": "2026-09-23T23:06:44.118+00:00",
            "EdgeInstanceID": "0b7f4c20-0000-11f1-aaca-000000000001",
            "Host": "203.0.113.10",
            "ID": "8b1c5e22-1111-11ef-9a11-0242ac120002",
            "ModificationDate": "2026-09-23T23:06:45.786+00:00",
            "Name": "Keystore 01",
            "PluginID": "0b7f4c20-0000-11f1-aaca-000000000002",
            "Port": 22,
            "Status": "VERIFIED"
        }
    }
}
```

#### Human Readable Output

>### Machine 8b1c5e22-1111-11ef-9a11-0242ac120002
>
>|ConnectionDetails|CreationDate|EdgeInstanceID|Host|ID|ModificationDate|Name|PluginID|Port|Status|
>|---|---|---|---|---|---|---|---|---|---|
>| protocol: ssh2<br>protocolSsh: {"hostnameOrAddress": "203.0.113.10", "port": 22} | 2026-09-23T23:06:44.118+00:00 | 0b7f4c20-0000-11f1-aaca-000000000001 | 203.0.113.10 | 8b1c5e22-1111-11ef-9a11-0242ac120002 | 2026-09-23T23:06:45.786+00:00 | Keystore 01 | 0b7f4c20-0000-11f1-aaca-000000000002 | 22 | VERIFIED |

### ngts-certificate-revoke

***
Revokes a certificate. This command is destructive and cannot be undone: restrict it through Integration Permissions if only some analysts should be able to run it. If a revocation approval rule covers the certificate's CA, NGTS refuses the request and nothing is changed; see Revocation approval rules in the integration help.

#### Base Command

`ngts-certificate-revoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fingerprint | The SHA-1 fingerprint of the certificate to revoke, with or without separators. Next-Gen Trust Security keys revocation on the SHA-1 fingerprint; a digest of any other length is rejected before the call is made. | Required |
| reason | The revocation reason recorded with the certificate authority. Possible values are: UNSPECIFIED, KEY_COMPROMISE, AFFILIATION_CHANGED, SUPERSEDED, CESSATION_OF_OPERATION. Default is UNSPECIFIED. | Optional |
| comment | Free text stored on the revocation. Use it to record the case or incident this revocation was performed for, so the action is traceable from Next-Gen Trust Security back to Cortex. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.Certificate.ID | String | The Next-Gen Trust Security identifier of the certificate. |
| CertManagerSaaS.Certificate.Fingerprint | String | The fingerprint of the certificate. |
| CertManagerSaaS.Certificate.CommonName | String | The first subject common name of the certificate. |
| CertManagerSaaS.Certificate.Status | String | The Next-Gen Trust Security status of the certificate. |
| CertManagerSaaS.Certificate.ValidTo | Date | The timestamp at which the certificate expires. |
| CertManagerSaaS.Certificate.Revocation.Status | String | The revocation status of the certificate. |
| CertManagerSaaS.Certificate.Revocation.Reason | String | The reason the certificate was revoked. |
| CertManagerSaaS.Certificate.Revocation.Comment | String | The comment stored with the revocation. |
| CertManagerSaaS.Certificate.Revocation.Error | String | The error the CA returned for a failed revocation. |
| CertManagerSaaS.Certificate.GlobalRevocation.Status | String | Whether the issuing CA's revocation list shows the certificate revoked (REVOKED, NOT_REVOKED or UNKNOWN). Checked against public CAs' revocation lists about every six hours; usually UNKNOWN for private CAs. |
| CertManagerSaaS.Certificate.GlobalRevocation.Reason | String | The revocation reason on the CA's revocation list. |
| CertManagerSaaS.Certificate.GlobalRevocation.RevokedTime | Date | When the CA revoked the certificate, from its revocation list. |
| CertManagerSaaS.Certificate.TSGID | String | The owner of the certificate - the TSG ID for a tenant-owned certificate, otherwise the workspace ID. |
| CertManagerSaaS.Certificate.SourceBrand | String | The brand of the integration that returned the certificate. Route follow-up commands for this certificate to that integration. |
| CertManagerSaaS.Certificate.SourceInstance | String | The name of the integration instance that returned the certificate. Pass it as using= to send follow-up commands to the tenant that holds the certificate. |

#### Command example

```!ngts-certificate-revoke fingerprint="A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" reason="KEY_COMPROMISE" comment="Revoked by Cortex (case 4210)."```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "Certificate": {
            "CommonName": "shop.example.com",
            "DaysUntilExpiry": 19,
            "Fingerprint": "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678",
            "ID": "4a2b7c10-3333-11ef-9a11-0242ac120002",
            "IsCA": false,
            "IsSelfSigned": false,
            "IssuerCommonName": "Example Issuing CA",
            "IssuerDN": "cn=Example Issuing CA,o=Example Ltd",
            "KeyUsages": [
                "DIGITAL_SIGNATURE",
                "KEY_ENCIPHERMENT",
                "KEY_AGREEMENT"
            ],
            "LastModifiedTime": "2026-09-23T22:07:34Z",
            "Name": "shop.example.com",
            "Origins": [
                "USER_PROVIDED"
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
            "SerialNumber": "0F1E2D3C4B5A69788796A5B4C3D2E1F0",
            "SignatureAlgorithm": "SHA-256withRSA",
            "SignatureHashAlgorithm": "SHA256",
            "SourceBrand": "NextGenTrustSecurity",
            "Status": "ACTIVE",
            "SubjectAlternativeNames": [
                "shop.example.com"
            ],
            "SubjectDN": "cn=shop.example.com,o=Example Ltd",
            "TSGID": "1234567890",
            "ValidFrom": "2026-09-23T22:07:04Z",
            "ValidTo": "2026-10-13T22:07:34Z",
            "ValidityPeriodSeconds": 1728030
        }
    }
}
```

#### Human Readable Output

>### Revoked certificate A1B2C3D4E5F60718293A4B5C6D7E8F9012345678
>
>|Fingerprint|CommonName|Status|ValidTo|Revocation|
>|---|---|---|---|---|
>| A1B2C3D4E5F60718293A4B5C6D7E8F9012345678 | shop.example.com | ACTIVE | 2026-10-13T22:07:34Z | Status: SUBMITTED<br>Reason: KEY_COMPROMISE<br>Comment: Revoked by Cortex (case 4210). |

### ngts-certificate-request

***
Requests a new certificate. Supply "certificate_signing_request" to submit your own CSR, or "common_name" to have Next-Gen Trust Security generate the key pair and the CSR.

#### Base Command

`ngts-certificate-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificate_issuing_template_id | The identifier of the certificate issuing template to issue under. | Required |
| common_name | The subject common name. Required unless a certificate signing request is supplied. | Optional |
| sans | A comma-separated list of DNS subject alternative names. | Optional |
| ip_sans | A comma-separated list of IP address subject alternative names. | Optional |
| organization | The subject organization. | Optional |
| organizational_units | A comma-separated list of subject organizational units. | Optional |
| locality | The subject locality. | Optional |
| state | The subject state or province. | Optional |
| country | The subject country, as a two-letter code. | Optional |
| key_type | The key algorithm. Only used when Next-Gen Trust Security generates the key pair. Possible values are: RSA, EC. | Optional |
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
| CertManagerSaaS.CertificateRequest.CertificateIssuingTemplateID | String | The identifier of the certificate issuing template the request was issued under. |
| CertManagerSaaS.CertificateRequest.CertificateIDs | String | The identifiers of the certificates the request produced. |
| CertManagerSaaS.CertificateRequest.SubjectDN | String | The subject distinguished name of the certificate request. |
| CertManagerSaaS.CertificateRequest.CreationDate | Date | When the certificate request was created. |

#### Command example

```!ngts-certificate-request certificate_issuing_template_id="3e5a7b90-4444-11ef-9a11-0242ac120002" common_name="shop.example.com" organization="Example Ltd" validity_period="P90D"```

#### Context Example

```json
{
    "CertManagerSaaS": {
        "CertificateRequest": {
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
>|ID|Status|SubjectDN|CreationDate|
>|---|---|---|---|
>| 7d3f1a20-2222-11ef-9a11-0242ac120002 | REQUESTED | cn=shop.example.com,o=Example Ltd | 2026-09-24T09:00:00.000+00:00 |

### ngts-certificate-request-status

***
Retrieves the status of a certificate request, including the identifiers of any certificates it produced and the reason it failed.

#### Base Command

`ngts-certificate-request-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The identifier of the certificate request. Matches CertManagerSaaS.CertificateRequest.ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CertManagerSaaS.CertificateRequest.ID | String | The identifier of the certificate request. |
| CertManagerSaaS.CertificateRequest.Status | String | The status of the certificate request: NEW, PENDING, PENDING_APPROVAL, PENDING_FINAL_APPROVAL, REJECTED_APPROVAL, REQUESTED, ISSUED, REJECTED, CANCELLED, REVOKED, FAILED or DELETED. |
| CertManagerSaaS.CertificateRequest.CertificateIDs | String | The identifiers of the certificates the request produced. Use one of these with ngts-certificate-download. |
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

```!ngts-certificate-request-status request_id="7d3f1a20-2222-11ef-9a11-0242ac120002"```

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
            "CreationDate": "2026-09-23T22:07:34.440+00:00",
            "ID": "7d3f1a20-2222-11ef-9a11-0242ac120002",
            "KeyLength": 2048,
            "KeyType": "RSA",
            "ModificationDate": "2026-09-23T22:07:35.852+00:00",
            "Status": "ISSUED",
            "SubjectDN": "cn=shop.example.com,o=Example Ltd",
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
>| 4a2b7c10-3333-11ef-9a11-0242ac120002,<br>4a2b7c10-3333-11ef-9a11-0242ac120007,<br>4a2b7c10-3333-11ef-9a11-0242ac120008 | 3e5a7b90-4444-11ef-9a11-0242ac120002 | 2026-09-23T22:07:34.440+00:00 | 7d3f1a20-2222-11ef-9a11-0242ac120002 | 2048 | RSA | 2026-09-23T22:07:35.852+00:00 | ISSUED | cn=shop.example.com,o=Example Ltd | P90D |

### ngts-certificate-download

***
Downloads a certificate as a war-room file. This endpoint is keyed on the certificate identifier, not the fingerprint - take it from CertManagerSaaS.Certificate.ID or from a completed certificate request.

#### Base Command

`ngts-certificate-download`

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

```!ngts-certificate-download certificate_id="4a2b7c10-3333-11ef-9a11-0242ac120002" format="PEM" chain_order="EE_FIRST"```

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

### ngts-certificate-keystore-download

***
Downloads a certificate with its private key as war-room files. The private key is encrypted with the passphrase and never goes into the context. Works only for a private key that a VSatellite generated. Restrict this command through Integration Permissions: anyone who can see the war room and knows the passphrase can use the key.

#### Base Command

`ngts-certificate-keystore-download`

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

```!ngts-certificate-keystore-download certificate_id="4a2b7c10-3333-11ef-9a11-0242ac120002" passphrase="example-passphrase" format="PEM"```

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
