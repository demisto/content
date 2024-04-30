Retrieves information about certificates stored in Venafi.
This integration was integrated and tested with version xx of Venafi TLS Protect.

## Configure Venafi TLS Protect on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Venafi TLS Protect.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.168.0.1) | True |
    | User Name | True |
    | Password | True |
    | Client ID | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### venafi-get-certificates

***
Gets Venafi certificates query. All dates are in 2016-11-12T00:00:00.0000000Z format. Additional fields can be used in the query by adding them in a key=value format.

#### Base Command

`venafi-get-certificates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| CreatedOn | Specify YYYY-MM-DD or the ISO 8601 format. | Optional | 
| CreatedOnGreater | Specify YYYY-MM-DD or the ISO 8601 format. | Optional | 
| CreatedOnLess | Specify YYYY-MM-DD or the ISO 8601 format. | Optional | 
| Disabled | Include only certificates that are enabled 0 or disabled 1. | Optional | 
| InError | Whether to include only certificates that are in an error state (1) or not in an error state (0). | Optional | 
| ValidationState | Validation state. Possible values: "Blank", "Success", or "Failure". Possible values are: Blank, Success, Failure. | Optional | 
| ManagementType | Management type. Possible values: "Unassigned", "Monitoring", "Enrollment", or "Provisioning". Possible values are: Unassigned, Monitoring, Enrollment, Provisioning. | Optional | 
| Name | Name of the certificate object. | Optional | 
| NetworkValidationDisabled | Whether to include only certificates with network validation disabled (1) or enabled (0). | Optional | 
| ParentDn | The full path to the parent of the object in Trust Protection Platform (e.g., \VED\Policy\Engineering,\VED\Policy\HR). | Optional | 
| ParentDnRecursive | The specific folder from which to retrieve certificates. (The subfolders will also be scanned.) Accepts a single value. | Optional | 
| PendingWorkflow | Whether to include only certificates that are pending workflow resolution (have an outstanding workflow ticket). This parameter does not require a value to be specified. | Optional | 
| Stage | Comma-separated list of stages in the certificate lifecycle. Will retrieve certificates at one or more of the stages. | Optional | 
| StageGreater | Find certificates with a stage greater than the specified stage (does not include specified stage). | Optional | 
| StageLess | Stage before which to retrieve certificates. | Optional | 
| ValidationDisabled | Whether to include only certificates with validation disabled (1) or enabled (0). | Optional | 
| C | Find certificates by Country attribute of Subject DN. | Optional | 
| CN | Find certificates by Common name attribute of Subject DN. | Optional | 
| Issuer | Issuer DN. Note, since most Issuer DNs include commas between DN components, it is important to surround the complete Issuer DN within double quotes (“). In addition, if the Issuer DN includes double quotes, each double quote should be prefixed by another double quote. | Optional | 
| KeyAlgorithm | Algorithm for the public key in the certificate (e.g., RSA, DSA). | Optional | 
| KeySize | Comma-separated list of the bit size of the public key in the certificate (e.g., 2048). | Required | 
| KeySizeGreater | The size for which the public key size is greater than. | Optional | 
| KeySizeLess | The size for which the public key size is less than. | Optional | 
| L | Find certificates by Locality/City attribute of Subject Distinguished Name (SDN). | Optional | 
| O | Find certificates by Organization attribute of Subject DN. | Optional | 
| S | Find certificates by State/Province attribute of Subject DN. | Optional | 
| S | Find certificates by State/Province attribute of Subject DN. | Optional | 
| Serial | Serial number of the certificate. | Optional | 
| SignatureAlgorithm | The algorithm used to sign the certificate (e.g., SHA1RSA). | Optional | 
| ValidFrom | Date on which the certificate was issued (e.g., 2015- 10-08T19:15:35.6431456Z or 2015-10-08). | Optional | 
| ValidTo | Date on which the certificate expires (e.g., 2015-10- 08T19:15:35.6431456Z or 2015-10-08). | Optional | 
| ValidToGreater | Date after which the certificates expire. | Optional | 
| ValidToLess | Date before which the certificates expire. | Optional | 
| Limit | The maximum number of certificates to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Venafi.Certificate.CreatedOn | date | The exact date and time when the certificate object was created. | 
| Venafi.Certificate.DN | string | The DN of the certificate. | 
| Venafi.Certificate.Name | string | The name of the certificate. | 
| Venafi.Certificate.ParentDN | string | The full path to the parent of the object in Trust Protection Platform. | 
| Venafi.Certificate.SchemaClass | string | The class name of the certificate object. | 
| Venafi.Certificate.ID | string | The certificate object GUID. | 
| Venafi.Certificate.X509 | dictionaryv |  | 

### venafi-get-certificate-details

***
Uses a certificate GUID to extract more details from the cert store.

#### Base Command

`venafi-get-certificate-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guid | The id of the certificate, add description that the user can get this value by running the command “venafi-get-certificates”. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Venafi.Certificate.ID | string | The certificate object GUID. | 
| ParentDN | string | The full path to the parent of the object in Trust Protection Platform. | 
| CreatedOn | date | The exact date and time when the Certificate object was created. | 
| DN | string | The DN of the certificate. | 
| Name | string | The name of the certificate. | 
| SchemaClass | string | The class name of the certificate object. | 
| Approver | string | An array of one or more users or groups who are certificate approvers. | 
| CertificateAuthorityDN | string | The CA template that is required for certificate renewal. | 
| Contact | string | An array of one or more users or groups who receive event notifications. The events notify people about certificate expiration and validation failures. | 
| Description | string | Certificate description. | 
| ManagedBy | string | Certificate manager. | 
| ManagementType | string | The level of management that the Trust Protection Platform applies to the certificate. | 
| CertificateDetails.AIAKeyIdentifier | string | Authority key identifier. | 
| CertificateDetails.Issuer | string | The CN, O, L, S, and C values from the certificate request. | 
| CertificateDetails.Serial | string | The unique serial number that the CA assigned to the certificate. | 
| CertificateDetails.Subject | string | The CN, O, L, S, and C values from the certificate request. | 
| CertificateDetails.Thumbprint | string | The SHA1 thumbprint hash of the certificate. | 
| CertificateDetails.ValidFrom | string | Certificate validation start date. | 
| CertificateDetails.ValidTo | string | Certificate validation end time. | 
| CertificateDetails.AIACAIssuerURL | array |  | 
| CertificateDetails.CN | string |  | 
| CertificateDetails.CN | string |  | 
| CertificateDetails.EnhancedKeyUsage | string |  | 
| CertificateDetails.KeyAlgorithm | string |  | 
| CertificateDetails.KeySize | string |  | 
| CertificateDetails.KeyUsage | string |  | 
| CertificateDetails.OU | string |  | 
| CertificateDetails.PublicKeyHash | string |  | 
| CertificateDetails.SKIKeyIdentifier | string |  | 
| CertificateDetails.SignatureAlgorithm | string |  | 
| CertificateDetails.SignatureAlgorithmOID | string |  | 
| CertificateDetails.StoreAdded | string |  | 
| CertificateDetails.SubjectAltNameDNS | string |  | 
| CertificateDetails.SubjectAltNameEmail | string |  | 
| CertificateDetails.SubjectAltNameOtherNameUPN | string |  | 
| CertificateDetails.SubjectAltNameIPAddress | string |  | 
| CertificateDetails.SubjectAltNameURI | string |  | 
| CreatedBy | string |  | 
| Origin | string |  | 
| ProcessingDetails | dictionary |  | 
| RenewalDetails | dictionary |  | 
| ValidationDetails | dictionary |  | 
