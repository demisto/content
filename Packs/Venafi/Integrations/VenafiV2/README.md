Retrieves information about certificates stored in Venafi.

## Configure Venafi TLS Protect on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Venafi TLS Protect.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., https://192.168.0.1) | True |
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
Gets Venafi certificates query. All dates are in 2016-11-12T00:00:00.0000000Z format. For additional field information, see: https://ao-tlspd.dev.ven-eco.com/aperture/help/Content/SDK/WebSDK/r-SDK-Certificates-search-attribute.htm and https://ao-tlspd.dev.ven-eco.com/aperture/help/Content/SDK/WebSDK/r-SDK-Certificates-search-status.htm

#### Base Command

`venafi-get-certificates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| CreatedOn | The date on which the certificated was created. Specify YYYY-MM-DD or the ISO 8601 format. | Optional | 
| CreatedOnGreater | Find certificates created after this date. Specify YYYY-MM-DD or the ISO 8601 format. | Optional | 
| CreatedOnLess | Find certificates created before this date. Specify YYYY-MM-DD or the ISO 8601 format. | Optional | 
| Disabled | Include only certificates that are enabled 0 or disabled 1. | Optional | 
| InError | Whether to include only certificates that are in an error state (1) or not in an error state (0). | Optional | 
| ValidationState | Validation state. Possible values are: Blank, Success, Failure. | Optional | 
| ManagementType | Management type. Possible values are: Unassigned, Monitoring, Enrollment, Provisioning. | Optional | 
| Name | Name of the certificate object. | Optional | 
| NetworkValidationDisabled | Whether to include only certificates with network validation disabled (1) or enabled (0). | Optional | 
| ParentDn | The full path to the parent of the object in Trust Protection Platform (e.g., \VED\Policy\Engineering,\VED\Policy\HR). | Optional | 
| ParentDnRecursive | The specific folder from which to retrieve certificates. (The subfolders will also be scanned.) Accepts a single value. | Optional | 
| PendingWorkflow | Whether to include only certificates that are pending workflow resolution (have an outstanding workflow ticket). | Optional | 
| Stage | Comma-separated list of stages in the certificate lifecycle. Will retrieve certificates at one or more of the stages. | Optional | 
| StageGreater | Find certificates with a stage greater than the specified stage (does not include specified stage). | Optional | 
| StageLess | Stage before which to retrieve certificates. | Optional | 
| ValidationDisabled | Whether to include only certificates with validation disabled (1) or enabled (0). | Optional | 
| C | Find certificates by Country attribute of Subject DN. | Optional | 
| CN | Find certificates by Common name attribute of Subject DN. | Optional | 
| Issuer | Find certificates by issuer. Use the CN ,O, L, S, and C values from the certificate request. Surround the complete value within double quotes ("). If a value already has double quotes, escape them with a second set of double quotes. For example, OU=""(c) 2020 Entrust, Inc. - for authorized use only"". | Optional | 
| KeyAlgorithm | Algorithm for the public key in the certificate (e.g., RSA, DSA). | Optional | 
| KeySize | Comma-separated list of the bit size of the public key in the certificate (e.g., 2048). | Optional | 
| KeySizeGreater | The size for which the public key size is greater than. | Optional | 
| KeySizeLess | The size for which the public key size is less than. | Optional | 
| L | Find certificates by Locality/City attribute of Subject Distinguished Name (SDN). | Optional | 
| O | Find certificates by Organization attribute of Subject DN. | Optional | 
| S | Find certificates by State/Province attribute of Subject DN. | Optional | 
| Serial | Serial number of the certificate. | Optional | 
| SignatureAlgorithm | The algorithm used to sign the certificate (e.g., SHA1RSA). | Optional | 
| ValidFrom | Date on which the certificate was issued (e.g., 2015- 10-08T19:15:35.6431456Z or 2015-10-08). | Optional | 
| ValidTo | Date on which the certificate expires (e.g., 2015-10- 08T19:15:35.6431456Z or 2015-10-08). | Optional | 
| ValidToGreater | Date after which the certificates expire. | Optional | 
| ValidToLess | Date before which the certificates expire. | Optional | 
| Limit | The maximum number of certificates to return. Default value = 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Venafi.Certificate.CreatedOn | date | The exact date and time when the certificate object was created. | 
| Venafi.Certificate.DN | string | The DN of the certificate. | 
| Venafi.Certificate.Name | string | The name of the certificate. | 
| Venafi.Certificate.ParentDN | string | The full path to the parent of the object in Trust Protection Platform. | 
| Venafi.Certificate.SchemaClass | string | The class name of the certificate object. | 
| Venafi.Certificate.ID | string | The certificate object GUID. | 
| Venafi.Certificate.X509 | dictionary | Enrolled or issued certificate information: CN, Issuer, KeyAlgorithm, KeySize, SANS, Serial, Subject, Thumbprint, ValidFrom, ValidTo. | 

### venafi-get-certificate-details

***
Uses a certificate GUID to extract more details from the certificate store.

#### Base Command

`venafi-get-certificate-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guid | The ID of the certificate. Get certificates ID by running the command “venafi-get-certificates”. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Venafi.Certificate.ID | string | The certificate object GUID. | 
| Venafi.Certificate.ParentDN | string | The full path to the parent of the object in Trust Protection Platform. | 
| Venafi.Certificate.CreatedOn | date | The exact date and time when the Certificate object was created. | 
| Venafi.Certificate.DN | string | The DN of the certificate. | 
| Venafi.Certificate.Name | string | The name of the certificate. | 
| Venafi.Certificate.SchemaClass | string | The class name of the certificate object. | 
| Venafi.Certificate.Approver | string | An array of one or more users or groups who are certificate approvers. | 
| Venafi.Certificate.CertificateAuthorityDN | string | The CA template that is required for certificate renewal. | 
| Venafi.Certificate.Contact | string | An array of one or more users or groups who receive event notifications. The events notify people about certificate expiration and validation failures. | 
| Venafi.Certificate.Description | string | Certificate description. | 
| Venafi.Certificate.ManagedBy | string | Certificate manager. | 
| Venafi.Certificate.ManagementType | string | The level of management that the Trust Protection Platform applies to the certificate. | 
| Venafi.Certificate.CertificateDetails.AIAKeyIdentifier | string | Authority key identifier. | 
| Venafi.Certificate.CertificateDetails.Issuer | string | The CN, O, L, S, and C values from the certificate request. | 
| Venafi.Certificate.CertificateDetails.Serial | string | The unique serial number that the CA assigned to the certificate. | 
| Venafi.Certificate.CertificateDetails.Subject | string | The CN, O, L, S, and C values from the certificate request. | 
| Venafi.Certificate.CertificateDetails.Thumbprint | string | The SHA1 thumbprint hash of the certificate. | 
| Venafi.Certificate.CertificateDetails.ValidFrom | string | Certificate validation start date. | 
| Venafi.Certificate.CertificateDetails.ValidTo | string | Certificate validation end time. | 
| Venafi.Certificate.CertificateDetails.AIACAIssuerURL | array | Available only when the certificate was issued by a well-configured CA. An array of Authority Information Access \(AIA\). Shows the CA issuer link and the CA's certificate details. May also include Online Certificate Status Protocol \(OCSP\) information about revocation. | 
| Venafi.Certificate.CertificateDetails.CN | string | The Common Name attribute of Subject Distinguished Name \(DN\). | 
| Venafi.Certificate.CertificateDetails.EnhancedKeyUsage | string | The PKI Server Authentication object identifier \(OID\). | 
| Venafi.Certificate.CertificateDetails.KeyAlgorithm | string | The algorithm for the public key. | 
| Venafi.Certificate.CertificateDetails.KeySize | string | Only available for RSA certificates. The bit size of the public key. | 
| Venafi.Certificate.CertificateDetails.KeyUsage | string | A list of Key Usage extension values that describe the purpose of the public key. | 
| Venafi.Certificate.CertificateDetails.OU | string | An array of Organization Units or names. | 
| Venafi.Certificate.CertificateDetails.PublicKeyHash | string | The public key hash string. Available only when the certificate has a private key. | 
| Venafi.Certificate.CertificateDetails.SKIKeyIdentifier | string | The generated Subject Key Identifier \(SKI\). | 
| Venafi.Certificate.CertificateDetails.SignatureAlgorithm | string | The signature algorithm for signing the certificate. | 
| Venafi.Certificate.CertificateDetails.SignatureAlgorithmOID | string | The Signature Object ID for signing the certificate. | 
| Venafi.Certificate.CertificateDetails.StoreAdded | string | The Date Time stamp when the private key was added to the store. | 
| Venafi.Certificate.CertificateDetails.SubjectAltNameDNS | string | An array of Domain Name System \(DNS\) SANs. | 
| Venafi.Certificate.CertificateDetails.SubjectAltNameEmail | string | An array of Email SANs. Based on RFC 822. | 
| Venafi.Certificate.CertificateDetails.SubjectAltNameOtherNameUPN | string | An array of User Principal Name \(UPN\) SANs. | 
| Venafi.Certificate.CertificateDetails.SubjectAltNameIPAddress | string | An array of IP address SANs. | 
| Venafi.Certificate.CertificateDetails.SubjectAltNameURI | string | An array of Uniform Resource Indicator \(URI\) SANs. | 
| Venafi.Certificate.CreatedBy | string | The object that initiated enrollment or provisioning changes. The default is Web SDK. | 
| Venafi.Certificate.Origin | string | Filter by origin. | 
| Venafi.Certificate.ProcessingDetails | dictionary | Absent when the certificate is not currently processing in the Trust Protection Platform lifecycle: InError, InProcess, Stage, Status, TicketDN. | 
| Venafi.Certificate.RenewalDetails | dictionary | A list of certificate renewal information. | 
| Venafi.Certificate.ValidationDetails | dictionary | A list of host identity information and the overall certificate validation state result. If no validation occurred, only the lastvalidationstateupdate field appears. All other validationdetails fields are absent. | 
