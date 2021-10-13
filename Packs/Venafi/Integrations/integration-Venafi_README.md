Retrieves information about certificates stored in Venafi.

This integration was integrated and tested with version 20.3.2.5263 of Venafi.

## Configure Venafi on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Venafi.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., https://192.168.0.1) | True |
    | Credentials | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### venafi-get-certificates
***
Gets Venafi certificates query. All dates are in the 2016-11-12T00:00:00.0000000Z format. Additional fields can be used in the query by adding them in a key=value format.


#### Base Command

`venafi-get-certificates`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| CreatedOn | Exact date and time on which the certificate object was created. | Optional | 
| CreatedOnGreater | Date and time after which certificate objects were created. | Optional | 
| CreatedOnLess | Date and time before which certificate objects were created. | Optional | 
| Disabled | Whether to include only certificates that are disabled (1) or enabled (0). | Optional | 
| InError | Whether to include only certificates that are in an error state (1) or not in an error state (0). | Optional | 
| ValidationState | Validation state. Possible values are: Blank, Success, Failure. | Optional | 
| ManagementType | Management type. Possible values are: Unassigned, Monitoring, Enrollment, Provisioning. | Optional | 
| Name | Name of the certificate object. | Optional | 
| NetworkValidationDisabled | Whether to include only certificates with network validation disabled (1) or enabled (0). | Optional | 
| ParentDn | The full path to the parent of the object in Trust Protection Platform (e.g., \VED\Policy\Engineering,\VED\Policy\HR). | Optional | 
| ParentDnRecursive | The specific folder from which to retrieve certificates. (The subfolders will also be scanned.) Accepts a single value.  | Optional | 
| PendingWorkflow |Whether to include only certificates that are pending workflow resolution (have an outstanding workflow ticket). This parameter does not require a value to be specified. | Optional | 
| Stage | Comma-separated list of stages in the certificate lifecycle. Will retrieve certificates at one or more of the stages. | Optional | 
| StageGreater | Stage after which to retrieve certificates. Does not include the specified stage. | Optional | 
| StageLess | Stage before which to retrieve certificates. | Optional | 
| ValidationDisabled | Whether to include only certificates with validation disabled (1) or enabled (0). | Optional | 
| C | Country attribute of the Subject Distinguished Name (DN). | Optional | 
| CN | Common name attribute of the Subject Distinguished Name (DN). | Optional | 
| Issuer | Issuer DN. Note, since most Issuer DNs include commas between DN components, it is important to surround the complete Issuer DN within double quotes (“). In addition, if the Issuer DN includes double quotes, each double quote should be prefixed by another double quote. | Optional | 
| KeyAlgorithm | Algorithm for the public key in the certificate (e.g., RSA, DSA). | Optional | 
| KeySize | Comma-separated list of the bit size of the public key in the certificate (e.g., 2048).  | Optional | 
| KeySizeGreater | The size for which the public key size is greater than.  | Optional | 
| KeySizeLess | The size for which the public key size is less than. | Optional | 
| L | Locality/City attribute of the Subject DN in the certificates. | Optional | 
| O |Organization attribute of the Subject DN in the certificates. | Optional | 
| S | State/Province attribute of the Subject DN in certificates. | Optional | 
| Serial | Serial number of the certificate. | Optional | 
| SignatureAlgorithm | The algorithm used to sign the certificate (e.g. SHA1RSA). | Optional | 
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


#### Command Example
```!venafi-get-certificates Limit="1"```

#### Context Example
```json
{
    "Venafi": {
        "Certificate": {
            "CreatedOn": "2018-07-16T16:35:35.9468326Z",
            "DN": "\\VED\\Policy\\Venafi Operational Certificates\\WIN-MLK71Q10559",
            "ID": "2a25573b-745c-4018-806a-e5c73f424675",
            "Name": "WIN-MLK71Q10559",
            "ParentDN": "\\VED\\Policy\\Venafi Operational Certificates",
            "SchemaClass": "X509 Server Certificate"
        }
    }
}
```

#### Human Readable Output

>### Venafi certificates query response
>CreatedOn|DN|ID|Name|ParentDN|SchemaClass
>---|---|---|---|---|---
>2018-07-16T16:35:35.9468326Z | \VED\Policy\Venafi Operational Certificates\WIN-MLK71Q10559 | 2a25573b-745c-4018-806a-e5c73f424675 | WIN-MLK71Q10559 | \VED\Policy\Venafi Operational Certificates | X509 Server Certificate


### venafi-get-certificate-details
***
Uses a certificate GUID to extract more details from the cert store.


#### Base Command

`venafi-get-certificate-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guid | GUID of the certificate of which to get details. | Required | 


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


#### Command Example
```!venafi-get-certificate-details guid=941e5574-e467-46c4-a735-e5daaa65832b```

#### Context Example
```json
{
    "Venafi": {
        "Certificate": {
            "Approver": [
                "local:{cd2e9fd1-8c0a-4a00-b6b3-e1de501e5b6e}"
            ],
            "CertificateDetails": {
                "CN": "hoho",
                "EnhancedKeyUsage": "Server Authentication (1.3.6.1.5.5.7.3.1) Smart Card Logon (1.3.6.1.4.1.311.20.2.2)",
                "Issuer": "CN=hoho",
                "KeyAlgorithm": "RSA",
                "KeySize": 2048,
                "PublicKeyHash": "4D93BA33FA4DBC2E6FCB0F1BCC57DFA795659EB4",
                "Serial": "01",
                "SignatureAlgorithm": "sha1RSA",
                "SignatureAlgorithmOID": "1.2.840.113549.1.1.5",
                "StoreAdded": "2017-12-13T17:51:54.4437541Z",
                "Subject": "CN=hoho",
                "Thumbprint": "95CD28BB7DB2067A8DCB0938DEFE0792F9E9BD32",
                "ValidFrom": "2017-11-23T14:25:00.0000000Z",
                "ValidTo": "2018-11-23T14:25:00.0000000Z"
            },
            "Contact": [
                "local:{cd2e9fd1-8c0a-4a00-b6b3-e1de501e5b6e}"
            ],
            "CreatedOn": "2017-12-13T17:49:28.8028346Z",
            "DN": "\\VED\\Policy\\Reputation\\digicert_test",
            "Guid": "{941e5574-e467-46c4-a735-e5daaa65832b}",
            "ID": "941e5574-e467-46c4-a735-e5daaa65832b",
            "Name": "digicert_test",
            "ParentDN": "\\VED\\Policy\\Reputation",
            "ParentDn": "\\VED\\Policy\\Reputation",
            "ProcessingDetails": {
                "InError": true,
                "Stage": 500,
                "Status": "Access denied due to access_denied_invalid_key."
            },
            "RenewalDetails": {
                "Subject": "hoho"
            },
            "SchemaClass": "X509 Server Certificate",
            "ValidationDetails": {
                "LastValidationStateUpdate": "2017-12-15T23:05:37.0000000Z",
                "ValidationState": "Failure"
            }
        }
    }
}
```

#### Human Readable Output

>### Venafi certificates details
>Approver|CertificateDetails|Contact|CreatedOn|DN|Guid|ID|Name|ParentDN|ParentDn|ProcessingDetails|RenewalDetails|SchemaClass|ValidationDetails
>---|---|---|---|---|---|---|---|---|---|---|---|---|---
>local:{cd2e9fd1-8c0a-4a00-b6b3-e1de501e5b6e} | {"CN":"hoho","EnhancedKeyUsage":"Server Authentication (1.3.6.1.5.5.7.3.1) Smart Card Logon (1.3.6.1.4.1.311.20.2.2)","Issuer":"CN=hoho","KeyAlgorithm":"RSA","KeySize":2048,"PublicKeyHash":"4D93BA33FA4DBC2E6FCB0F1BCC57DFA795659EB4","Serial":"01","SignatureAlgorithm":"sha1RSA","SignatureAlgorithmOID":"1.2.840.113549.1.1.5","StoreAdded":"2017-12-13T17:51:54.4437541Z","Subject":"CN=hoho","Thumbprint":"95CD28BB7DB2067A8DCB0938DEFE0792F9E9BD32","ValidFrom":"2017-11-23T14:25:00.0000000Z","ValidTo":"2018-11-23T14:25:00.0000000Z"} | local:{cd2e9fd1-8c0a-4a00-b6b3-e1de501e5b6e} | 2017-12-13T17:49:28.8028346Z | \VED\Policy\Reputation\digicert_test | {941e5574-e467-46c4-a735-e5daaa65832b} | 941e5574-e467-46c4-a735-e5daaa65832b | digicert_test | \VED\Policy\Reputation | \VED\Policy\Reputation | {"InError":true,"Stage":500,"Status":"Access denied due to access_denied_invalid_key."} | {"Subject":"hoho"} | X509 Server Certificate | {"LastValidationStateUpdate":"2017-12-15T23:05:37.0000000Z","ValidationState":"Failure"}

