Manage certificates using Venafi

This integration was integrated and tested with version 20.3.2.5263 of Venafi

## Configure Venafi on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Venafi.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.168.0.1) | True |
    | Credentials | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### venafi-get-certificates
***
Get Venafi certificates query. All dates are in the 2016-11-12T00:00:00.0000000Z format. Additional fields can be used in the query by adding them in a key=value manner


#### Base Command

`venafi-get-certificates`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| CreatedOn | Exact date and time on which the certificate object was created. | Optional | 
| CreatedOnGreater | Certificate objects created after this date and time. | Optional | 
| CreatedOnLess | Certificate objects created before this date and time. | Optional | 
| Disabled | Include only certificates that are disabled (1) or enabled (0). | Optional | 
| InError | Include only certificates that are in an error state (1) or not in an error state (0). | Optional | 
| ValidationState | Validation state of Blank, Success, or Failure. Possible values are: Blank, Success, Failure. | Optional | 
| ManagementType | Management type of Unassigned, Monitoring, Enrollment, or Provisioning. Possible values are: Unassigned, Monitoring, Enrollment, Provisioning. | Optional | 
| Name | Name of the certificate object. | Optional | 
| NetworkValidationDisabled | Include only certificates with network validation disabled (1) or enabled (0). | Optional | 
| ParentDn | ParentDn One or more folders in which to search for certificates (e.g., \VED\Policy\Engineering,\VED\Policy\HR). | Optional | 
| ParentDnRecursive | Certificates within a specific folder and its subfolders. Accepts a single value. | Optional | 
| PendingWorkflow | Include only certificates that are pending workflow resolution (have an outstanding workflow ticket). This parameter does not require a value to be specified. | Optional | 
| Stage | Certificates at one or more stages in the certificate lifecycle. Accepts multiple comma separated values. | Optional | 
| StageGreater | Certificates with a stage greater than the specified stage (does not include specified stage). | Optional | 
| StageLess | Certificates a stage less than the specified stage. | Optional | 
| ValidationDisabled | Include only certificates with validation disabled (1) or enabled (0). | Optional | 
| C | Country attribute of Subject DN. | Optional | 
| CN | Common name attribute of Subject DN. | Optional | 
| Issuer | Issuer DN. Note, since most Issuer DNs include commas between DN components, it is important to surround the complete Issuer DN within double quotes (“). In addition, if the Issuer DN includes double quotes, each double quote should be prefixed by another double quote. | Optional | 
| KeyAlgorithm | Algorithm for the public key in the certificate (e.g., RSA, DSA). | Optional | 
| KeySize | Size of the public key in the certificate (e.g., 2048). Accepts multiple comma separated values. | Optional | 
| KeySizeGreater | Key size greater than the specified value. | Optional | 
| KeySizeLess | Key size less than the specified value. | Optional | 
| L | Locality/City attribute of Subject DN in certificates. | Optional | 
| O | Organization attribute of Subject DN in certificates. | Optional | 
| S | State/Province attribute of Subject DN in certificates. | Optional | 
| Serial | Serial number of the certificate. | Optional | 
| SignatureAlgorithm | The algorithm used to sign the certificate (e.g. SHA1RSA). | Optional | 
| ValidFrom | Date on which the certificate was issued (e.g., 2015- 10-08T19:15:35.6431456Z or 2015-10-08). | Optional | 
| ValidTo | Date on which the certificate expires (e.g., 2015-10- 08T19:15:35.6431456Z or 2015-10-08). | Optional | 
| ValidToGreater | Certificates that expire after the specified date. | Optional | 
| ValidToLess | Certificates that expire before the specified date. | Optional | 
| Limit | The maximum number of certificates to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Venafi.Certificate.CreatedOn | date | Certificate creation date | 
| Venafi.Certificate.DN | string | Certificate DN | 
| Venafi.Certificate.Name | string | Certificate name | 
| Venafi.Certificate.ParentDN | string | Certificate parent DN | 
| Venafi.Certificate.SchemaClass | string | Certificate schema | 
| Venafi.Certificate.ID | string | Certificate ID \(GUID\) | 


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
        },
        "Certificats": {
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

>### Venafi certificats query response
>CreatedOn|DN|ID|Name|ParentDN|SchemaClass
>---|---|---|---|---|---
>2018-07-16T16:35:35.9468326Z | \VED\Policy\Venafi Operational Certificates\WIN-MLK71Q10559 | 2a25573b-745c-4018-806a-e5c73f424675 | WIN-MLK71Q10559 | \VED\Policy\Venafi Operational Certificates | X509 Server Certificate


### venafi-get-certificate-details
***
Use a certificate guid to extract more details from the cert store.


#### Base Command

`venafi-get-certificate-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guid | Certificate GUID to get details of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Venafi.Certificate.ID | string | Certificate ID \(GUID\) | 
| Venafi.Certificate.ParentDN | string | Certificate parent DN | 
| Venafi.Certificate.CreatedOn | date | Certificate creation date | 
| Venafi.Certificate.DN | string | Certificate DN | 
| Venafi.Certificate.Name | string | Certificate name | 
| Venafi.Certificate.SchemaClass | string | Certificate schema | 
| Venafi.Certificate.Approver | string | Certificate approver | 
| Venafi.Certificate.CertificateAuthorityDN | string | Certificate authority DN | 
| Venafi.Certificate.Contact | string | Certificate contacts | 
| Venafi.Certificate.Description | string | Certificate description | 
| Venafi.Certificate.ManagedBy | string | Certificate manager | 
| Venafi.Certificate.ManagementType | string | Certificate management type | 
| Venafi.Certificate.CertificateDetails.AIAKeyIdentifier | string | Certificate AIA key identifier | 
| Venafi.Certificate.CertificateDetails.Issuer | string | Certificate issuer | 
| Venafi.Certificate.CertificateDetails.Serial | string | Certificate serial | 
| Venafi.Certificate.CertificateDetails.Subject | string | Certificate subject | 
| Venafi.Certificate.CertificateDetails.Thumbprint | string | Certificate thumbprint | 
| Venafi.Certificate.CertificateDetails.ValidFrom | string | Certificate validation start date | 
| Venafi.Certificate.CertificateDetails.ValidTo | string | Certificate validation end time | 


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

>### Venafi certificats details
>Approver|CertificateDetails|Contact|CreatedOn|DN|Guid|ID|Name|ParentDN|ParentDn|ProcessingDetails|RenewalDetails|SchemaClass|ValidationDetails
>---|---|---|---|---|---|---|---|---|---|---|---|---|---
>local:{cd2e9fd1-8c0a-4a00-b6b3-e1de501e5b6e} | {"CN":"hoho","EnhancedKeyUsage":"Server Authentication (1.3.6.1.5.5.7.3.1) Smart Card Logon (1.3.6.1.4.1.311.20.2.2)","Issuer":"CN=hoho","KeyAlgorithm":"RSA","KeySize":2048,"PublicKeyHash":"4D93BA33FA4DBC2E6FCB0F1BCC57DFA795659EB4","Serial":"01","SignatureAlgorithm":"sha1RSA","SignatureAlgorithmOID":"1.2.840.113549.1.1.5","StoreAdded":"2017-12-13T17:51:54.4437541Z","Subject":"CN=hoho","Thumbprint":"95CD28BB7DB2067A8DCB0938DEFE0792F9E9BD32","ValidFrom":"2017-11-23T14:25:00.0000000Z","ValidTo":"2018-11-23T14:25:00.0000000Z"} | local:{cd2e9fd1-8c0a-4a00-b6b3-e1de501e5b6e} | 2017-12-13T17:49:28.8028346Z | \VED\Policy\Reputation\digicert_test | {941e5574-e467-46c4-a735-e5daaa65832b} | 941e5574-e467-46c4-a735-e5daaa65832b | digicert_test | \VED\Policy\Reputation | \VED\Policy\Reputation | {"InError":true,"Stage":500,"Status":"Access denied due to access_denied_invalid_key."} | {"Subject":"hoho"} | X509 Server Certificate | {"LastValidationStateUpdate":"2017-12-15T23:05:37.0000000Z","ValidationState":"Failure"}

