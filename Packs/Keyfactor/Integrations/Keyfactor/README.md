
### keyfactor-get-enrollment-csr

***
Retrieve a list of Certificate Templates

#### Base Command

`keyfactor-get-enrollment-csr`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keyfactor.CSRTemplate.Lists.Name | string | list of csr template name | 
### keyfactor-post-enrollment-csr

***
Send CSR request and return certificate info

#### Base Command

`keyfactor-post-enrollment-csr`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| csr_base64 | Certificate Signing Request in Base64 format. | Required | 
| cert_authority | Certificate Authority. | Required | 
| include_chain | Include Certificate Chain. Possible values are: true, false. Default is true. | Required | 
| template | Certificate Template. | Required | 
| sans_ip4 | Subject Alternative Names IP addresses. | Optional | 
| metadata | Metadata. | Required | 
| keyAlgorithm | the key algorithm. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Keyfactor.CSRTemplate.Lists.SerialNumber | string | Certificate Serial Number | 
| Keyfactor.CSRTemplate.Lists.IssuerDN | string | Certificate Issuer Domain | 
| Keyfactor.CSRTemplate.Lists.Thumbprint | string | Certificate Thumb Print | 
| Keyfactor.CSRTemplate.Lists.KeyfactorID | number | Certificate KeyfactorID | 
| Keyfactor.CertInfo.Lists.Certificates | string | List of Certificates | 
| Keyfactor.CertInfo.Lists.RequestDisposition | string | Certificate Request Disposition | 
| Keyfactor.CertInfo.Lists.DispositionMessage | string | Certificate Request Disposition Message | 
| Keyfactor.CertInfo.Lists.EnrollmentContext | string | Certificate Request Enrollment Context | 
| Keyfactor.CertInfo.Lists.KeyfactorRequestId | number | Certificate Request ID | 
| Keyfactor.CertInfo.Lists.formated_cert | string | Formatted Certificate without Trust Chain | 
| Keyfactor.CertInfo.Lists.formated_chain | string | Formatted Certificate's Trust Chain | 
