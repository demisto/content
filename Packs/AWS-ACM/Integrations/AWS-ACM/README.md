Amazon Web Services Certificate Manager Service (ACM)

For more information regarding the AWS ACM service, please visit the official documentation found [here](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html).

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).

## Configure AWS - ACM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | role ARN | False |
| roleSessionName | Role Session Name | False |
| defaultRegion | AWS Default Region | False |
| sessionDuration | Role Session Duration | False |
| access_key | Access Key | False |
| secret_key | Secret Key | False |
| timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout (for example 60) or also the connect timeout followed after a comma (for example 60,10). If a connect timeout is not specified a default of 10 second will be used. | False |
| retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. More details about the retries strategy is available [here](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html). | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-acm-describe-certificate
***
Returns detailed metadata about the specified ACM certificate.


#### Base Command

`aws-acm-describe-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificateArn | The Amazon Resource Name (ARN) of the ACM certificate. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.ACM.Certificates.CertificateArn | string | he Amazon Resource Name \(ARN\) of the certificate. | 
| AWS.ACM.Certificates.DomainName | string | The fully qualified domain name for the certificate, such as www.example.com or example.com. | 
| AWS.ACM.Certificates.SubjectAlternativeNames | string | One or more domain names \(subject alternative names\) included in the certificate. This list contains the domain names that are bound to the public key that is contained in the certificate. The subject alternative names include the canonical domain name \(CN\) of the certificate and additional domain names that can be used to connect to the website. | 
| AWS.ACM.Certificates.DomainValidationOptions.DomainName | string | A fully qualified domain name \(FQDN\) in the certificate. | 
| AWS.ACM.Certificates.DomainValidationOptions.ValidationEmails | string | A list of email addresses that ACM used to send domain validation emails. | 
| AWS.ACM.Certificates.DomainValidationOptions.ValidationDomain | string | The domain name that ACM used to send domain validation emails. | 
| AWS.ACM.Certificates.DomainValidationOptions.ValidationStatu | string | The validation status of the domain name. | 
| AWS.ACM.Certificates.DomainValidationOptions.ResourceRecord.Name | string | The name of the DNS record to create in your domain. This is supplied by ACM. | 
| AWS.ACM.Certificates.DomainValidationOptions.ResourceRecord.Type | string | The type of DNS record. Currently this can be CNAME. | 
| AWS.ACM.Certificates.DomainValidationOptions.ResourceRecord.Value | string | The value of the CNAME record to add to your DNS database. This is supplied by ACM. | 
| AWS.ACM.Certificates.DomainValidationOptions.ValidationMethod | string | Specifies the domain validation method. | 
| AWS.ACM.Certificates.Serial | string | The serial number of the certificate. | 
| AWS.ACM.Certificates.Subject | string | The name of the entity that is associated with the public key contained in the certificate. | 
| AWS.ACM.Certificates.Issuer | string | The name of the certificate authority that issued and signed the certificate. | 
| AWS.ACM.Certificates.CreatedAt | date | The time at which the certificate was requested. This value exists only when the certificate type is AMAZON_ISSUED . | 
| AWS.ACM.Certificates.IssuedAt | date | The time at which the certificate was issued. This value exists only when the certificate type is AMAZON_ISSUED . | 
| AWS.ACM.Certificates.ImportedAt | date | The date and time at which the certificate was imported. This value exists only when the certificate type is IMPORTED. | 
| AWS.ACM.Certificates.Status | string | The status of the certificate. | 
| AWS.ACM.Certificates.RevokedAt | date | The time at which the certificate was revoked. This value exists only when the certificate status is REVOKED. | 
| AWS.ACM.Certificates.RevocationReason | string | The reason the certificate was revoked. This value exists only when the certificate status is REVOKED. | 
| AWS.ACM.Certificates.NotBefore | date | The time before which the certificate is not valid. | 
| AWS.ACM.Certificates.NotAfter | date | The time after which the certificate is not valid. | 
| AWS.ACM.Certificates.KeyAlgorithm | string | The algorithm that was used to generate the public-private key pair. | 
| AWS.ACM.Certificates.SignatureAlgorithm | string | The algorithm that was used to sign the certificate. | 
| AWS.ACM.Certificates.InUseBy | string | A list of ARNs for the AWS resources that are using the certificate. A certificate can be used by multiple AWS resources. | 
| AWS.ACM.Certificates.FailureReason | string | The reason the certificate request failed. | 
| AWS.ACM.Certificates.Type | string | The source of the certificate. | 
| AWS.ACM.Certificates.RenewalSummary.RenewalStatus | string | The status of ACM's managed renewal of the certificate. | 
| AWS.ACM.Certificates.RenewalSummary.DomainValidationOptions.DomainName | string | A fully qualified domain name \(FQDN\) in the certificate. | 
| AWS.ACM.Certificates.RenewalSummary.DomainValidationOptions.ValidationEmails | string | A list of email addresses that ACM used to send domain validation emails. | 
| AWS.ACM.Certificates.RenewalSummary.DomainValidationOptions.ValidationDomain | string | The domain name that ACM used to send domain validation emails. | 
| AWS.ACM.Certificates.RenewalSummary.DomainValidationOptions.ValidationStatus | string | The validation status of the domain name. | 
| AWS.ACM.Certificates.RenewalSummary.DomainValidationOptions.ResourceRecord.Name | string | The name of the DNS record to create in your domain. This is supplied by ACM. | 
| AWS.ACM.Certificates.RenewalSummary.DomainValidationOptions.ResourceRecord.Type | string | The type of DNS record. | 
| AWS.ACM.Certificates.RenewalSummary.DomainValidationOptions.ResourceRecord.Value | string | The value of the CNAME record to add to your DNS database. This is supplied by ACM. | 
| AWS.ACM.Certificates.RenewalSummary.DomainValidationOptions.ValidationMethod | string | Specifies the domain validation method. | 
| AWS.ACM.Certificates.KeyUsages.Name | string | A list of Key Usage X.509 v3 extension objects. Each object is a string value that identifies the purpose of the public key contained in the certificate. | 
| AWS.ACM.Certificates.ExtendedKeyUsages.Name | string | The name of an Extended Key Usage value. | 
| AWS.ACM.Certificates.ExtendedKeyUsages.OID | unknown | An object identifier \(OID\) for the extension value. OIDs are strings of numbers separated by periods. | 
| AWS.ACM.Certificates.CertificateAuthorityArn | string | The Amazon Resource Name \(ARN\) of the ACM PCA private certificate authority \(CA\) that issued the certificate. | 
| AWS.ACM.Certificates.RenewalEligibility | string | Specifies whether the certificate is eligible for renewal. | 
| AWS.ACM.Certificates.Options.CertificateTransparencyLoggingPreference | string | You can opt out of certificate transparency logging by specifying the DISABLED option. Opt in by specifying ENABLED. | 


### aws-acm-list-certificates
***
Retrieves a list of certificate ARNs and domain names. You can request that only certificates that match a specific status be listed. You can also filter by specific attributes of the certificate.


#### Base Command

`aws-acm-list-certificates`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificateStatuses | Filter the certificate list by status value. Possible values are: PENDING_VALIDATION, ISSUED, INACTIVE, EXPIRED, VALIDATION_TIMED_OUT, REVOKED, FAILED. | Optional | 
| extendedKeyUsage | Specify one or more ExtendedKeyUsage extension values. Possible values are: TLS_WEB_SERVER_AUTHENTICATION, TLS_WEB_CLIENT_AUTHENTICATION, CODE_SIGNING, EMAIL_PROTECTION, TIME_STAMPING, OCSP_SIGNING, IPSEC_END_SYSTEM, IPSEC_TUNNEL, IPSEC_USER, ANY, NONE, CUSTOM. | Optional | 
| keyUsage | Specify one or more KeyUsage extension values. Possible values are: DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT, KEY_AGREEMENT, CERTIFICATE_SIGNING, CRL_SIGNING, ENCIPHER_ONLY, DECIPHER_ONLY, ANY, CUSTOM. | Optional | 
| keyTypes | Specify one or more algorithms that can be used to generate key pairs. Possible values are: RSA_2048, RSA_1024, RSA_4096, EC_prime256v1, EC_secp384r1, EC_secp521r1. | Optional | 
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.ACM.Certificates.CertificateArn | string | Amazon Resource Name \(ARN\) of the certificate. | 
| AWS.ACM.Certificates.DomainName | string | Fully qualified domain name \(FQDN\), such as www.example.com or example.com, for the certificate. | 
| AWS.ACM.Certificates.Region | unknown | The AWS region were the certificate is located. | 


### aws-acm-add-tags-to-certificate
***
Adds one or more tags to an ACM certificate.


#### Base Command

`aws-acm-add-tags-to-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificateArn | String that contains the ARN of the ACM certificate to which the tag is to be applied. | Required | 
| tags | The key-value pair that defines the tag. The tag value is optional. | Required | 
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.


### aws-acm-remove-tags-from-certificate
***
Remove one or more tags from an ACM certificate.


#### Base Command

`aws-acm-remove-tags-from-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificateArn | The ARN of the ACM Certificate with one or more tags that you want to remove. | Required | 
| tags | The key-value pair that defines the tag to remove. | Required | 
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.


### aws-acm-list-tags-for-certificate
***
Lists the tags that have been applied to the ACM certificate. Use the certificate's Amazon Resource Name (ARN) to specify the certificate.


#### Base Command

`aws-acm-list-tags-for-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificateArn | The ARN of the ACM certificate for which you want to list the tags. | Required | 
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.ACM.Certificates.Tags.Key | string | The key of the tag. | 
| AWS.ACM.Certificates.Tags.Value | string | The value of the tag. | 


### aws-acm-get-certificate
***
Retrieves a certificate specified by an ARN and its certificate chain . The chain is an ordered list of certificates that contains the end entity certificate, intermediate certificates of subordinate CAs, and the root certificate in that order. The certificate and certificate chain are base64 encoded. If you want to decode the certificate to see the individual fields, you can use OpenSSL.


#### Base Command

`aws-acm-get-certificate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| certificateArn | The ARN of the certificate. | Required | 
| region | The AWS Region, if not specified the default region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3, us-gov-east-1, us-gov-west-1. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.ACM.Certificates.Certificate | string | String that contains the ACM certificate represented by the ARN specified at input. | 
| AWS.ACM.Certificates.CertificateChain | string | The certificate chain that contains the root certificate issued by the certificate authority \(CA\). | 

