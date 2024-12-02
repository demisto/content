Manage secrets and protect sensitive data through Thales CipherTrust security platform.
This integration was integrated and tested with version v1 of CipherTrust.

## Configure Thales CipherTrust Manager in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Username | True |
| Password | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


### Main Use Cases for the Thales CipherTrust Manager Integration

The Thales CipherTrust Manager integration supports several key use cases:

#### 1. Groups Management

Groups management is essential for organizing users and defining permissions within the Thales CipherTrust Manager.

- **Overview**:

  A group carries with it permissions for performing specific tasks. A group also consists of a set of users and/or clients that have been authorized to perform these tasks.
The CipherTrust Manager defines Special System Users, System Defined Groups, and User Defined Groups. System Defined Groups exist on CipherTrust Manager at launch time. Each System Defined Group carries with it permissions to perform specific tasks. \
 To read more about the Special System Users and System Defined Groups, refer to the CipherTrust Manager documentation.

- ***User Defined Groups***: User Defined Groups
User Defined Groups are created by Application Administrators. Administrators may use groups solely for organizing users, or may create policies that use group membership to assign other permissions. Adding group permissions to keys grants users in a User Defined Group the privileges to perform operations with those keys.
Groups are stored in CipherTrust Manager's internal database.


#### 2. Users Management
   
 Users management is critical for ensuring secure access and proper account management within the Thales CipherTrust Manager.

- **Overview**:

    Users are unique individuals or systems using the CipherTrust API. Users are authenticated against authentication systems, called "connections". A "connection" can be an identity provider, such as an OpenID endpoint, or a directory, such as LDAP or AD. CipherTrust Manager has a built-in, internal user directory, whose connection name is "local_account".
    
    The User's connection property refers to the authentication system in which the user's credentials and identity reside. When you create a User, you must specify the connection: this tells CipherTrust Manager which authentication system it should use to authenticate the User. Some connections may require additional, connection-specific properties to create the User.
    
    CipherTrust Manager supports external authentication systems. Once a user is authenticated against an external authentication system, a user will be created with connection|unique ID. This unique ID will be taken from an attribute associated with that user on the external authentication system.
    
    The user_id identifies Users and it is in the form of: `connection|unique ID in that connection`

    The internal user database uses UUIDs, so a user in the local_account connection might have a user_id of:`local_account|9cd4196b-b4b3-42d7-837f-d4fdeff36538` 

    Users have two attributes, `user_metadata` and `app_metadata`, which can be used to store application-specific information. The system does not use this information; it just stores it for the convenience of applications using the API. These properties are unstructured JSON documents: the caller can put any JSON-structured information in them.
    
    `user_metadata` is typically used to store application-specific data which the end user is allowed to see and modify, such as user preferences.
    
    `app_metadata` is typically used to store application-specific data about the user which the end user is not allowed to view or modify, such as the user's security roles.
    
    `certificate_subject_dn` is used to store Distinguished Name. To enable certificate-based authentication, add `"user_certificate"` authentication method in allowed_auth_methods. Value of Distinguished Name in the certificate and the value in the user object must match for successful authentication.
 
    `allowed_client_types` and `allowed_auth_methods` do not control login behavior for users in admin group.



#### 3. Certificate Authority

Managing digital certificates is crucial for maintaining secure communications and ensuring data integrity.

- **Overview**:

    A Certificate Authority (CA) issues and installs digital certificates and certificate signing requests (CSR).
    
    A certificate generally acts as the identity of a server or client and this API can be used to issue server and client certificates in order to setup trusted communication channels to the system. A Certificate Authority acts as the initially trusted shared entity between peers and can issue signed certificates to make it possible for each party to trust the other.
    
    The system distinguishes between local CAs and external CAs with the difference that a local CA can issue signed certificates as the private signing key is stored inside the system. An external CA does not store the private key and can instead be used as a trusted entity for various interfaces and services inside the system when certificates are issued externally. It is fine to have a mix of both.
    
    During initial bootstrapping of a new server a new local CipherTrust Manager root CA is automatically generated. This CA is later used to issue a server certificate for the interfaces available in the system. An easy way to inspect the certificate chain is to view the certificates in your browser when you connect to the web interface. All interfaces and services will by default trust this CA which means that a client certificate issued from this initial CipherTrust Manager root CA will automatically be trusted by the system. If preferred it is possible to create new local CAs and/or external CAs and instead used them for the internal interfaces and services.
    
    Creating a local CA is a two-step process:
  - Invoke Create local CA which creates a local CA in pending state and returns a CSR for signing. A pending local CA can then be activated in two ways:
    - Invoke Self-sign a local CA to let the CA sign itself. This is typically done for Root CAs.
    - Invoke Install a local CA which requires a signed certificate based on the CSR from the pending CA. This certificate can be signed by any other entity such as an external CA or even an other local CA.
  - Once a local CA exists a signed certificate can be issued by invoking Issue certificate and provide the CSR, the purpose and the duration. A new signed certificate will be returned.
      
  CipherTrust Manager allows to revoke and resume certificates signed by local CA. User can specify a reason to revoke a certificate according to RFC 5280. Certificates revoked with certificateHold reason will only allow resuming.
    
  Creating an external CA is a single step:
  - Invoke Upload external CA and provide the signed external CA certificate.


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ciphertrust-csr-generate

***
Creates a Certificate Signing Request (CSR) and its corresponding private key. This API does not store any state on the server as everything is returned in the result. This means that both the CSR and the private key must be stored securely on the client side. The private key can optionally be encrypted with a password. It is strongly recommended to encrypt the private key. If not specified, the private_key_file_password is mandatory and the file itself is protected with the password even if the private key is not encrypted.

#### Base Command

`ciphertrust-csr-generate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cn | Common Name. | Required | 
| algorithm | RSA or ECDSA (default) algorithms are supported. A signature algorithm (SHA512WithRSA, SHA384WithRSA, SHA256WithRSA, SHA1WithRSA, ECDSAWithSHA512, ECDSAWithSHA384, ECDSAWithSHA256) is selected based on the algorithm and size. Possible values are: RSA, ECDSA. | Optional | 
| dns_names | A comma-separated list of Subject Alternative Names (SAN) values. | Optional | 
| email | A comma-separated list of e-mail addresses. | Optional | 
| ip | A comma-separated list of IP addresses. | Optional | 
| name | A unique name of the CSR. | Optional | 
| encryption_algo | Private key encryption algorithm. Possible values are: AES256, AES192, AES128, TDES. | Optional | 
| name_fields_raw_json | Name fields are "O=organization, OU=organizational unit, L=location, ST=state/province, C=country". Fields can be duplicated if present in different objects. This is a raw json string, for example: "[{"O": "Thales", "OU": "RnD", "C": "US", "ST": "MD", "L": "Belcamp"}, {"OU": "Thales Group Inc."}]". | Optional | 
| name_fields_json_entry_id | Entry ID of the file that contains the JSON representation of the name_fields_raw_json. | Optional | 
| key_size | Key size. RSA: 1024 - 4096 (default: 2048), ECDSA: 256 (default), 384, 521. Possible values are: 1024, 2048, 3072, 4096, 256, 384, 521. | Optional | 
| encryption_password | Password to PEM-encrypt the private key. If not specified, the private key is not encrypted in return. It is strongly recommended to encrypt the private key. If not specified, the private_key_file_password is mandatory. | Optional | 
| private_key_file_password | Password to encrypt the private key file. It is strongly recommended to encrypt the private key. If not specified, the private key is encrypted with the password which must be provided. | Optional | 
| private_key_bytes | Private Key bytes of the key which is to be used while creating CSR. (The algorithm and size should be according to this key). If not given will generate key internally as per algorithm and size. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 

#### Command example

```!ciphertrust-csr-generate cn="example_csr" private_key_file_password=123```

#### Context Example

```json
{
    "InfoFile": [
        {
            "EntryID": "2201@a48e3cfd-a079-4895-89a7-4fac11b8143d",
            "Extension": "pem",
            "Info": "application/x-x509-ca-cert",
            "Name": "CSR.pem",
            "Size": 355,
            "Type": "PEM certificate request"
        },
        {
            "EntryID": "2202@a48e3cfd-a079-4895-89a7-4fac11b8143d",
            "Extension": "zip",
            "Info": "application/zip",
            "Name": "privateKey.zip",
            "Size": 178,
            "Type": "Zip archive data, at least v2.0 to extract"
        }
    ]
}
```

#### Human Readable Output

>CSR and its corresponding private key have been generated successfully for example_csr.

### ciphertrust-certificate-issue

***
Issues a certificate by signing the provided CSR with the CA. This is typically used to issue server, client or intermediate CA certificates. Either duration or not_after date must be specified. If both not_after date and duration are given, then not_after takes precedence over duration. If duration is given without not_before date, ceritificate is issued starting from server's current time for the specified duration.

#### Base Command

`ciphertrust-certificate-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ca_id | An identifier of the issuer CA resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Required | 
| csr_entry_id | The entry ID of the file to upload that contains CSR in PEM format. | Required | 
| purpose | Purpose of the certificate. Possible values are: server, client, ca. | Required | 
| duration | Duration in days of certificate. Either duration or not_after date must be specified. Default is 365. | Optional | 
| name | A unique name of the certificate. If not provided, will be set to cert-&lt;id&gt;. | Optional | 
| not_after | End date of the certificate. Either not_after date or duration must be specified. not_after overrides duration if both are given. | Optional | 
| not_before | Start date of the certificate. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.CACertificate.id | String | A unique identifier for the certificate authority \(CA\). | 
| CipherTrust.CACertificate.uri | String | Uniform Resource Identifier associated with the CA. | 
| CipherTrust.CACertificate.account | String | Account associated with the CA. | 
| CipherTrust.CACertificate.application | String | Application associated with the CA. | 
| CipherTrust.CACertificate.devAccount | String | Developer account associated with the CA. | 
| CipherTrust.CACertificate.name | String | Name of the CA. | 
| CipherTrust.CACertificate.state | String | Current state of the CA \(e.g., active, pending\). | 
| CipherTrust.CACertificate.createdAt | Date | Timestamp of when the CA was created. | 
| CipherTrust.CACertificate.updatedAt | Date | Timestamp of the last update of the CA. | 
| CipherTrust.CACertificate.serialNumber | String | Serial number of the CA's certificate. | 
| CipherTrust.CACertificate.subject | String | Subject of the CA's certificate. | 
| CipherTrust.CACertificate.issuer | String | Issuer of the CA's certificate. | 
| CipherTrust.CACertificate.ca | String | Certificate authority. | 
| CipherTrust.CACertificate.revoked_at | String | Revocation timestamp. | 
| CipherTrust.CACertificate.sha1Fingerprint | String | SHA1 fingerprint of the certificate. | 
| CipherTrust.CACertificate.sha256Fingerprint | String | SHA256 fingerprint of the certificate. | 
| CipherTrust.CACertificate.sha512Fingerprint | String | SHA512 fingerprint of the certificate. | 
| CipherTrust.CACertificate.notBefore | Date | Timestamp of when the certificate is valid from. | 
| CipherTrust.CACertificate.notAfter | Date | Timestamp of when the certificate is valid until. | 

#### Command example

```!ciphertrust-certificate-issue ca_id="example_local_ca" csr_entry_id="2234@a48e3cfd-a079-4895-89a7-4fac11b8143d" purpose=server duration=365```

#### Context Example

```json
{
    "CipherTrust": {
        "CACertificate": {
    "id": "d897c45c-30c7-4681-825d-4598e1234ddf",
    "uri": "kylo:kylo:naboo:certs:d897c45c-30c7-4681-825d-4598e1234ddf",
    "account": "kylo:kylo:admin:accounts:kylo",
    "createdAt": "2024-06-18T13:05:41.144324Z",
    "updatedAt": "2024-06-18T13:05:41.144324Z",
    "name": "cert-d897c45c-30c7-4681-825d-4598e1234ddf",
    "ca": "kylo:kylo:naboo:localca:9ccf5388-eb33-4b5d-b3bb-6060ab98c1d5",
    "revoked_at": "0001-01-01T00:00:00Z",
    "state": "active",
    "sha1Fingerprint": "F4EE1A03FB77FE935CED90453BEA48CEA534452F",
    "sha256Fingerprint": "8419720D5B65C2502132F5E7BCE735F7CF9EE800E9AF227783C7EA1390A79F90",
    "sha512Fingerprint": "5FFED62F81B2F31163C571535690258D509D00B089FE12FA1E629CEF96F0DEFC442095EBDB276862877F335AC18888AF6E04DA94634B1919CC8B2C99D84808B2",
    "serialNumber": "203857676859724655622907570743915678825",
    "subject": "/CN=my cert",
    "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/CN=kylo.com",
    "notBefore": "2024-06-17T13:05:41Z",
    "notAfter": "2025-06-18T13:05:41Z"
  }, 
         "InfoFile": {
        "EntryID": "2139@a48e3cfd-a079-4895-89a7-4fac11b8143d",
        "Extension": "pem",
        "Info": "application/x-x509-ca-cert",
        "Name": "Certificate.pem",
        "Size": 761,
        "Type": "PEM certificate"
    }
    }
}
```

#### Human Readable Output

>cert-d897c45c-30c7-4681-825d-4598e1234ddf has been issued successfully!


### ciphertrust-certificate-list

***
Returns a list of certificates issued by the specified CA. The results can be filtered, using the command arguments.

#### Base Command

`ciphertrust-certificate-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ca_id | An identifier of the issuer CA resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Required | 
| subject | Filter by the subject. | Optional | 
| issuer | Filter by the issuer. | Optional | 
| cert | Filter by the cert. | Optional | 
| id | Filter by ID or URI. | Optional | 
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 2000 (in case only page was provided). Maximum entries per page is 2000. | Optional | 
| limit | The maximum number of entries to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CipherTrust.CACertificate.name | String | The name of the certificate. | 
| CipherTrust.CACertificate.id | String | A unique identifier for the certificate. | 
| CipherTrust.CACertificate.uri | String | Uniform Resource Identifier associated with the certificate. | 
| CipherTrust.CACertificate.account | String | Account associated with the certificate. | 
| CipherTrust.CACertificate.application | String | Application associated with the certificate. | 
| CipherTrust.CACertificate.devAccount | String | Developer account associated with the certificate. | 
| CipherTrust.CACertificate.createdAt | Date | Timestamp of when the certificate was created. | 
| CipherTrust.CACertificate.updatedAt | Date | Timestamp of the last update of the certificate. | 
| CipherTrust.CACertificate.ca | String | Certificate authority. | 
| CipherTrust.CACertificate.revoked_at | String | Revocation timestamp. | 
| CipherTrust.CACertificate.sha1Fingerprint | String | SHA1 fingerprint of the certificate. | 
| CipherTrust.CACertificate.sha256Fingerprint | String | SHA256 fingerprint of the certificate. | 
| CipherTrust.CACertificate.sha512Fingerprint | String | SHA512 fingerprint of the certificate. | 
| CipherTrust.CACertificate.serialNumber | String | Serial number of the certificate. | 
| CipherTrust.CACertificate.subject | String | Subject of the certificate. | 
| CipherTrust.CACertificate.issuer | String | Issuer of the certificate. | 
| CipherTrust.CACertificate.notBefore | Date | Timestamp of when the certificate is valid from. | 
| CipherTrust.CACertificate.notAfter | Date | Timestamp of when the certificate is valid until. | 

#### Command example

```!ciphertrust-certificate-list ca_id="localca-3dc1f629-23b6-4cce-876a-c7d07a4862cd"```

#### Context Example

```json
{
    "CipherTrust": {
        "CACertificate": [
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "ca": "kylo:kylo:naboo:localca:3dc1f629-23b6-4cce-876a-c7d07a4862cd",
                "createdAt": "2024-06-13T16:22:50.935704Z",
                "id": "731d4f15-ea27-4cd5-bd11-7f8d488f51b7",
                "issuer": "/CN=demo_prep_example.com",
                "name": "cert-731d4f15-ea27-4cd5-bd11-7f8d488f51b7",
                "notAfter": "2025-06-02T13:58:56Z",
                "notBefore": "2024-06-13T16:22:51Z",
                "revoked_at": "2024-06-13T16:27:51.151471Z",
                "revoked_reason": "certificateHold",
                "serialNumber": "278194539608420376178600649699280848294",
                "sha1Fingerprint": "EEDE423751F0D393B775CAC3795B9CBB4D67ADF3",
                "sha256Fingerprint": "6E0BCC3C4294725AA9D8CA797A65066458A08DF243A5B1335A17BF1CE5E8EDD6",
                "sha512Fingerprint": "7C41E2235A73B61CB1456155DCBA2C05272DC9585521B84067BD579F9E73E0B598F1805C1593E81D767D702BE5466D367FC4D64555118F9832E1D0B3BC0CF1C3",
                "state": "revoked",
                "subject": "/CN=ui_test",
                "updatedAt": "2024-06-13T16:27:51.151693Z",
                "uri": "kylo:kylo:naboo:certs:731d4f15-ea27-4cd5-bd11-7f8d488f51b7"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "ca": "kylo:kylo:naboo:localca:3dc1f629-23b6-4cce-876a-c7d07a4862cd",
                "createdAt": "2024-06-10T07:33:00.686183Z",
                "id": "0fb15f00-722c-412e-a1e8-6eb6130e87ba",
                "issuer": "/CN=demo_prep_example.com",
                "name": "cert-0fb15f00-722c-412e-a1e8-6eb6130e87ba",
                "notAfter": "2025-06-02T13:58:56Z",
                "notBefore": "2024-06-10T07:33:19Z",
                "revoked_at": "0001-01-01T00:00:00Z",
                "serialNumber": "94578324115075140466834527563222175449",
                "sha1Fingerprint": "B8FE025144990B0662940F938E7C68E67877B76E",
                "sha256Fingerprint": "6F4E76E3B66E0E33F59EE24DBEF63E00FE8ACA8C14E504D20D184FD6CC0ACED3",
                "sha512Fingerprint": "7BF057227CC78B7E410023698B65D5D12018F4E102243A1D62445A7ACE1C92E53EBEDA25F3EAA9E3C0AA44CF217C2F426D1F05BAC1C4B522926E78EC83C1D7E1",
                "state": "active",
                "subject": "/CN=test123",
                "updatedAt": "2024-06-13T16:22:14.494428Z",
                "uri": "kylo:kylo:naboo:certs:0fb15f00-722c-412e-a1e8-6eb6130e87ba"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "ca": "kylo:kylo:naboo:localca:3dc1f629-23b6-4cce-876a-c7d07a4862cd",
                "createdAt": "2024-06-03T12:03:51.448698Z",
                "id": "e7ed2c9d-db2e-4625-a224-33007cee64ca",
                "issuer": "/CN=demo_prep_example.com",
                "name": "cert-e7ed2c9d-db2e-4625-a224-33007cee64ca",
                "notAfter": "2025-06-02T13:58:56Z",
                "notBefore": "2024-06-03T12:04:10Z",
                "revoked_at": "0001-01-01T00:00:00Z",
                "serialNumber": "84999099666945695093203891019263091250",
                "sha1Fingerprint": "D839A29F86EFFA3A4569FEF6B146F79C807433FC",
                "sha256Fingerprint": "E18D1BB65DB40B1491534014E496CF62E106361DC1EDF6DB2B984DDF51A603C5",
                "sha512Fingerprint": "FCAFDFBE22083DF455A0392E9C427CF05E437F3C5027EB949838A5525BE09BE13A3DE6EC04DF9B4AC361C29F718D99C2736557BFD3CCB5AA1C1EF6B8B2554084",
                "state": "active",
                "subject": "/CN=example",
                "updatedAt": "2024-06-03T12:03:51.448698Z",
                "uri": "kylo:kylo:naboo:certs:e7ed2c9d-db2e-4625-a224-33007cee64ca"
            }
        ]
    }
}
```

#### Human Readable Output

>### Certificates issued by localca-3dc1f629-23b6-4cce-876a-c7d07a4862cd

>|Id|Uri|Createdat|Updatedat|Name|Ca|RevokedReason|RevokedAt|State|Sha1Fingerprint|Sha256Fingerprint|Sha512Fingerprint|Serialnumber|Subject|Issuer|Notbefore|Notafter|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 731d4f15-ea27-4cd5-bd11-7f8d488f51b7 | kylo:kylo:naboo:certs:731d4f15-ea27-4cd5-bd11-7f8d488f51b7 | 2024-06-13T16:22:50.935704Z | 2024-06-13T16:27:51.151693Z | cert-731d4f15-ea27-4cd5-bd11-7f8d488f51b7 | kylo:kylo:naboo:localca:3dc1f629-23b6-4cce-876a-c7d07a4862cd | certificateHold | 2024-06-13T16:27:51.151471Z | revoked | EEDE423751F0D393B775CAC3795B9CBB4D67ADF3 | 6E0BCC3C4294725AA9D8CA797A65066458A08DF243A5B1335A17BF1CE5E8EDD6 | 7C41E2235A73B61CB1456155DCBA2C05272DC9585521B84067BD579F9E73E0B598F1805C1593E81D767D702BE5466D367FC4D64555118F9832E1D0B3BC0CF1C3 | 278194539608420376178600649699280848294 | /CN=ui_test | /CN=demo_prep_example.com | 2024-06-13T16:22:51Z | 2025-06-02T13:58:56Z |
>| 0fb15f00-722c-412e-a1e8-6eb6130e87ba | kylo:kylo:naboo:certs:0fb15f00-722c-412e-a1e8-6eb6130e87ba | 2024-06-10T07:33:00.686183Z | 2024-06-13T16:22:14.494428Z | cert-0fb15f00-722c-412e-a1e8-6eb6130e87ba | kylo:kylo:naboo:localca:3dc1f629-23b6-4cce-876a-c7d07a4862cd |  | 0001-01-01T00:00:00Z | active | B8FE025144990B0662940F938E7C68E67877B76E | 6F4E76E3B66E0E33F59EE24DBEF63E00FE8ACA8C14E504D20D184FD6CC0ACED3 | 7BF057227CC78B7E410023698B65D5D12018F4E102243A1D62445A7ACE1C92E53EBEDA25F3EAA9E3C0AA44CF217C2F426D1F05BAC1C4B522926E78EC83C1D7E1 | 94578324115075140466834527563222175449 | /CN=test123 | /CN=demo_prep_example.com | 2024-06-10T07:33:19Z | 2025-06-02T13:58:56Z |
>| e7ed2c9d-db2e-4625-a224-33007cee64ca | kylo:kylo:naboo:certs:e7ed2c9d-db2e-4625-a224-33007cee64ca | 2024-06-03T12:03:51.448698Z | 2024-06-03T12:03:51.448698Z | cert-e7ed2c9d-db2e-4625-a224-33007cee64ca | kylo:kylo:naboo:localca:3dc1f629-23b6-4cce-876a-c7d07a4862cd |  | 0001-01-01T00:00:00Z | active | D839A29F86EFFA3A4569FEF6B146F79C807433FC | E18D1BB65DB40B1491534014E496CF62E106361DC1EDF6DB2B984DDF51A603C5 | FCAFDFBE22083DF455A0392E9C427CF05E437F3C5027EB949838A5525BE09BE13A3DE6EC04DF9B4AC361C29F718D99C2736557BFD3CCB5AA1C1EF6B8B2554084 | 84999099666945695093203891019263091250 | /CN=example | /CN=demo_prep_example.com | 2024-06-03T12:04:10Z | 2025-06-02T13:58:56Z |
>
>1 to 3 of 3 Certificates issued by localca-3dc1f629-23b6-4cce-876a-c7d07a4862cd

### ciphertrust-certificate-resume

***
Certificate can be resumed only if it is revoked with reason certificateHold.

#### Base Command

`ciphertrust-certificate-resume`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ca_id | An identifier of the issuer CA resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Required | 
| cert_id | An identifier of the certificate resource. This can be either the ID (a UUIDv4), the URI, or the slug (which is the last component of the URI). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.CACertificate.name | String | The name of the certificate. | 
| CipherTrust.CACertificate.id | String | A unique identifier for the certificate. | 
| CipherTrust.CACertificate.uri | String | Uniform Resource Identifier associated with the certificate. | 
| CipherTrust.CACertificate.account | String | Account associated with the certificate. | 
| CipherTrust.CACertificate.application | String | Application associated with the certificate. | 
| CipherTrust.CACertificate.devAccount | String | Developer account associated with the certificate. | 
| CipherTrust.CACertificate.createdAt | Date | Timestamp of when the certificate was created. | 
| CipherTrust.CACertificate.updatedAt | Date | Timestamp of the last update of the certificate. | 
| CipherTrust.CACertificate.ca | String | Certificate authority. | 
| CipherTrust.CACertificate.revoked_at | Date | Revocation timestamp. | 
| CipherTrust.CACertificate.state | String | Current state of the certificate \(e.g., active, revoked\). | 
| CipherTrust.CACertificate.sha1Fingerprint | String | SHA1 fingerprint of the certificate. | 
| CipherTrust.CACertificate.sha256Fingerprint | String | SHA256 fingerprint of the certificate. | 
| CipherTrust.CACertificate.sha512Fingerprint | String | SHA512 fingerprint of the certificate. | 
| CipherTrust.CACertificate.serialNumber | String | Serial number of the certificate. | 
| CipherTrust.CACertificate.subject | String | Subject of the certificate. | 
| CipherTrust.CACertificate.issuer | String | Issuer of the certificate. | 
| CipherTrust.CACertificate.notBefore | Date | Timestamp of when the certificate is valid from. | 
| CipherTrust.CACertificate.notAfter | Date | Timestamp of when the certificate is valid until. | 

#### Command example

```!ciphertrust-certificate-resume ca_id="localca-3dc1f629-23b6-4cce-876a-c7d07a4862cd" cert_id="0fb15f00-722c-412e-a1e8-6eb6130e87ba"```

#### Context Example

```json
{
    "CipherTrust": {
        "CACertificate": {
            "account": "kylo:kylo:admin:accounts:kylo",
            "ca": "kylo:kylo:naboo:localca:3dc1f629-23b6-4cce-876a-c7d07a4862cd",
            "createdAt": "2024-06-10T07:33:00.686183Z",
            "id": "0fb15f00-722c-412e-a1e8-6eb6130e87ba",
            "issuer": "/CN=demo_prep_example.com",
            "name": "cert-0fb15f00-722c-412e-a1e8-6eb6130e87ba",
            "notAfter": "2025-06-02T13:58:56Z",
            "notBefore": "2024-06-10T07:33:19Z",
            "revoked_at": "0001-01-01T00:00:00Z",
            "serialNumber": "94578324115075140466834527563222175449",
            "sha1Fingerprint": "B8FE025144990B0662940F938E7C68E67877B76E",
            "sha256Fingerprint": "6F4E76E3B66E0E33F59EE24DBEF63E00FE8ACA8C14E504D20D184FD6CC0ACED3",
            "sha512Fingerprint": "7BF057227CC78B7E410023698B65D5D12018F4E102243A1D62445A7ACE1C92E53EBEDA25F3EAA9E3C0AA44CF217C2F426D1F05BAC1C4B522926E78EC83C1D7E1",
            "state": "active",
            "subject": "/CN=test123",
            "updatedAt": "2024-06-18T09:17:09.837146586Z",
            "uri": "kylo:kylo:naboo:certs:0fb15f00-722c-412e-a1e8-6eb6130e87ba"
        }
    },
    "InfoFile": {
        "EntryID": "2139@a48e3cfd-a079-4895-89a7-4fac11b8143d",
        "Extension": "pem",
        "Info": "application/x-x509-ca-cert",
        "Name": "Certificate.pem",
        "Size": 761,
        "Type": "PEM certificate"
    }
}
```

#### Human Readable Output

>0fb15f00-722c-412e-a1e8-6eb6130e87ba has been resumed

### ciphertrust-certificate-revoke

***
Revoke certificate with a given specific reason.

#### Base Command

`ciphertrust-certificate-revoke`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ca_id | An identifier of the issuer CA resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Required | 
| cert_id | An identifier of the certificate resource. This can be either the ID (a UUIDv4), the URI, or the slug (which is the last component of the URI). | Required | 
| reason | Specify one of the reasons to revoke a certificate according to RFC 5280. Possible values are: unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.CACertificate.name | String | The name of the certificate. | 
| CipherTrust.CACertificate.id | String | A unique identifier for the certificate. | 
| CipherTrust.CACertificate.uri | String | Uniform Resource Identifier associated with the certificate. | 
| CipherTrust.CACertificate.account | String | Account associated with the certificate. | 
| CipherTrust.CACertificate.application | String | Application associated with the certificate. | 
| CipherTrust.CACertificate.devAccount | String | Developer account associated with the certificate. | 
| CipherTrust.CACertificate.createdAt | Date | Timestamp of when the certificate was created. | 
| CipherTrust.CACertificate.updatedAt | Date | Timestamp of the last update of the certificate. | 
| CipherTrust.CACertificate.ca | String | Certificate authority. | 
| CipherTrust.CACertificate.revoked_at | Date | Revocation timestamp. | 
| CipherTrust.CACertificate.revoked_reason | String | Reason for revocation. | 
| CipherTrust.CACertificate.state | String | Current state of the certificate \(e.g., active, revoked\). | 
| CipherTrust.CACertificate.sha1Fingerprint | String | SHA1 fingerprint of the certificate. | 
| CipherTrust.CACertificate.sha256Fingerprint | String | SHA256 fingerprint of the certificate. | 
| CipherTrust.CACertificate.sha512Fingerprint | String | SHA512 fingerprint of the certificate. | 
| CipherTrust.CACertificate.serialNumber | String | Serial number of the certificate. | 
| CipherTrust.CACertificate.subject | String | Subject of the certificate. | 
| CipherTrust.CACertificate.issuer | String | Issuer of the certificate. | 
| CipherTrust.CACertificate.notBefore | Date | Timestamp of when the certificate is valid from. | 
| CipherTrust.CACertificate.notAfter | Date | Timestamp of when the certificate is valid until. | 

#### Command example

```!ciphertrust-certificate-revoke ca_id="localca-3dc1f629-23b6-4cce-876a-c7d07a4862cd" cert_id="0fb15f00-722c-412e-a1e8-6eb6130e87ba" reason="certificateHold"```

#### Context Example

```json
{
    "CipherTrust": {
        "CACertificate": {
            "account": "kylo:kylo:admin:accounts:kylo",
            "ca": "kylo:kylo:naboo:localca:3dc1f629-23b6-4cce-876a-c7d07a4862cd",
            "createdAt": "2024-06-10T07:33:00.686183Z",
            "id": "0fb15f00-722c-412e-a1e8-6eb6130e87ba",
            "issuer": "/CN=demo_prep_example.com",
            "name": "cert-0fb15f00-722c-412e-a1e8-6eb6130e87ba",
            "notAfter": "2025-06-02T13:58:56Z",
            "notBefore": "2024-06-10T07:33:19Z",
            "revoked_at": "2024-06-18T09:17:06.11766701Z",
            "revoked_reason": "certificateHold",
            "serialNumber": "94578324115075140466834527563222175449",
            "sha1Fingerprint": "B8FE025144990B0662940F938E7C68E67877B76E",
            "sha256Fingerprint": "6F4E76E3B66E0E33F59EE24DBEF63E00FE8ACA8C14E504D20D184FD6CC0ACED3",
            "sha512Fingerprint": "7BF057227CC78B7E410023698B65D5D12018F4E102243A1D62445A7ACE1C92E53EBEDA25F3EAA9E3C0AA44CF217C2F426D1F05BAC1C4B522926E78EC83C1D7E1",
            "state": "revoked",
            "subject": "/CN=test123",
            "updatedAt": "2024-06-18T09:17:06.1179196Z",
            "uri": "kylo:kylo:naboo:certs:0fb15f00-722c-412e-a1e8-6eb6130e87ba"
        }
    },
    "InfoFile": {
        "EntryID": "2134@a48e3cfd-a079-4895-89a7-4fac11b8143d",
        "Extension": "pem",
        "Info": "application/x-x509-ca-cert",
        "Name": "Certificate.pem",
        "Size": 761,
        "Type": "PEM certificate"
    }
}
```

#### Human Readable Output

>0fb15f00-722c-412e-a1e8-6eb6130e87ba has been revoked

### ciphertrust-external-ca-delete

***
Deletes an external CA certificate.

#### Base Command

`ciphertrust-external-ca-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| external_ca_id | An identifier of the resource. This can be either the ID (a UUIDv4), the Name, the URI, or the slug (which is the last component of the URI). | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!ciphertrust-external-ca-delete external_ca_id="123e0a83-63d3-4632-925b-e78ddbfc7774"```

#### Human Readable Output

>123e0a83-63d3-4632-925b-e78ddbfc7774 has been deleted successfully!

### ciphertrust-external-ca-list

***
Returns a list of external CA certificates. The results can be filtered, using the command arguments.

#### Base Command

`ciphertrust-external-ca-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| external_ca_id | An identifier of the resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Optional | 
| subject | Filter by the subject. | Optional | 
| issuer | Filter by the issuer. | Optional | 
| serial_number | Filter by the serial number. | Optional | 
| cert | Filter by the cert. | Optional | 
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 2000 (in case only page was provided). Maximum entries per page is 2000. | Optional | 
| limit | The maximum number of entries to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g. ,"PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.ExternalCA.id | String | A unique identifier for the certificate authority \(CA\) certificate. | 
| CipherTrust.ExternalCA.uri | String | Uniform Resource Identifier associated with the CA certificate. | 
| CipherTrust.ExternalCA.account | String | Account associated with the CA certificate. | 
| CipherTrust.ExternalCA.devAccount | String | Developer account associated with the CA certificate. | 
| CipherTrust.ExternalCA.application | String | Application associated with the CA certificate. | 
| CipherTrust.ExternalCA.createdAt | Date | Timestamp of when the CA certificate was created. | 
| CipherTrust.ExternalCA.updatedAt | Date | Timestamp of the last update of the CA certificate. | 
| CipherTrust.ExternalCA.name | String | Name of the CA certificate. | 
| CipherTrust.ExternalCA.purpose.client_authentication | String | If set to enabled, the certificates signed by the specified CA can be used for client authentication. | 
| CipherTrust.ExternalCA.purpose.user_authentication | String | If set to enabled, the certificates signed by the specified CA can be used for user authentication. | 
| CipherTrust.ExternalCA.serialNumber | String | Serial number of the CA certificate. | 
| CipherTrust.ExternalCA.subject | String | Subject of the CA certificate. | 
| CipherTrust.ExternalCA.issuer | String | Issuer of the CA certificate. | 
| CipherTrust.ExternalCA.notBefore | Date | Timestamp of when the CA certificate is valid from. | 
| CipherTrust.ExternalCA.notAfter | Date | Timestamp of when the CA certificate is valid until. | 
| CipherTrust.ExternalCA.sha1Fingerprint | String | SHA1 fingerprint of the CA certificate. | 
| CipherTrust.ExternalCA.sha256Fingerprint | String | SHA256 fingerprint of the CA certificate. | 
| CipherTrust.ExternalCA.sha512Fingerprint | String | SHA512 fingerprint of the CA certificate. | 

#### Command example

```!ciphertrust-external-ca-list```

#### Context Example

```json
{
    "CipherTrust": {
        "ExternalCA": [
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-13T16:26:17.877709Z",
                "id": "123e0a83-63d3-4632-925b-e78ddbfc7774",
                "issuer": "/CN=ui_test",
                "name": "test_ui",
                "notAfter": "2025-06-13T16:20:50Z",
                "notBefore": "2024-06-13T16:20:50Z",
                "purpose": {
                    "client_authentication": "Disabled",
                    "user_authentication": "Disabled"
                },
                "serialNumber": "22416116914186521030446027138329400040",
                "sha1Fingerprint": "999F0159EB3ADB9E2C2591BE19DF0964075ECB77",
                "sha256Fingerprint": "17E54883786AD97D5BFD962F39B9A5CA254E34CAE6012541D606808E4CCA76A0",
                "sha512Fingerprint": "BD052596815129BD78732ADF87265A64534A553F8AFBBAD19EF908FDD68373475D74DD159A112D4AF9DB7E5730064BF23BECDB33DBEE53FBD220F095B8ECF66F",
                "subject": "/CN=ui_test",
                "updatedAt": "2024-06-18T09:09:09.100327Z",
                "uri": "kylo:kylo:naboo:external_ca:123e0a83-63d3-4632-925b-e78ddbfc7774"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-02T14:32:54.433033Z",
                "id": "2936eece-2e14-4ad2-96a4-98113920d5fd",
                "issuer": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com",
                "name": "test_external_cert",
                "notAfter": "2047-07-26T22:42:23Z",
                "notBefore": "2017-08-02T22:42:23Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "0",
                "sha1Fingerprint": "47E47FADCE48664689AD46275EE63168CC4CE809",
                "sha256Fingerprint": "197EC3BB1827EFEE9A3FD6CF25A7C88E4C86E25D356D00F84EC3E8FE5B943564",
                "sha512Fingerprint": "C09A87FA4A95F94BED0F005E687FEA097B5F8A2F5670C814B7C887301AD6F7A0CA167E0D3234AA60977A4F46F3884838F255766FCCC24990572F4BD2A769027A",
                "subject": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com",
                "updatedAt": "2024-06-02T14:32:54.433033Z",
                "uri": "kylo:kylo:naboo:external_ca:2936eece-2e14-4ad2-96a4-98113920d5fd"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-02T11:36:48.983514Z",
                "id": "d532cf16-5618-4080-86a2-9b4f59b3352a",
                "issuer": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com",
                "name": "sample-ex-CA",
                "notAfter": "2047-07-26T22:42:23Z",
                "notBefore": "2017-08-02T22:42:23Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "0",
                "sha1Fingerprint": "47E47FADCE48664689AD46275EE63168CC4CE809",
                "sha256Fingerprint": "197EC3BB1827EFEE9A3FD6CF25A7C88E4C86E25D356D00F84EC3E8FE5B943564",
                "sha512Fingerprint": "C09A87FA4A95F94BED0F005E687FEA097B5F8A2F5670C814B7C887301AD6F7A0CA167E0D3234AA60977A4F46F3884838F255766FCCC24990572F4BD2A769027A",
                "subject": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com",
                "updatedAt": "2024-06-02T11:43:10.668463Z",
                "uri": "kylo:kylo:naboo:external_ca:d532cf16-5618-4080-86a2-9b4f59b3352a"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-02T11:09:49.290572Z",
                "id": "5304de93-6939-4a26-bdb4-5e3d0b2fdb38",
                "issuer": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com",
                "name": "externalca-5304de93-6939-4a26-bdb4-5e3d0b2fdb38",
                "notAfter": "2047-07-26T22:42:23Z",
                "notBefore": "2017-08-02T22:42:23Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "0",
                "sha1Fingerprint": "47E47FADCE48664689AD46275EE63168CC4CE809",
                "sha256Fingerprint": "197EC3BB1827EFEE9A3FD6CF25A7C88E4C86E25D356D00F84EC3E8FE5B943564",
                "sha512Fingerprint": "C09A87FA4A95F94BED0F005E687FEA097B5F8A2F5670C814B7C887301AD6F7A0CA167E0D3234AA60977A4F46F3884838F255766FCCC24990572F4BD2A769027A",
                "subject": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com",
                "updatedAt": "2024-06-02T11:09:49.290572Z",
                "uri": "kylo:kylo:naboo:external_ca:5304de93-6939-4a26-bdb4-5e3d0b2fdb38"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-02T11:09:49.267786Z",
                "id": "208d8f42-1af3-4039-8b02-5e38fb4723f4",
                "issuer": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com",
                "name": "externalca-208d8f42-1af3-4039-8b02-5e38fb4723f4",
                "notAfter": "2047-07-26T22:42:23Z",
                "notBefore": "2017-08-02T22:42:23Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "0",
                "sha1Fingerprint": "47E47FADCE48664689AD46275EE63168CC4CE809",
                "sha256Fingerprint": "197EC3BB1827EFEE9A3FD6CF25A7C88E4C86E25D356D00F84EC3E8FE5B943564",
                "sha512Fingerprint": "C09A87FA4A95F94BED0F005E687FEA097B5F8A2F5670C814B7C887301AD6F7A0CA167E0D3234AA60977A4F46F3884838F255766FCCC24990572F4BD2A769027A",
                "subject": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com",
                "updatedAt": "2024-06-02T11:09:49.267786Z",
                "uri": "kylo:kylo:naboo:external_ca:208d8f42-1af3-4039-8b02-5e38fb4723f4"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-02T11:04:22.586313Z",
                "id": "ef6daa19-6235-4d7a-8a19-86f950836545",
                "issuer": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com",
                "name": "sample-ex-CA1",
                "notAfter": "2047-07-26T22:42:23Z",
                "notBefore": "2017-08-02T22:42:23Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "0",
                "sha1Fingerprint": "47E47FADCE48664689AD46275EE63168CC4CE809",
                "sha256Fingerprint": "197EC3BB1827EFEE9A3FD6CF25A7C88E4C86E25D356D00F84EC3E8FE5B943564",
                "sha512Fingerprint": "C09A87FA4A95F94BED0F005E687FEA097B5F8A2F5670C814B7C887301AD6F7A0CA167E0D3234AA60977A4F46F3884838F255766FCCC24990572F4BD2A769027A",
                "subject": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com",
                "updatedAt": "2024-06-02T11:04:22.586313Z",
                "uri": "kylo:kylo:naboo:external_ca:ef6daa19-6235-4d7a-8a19-86f950836545"
            }
        ]
    }
}
```

#### Human Readable Output

>### External Certificate Authorities

>|Name|Subject|Serial #|Activation|Expiration|Client Auth|User Auth|
>|---|---|---|---|---|---|---|
>| test_ui | /CN=ui_test | 22416116914186521030446027138329400040 | 13 Jun 2024, 16:20 | 13 Jun 2025, 16:20 | Disabled | Disabled |
>| test_external_cert | /C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com | 0 | 02 Aug 2017, 22:42 | 26 Jul 2047, 22:42 | Disabled | Disabled |
>| sample-ex-CA | /C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com | 0 | 02 Aug 2017, 22:42 | 26 Jul 2047, 22:42 | Disabled | Disabled |
>| externalca-5304de93-6939-4a26-bdb4-5e3d0b2fdb38 | /C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com | 0 | 02 Aug 2017, 22:42 | 26 Jul 2047, 22:42 | Disabled | Disabled |
>| externalca-208d8f42-1af3-4039-8b02-5e38fb4723f4 | /C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com | 0 | 02 Aug 2017, 22:42 | 26 Jul 2047, 22:42 | Disabled | Disabled |
>| sample-ex-CA1 | /C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com | 0 | 02 Aug 2017, 22:42 | 26 Jul 2047, 22:42 | Disabled | Disabled |
>
>1 to 6 of 6 External Certificate Authorities

### ciphertrust-external-ca-update

***
Update an external CA.

#### Base Command

`ciphertrust-external-ca-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| external_ca_id | An identifier of the resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Required | 
| allow_client_authentication | If set to true, the certificates signed by the specified CA can be used for client authentication. Possible values are: true, false. | Optional | 
| allow_user_authentication | If set to true, the certificates signed by the specified CA can be used for user authentication. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.ExternalCA.id | String | A unique identifier for the certificate authority \(CA\) certificate. | 
| CipherTrust.ExternalCA.uri | String | Uniform Resource Identifier associated with the CA certificate. | 
| CipherTrust.ExternalCA.account | String | Account associated with the CA certificate. | 
| CipherTrust.ExternalCA.devAccount | String | Developer account associated with the CA certificate. | 
| CipherTrust.ExternalCA.application | String | Application associated with the CA certificate. | 
| CipherTrust.ExternalCA.createdAt | Date | Timestamp of when the CA certificate was created. | 
| CipherTrust.ExternalCA.updatedAt | Date | Timestamp of the last update of the CA certificate. | 
| CipherTrust.ExternalCA.name | String | Name of the CA certificate. | 
| CipherTrust.ExternalCA.purpose.client_authentication | String | If set to enabled, the certificates signed by the specified CA can be used for client authentication. | 
| CipherTrust.ExternalCA.purpose.user_authentication | String | If set to enabled, the certificates signed by the specified CA can be used for user authentication. | 
| CipherTrust.ExternalCA.serialNumber | String | Serial number of the CA certificate. | 
| CipherTrust.ExternalCA.subject | String | Subject of the CA certificate. | 
| CipherTrust.ExternalCA.issuer | String | Issuer of the CA certificate. | 
| CipherTrust.ExternalCA.notBefore | Date | Timestamp of when the CA certificate is valid from. | 
| CipherTrust.ExternalCA.notAfter | Date | Timestamp of when the CA certificate is valid until. | 
| CipherTrust.ExternalCA.sha1Fingerprint | String | SHA1 fingerprint of the CA certificate. | 
| CipherTrust.ExternalCA.sha256Fingerprint | String | SHA256 fingerprint of the CA certificate. | 
| CipherTrust.ExternalCA.sha512Fingerprint | String | SHA512 fingerprint of the CA certificate. | 

#### Command example

```!ciphertrust-external-ca-update external_ca_id="123e0a83-63d3-4632-925b-e78ddbfc7774" allow_client_authentication=true allow_user_authentication=true```

#### Context Example

```json
{
    "CipherTrust": {
        "ExternalCA": {
            "account": "kylo:kylo:admin:accounts:kylo",
            "createdAt": "2024-06-13T16:26:17.877709Z",
            "id": "123e0a83-63d3-4632-925b-e78ddbfc7774",
            "issuer": "/CN=ui_test",
            "name": "test_ui",
            "notAfter": "2025-06-13T16:20:50Z",
            "notBefore": "2024-06-13T16:20:50Z",
            "purpose": {
                "client_authentication": "Enabled",
                "user_authentication": "Enabled"
            },
            "serialNumber": "22416116914186521030446027138329400040",
            "sha1Fingerprint": "999F0159EB3ADB9E2C2591BE19DF0964075ECB77",
            "sha256Fingerprint": "17E54883786AD97D5BFD962F39B9A5CA254E34CAE6012541D606808E4CCA76A0",
            "sha512Fingerprint": "BD052596815129BD78732ADF87265A64534A553F8AFBBAD19EF908FDD68373475D74DD159A112D4AF9DB7E5730064BF23BECDB33DBEE53FBD220F095B8ECF66F",
            "subject": "/CN=ui_test",
            "updatedAt": "2024-06-18T11:21:16.173139941Z",
            "uri": "kylo:kylo:naboo:external_ca:123e0a83-63d3-4632-925b-e78ddbfc7774"
        }
    },
    "InfoFile": {
        "EntryID": "2178@a48e3cfd-a079-4895-89a7-4fac11b8143d",
        "Extension": "pem",
        "Info": "application/x-x509-ca-cert",
        "Name": "Certificate.pem",
        "Size": 627,
        "Type": "PEM certificate"
    }
}
```

#### Human Readable Output

>123e0a83-63d3-4632-925b-e78ddbfc7774 has been updated successfully!

### ciphertrust-external-ca-upload

***
Uploads an external CA certificate. These certificates can later be trusted by services inside the system for verification of client certificates. The uploaded certificate must have "CA:TRUE" as part of the "X509v3 Basic Constraints" to be accepted.

#### Base Command

`ciphertrust-external-ca-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cert_entry_id | The entry ID of the file to upload that contains the external CA certificate in PEM format. | Required | 
| name | A unique name of the CA. If not provided, will be set to externalca-&lt;id&gt;. | Optional | 
| parent | URI reference to a parent external CA certificate. This information can be used to build a certificate hierarchy. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.ExternalCA.id | String | A unique identifier for the certificate authority \(CA\) certificate. | 
| CipherTrust.ExternalCA.uri | String | Uniform Resource Identifier associated with the CA certificate. | 
| CipherTrust.ExternalCA.account | String | Account associated with the CA certificate. | 
| CipherTrust.ExternalCA.devAccount | String | Developer account associated with the CA certificate. | 
| CipherTrust.ExternalCA.application | String | Application associated with the CA certificate. | 
| CipherTrust.ExternalCA.createdAt | Date | Timestamp of when the CA certificate was created. | 
| CipherTrust.ExternalCA.updatedAt | Date | Timestamp of the last update of the CA certificate. | 
| CipherTrust.ExternalCA.name | String | Name of the CA certificate. | 
| CipherTrust.ExternalCA.purpose.client_authentication | String | If set to enabled, the certificates signed by the specified CA can be used for client authentication. | 
| CipherTrust.ExternalCA.purpose.user_authentication | String | If set to enabled, the certificates signed by the specified CA can be used for user authentication. | 
| CipherTrust.ExternalCA.serialNumber | String | Serial number of the CA certificate. | 
| CipherTrust.ExternalCA.subject | String | Subject of the CA certificate. | 
| CipherTrust.ExternalCA.issuer | String | Issuer of the CA certificate. | 
| CipherTrust.ExternalCA.notBefore | Date | Timestamp of when the CA certificate is valid from. | 
| CipherTrust.ExternalCA.notAfter | Date | Timestamp of when the CA certificate is valid until. | 
| CipherTrust.ExternalCA.sha1Fingerprint | String | SHA-1 fingerprint of the CA certificate. | 
| CipherTrust.ExternalCA.sha256Fingerprint | String | SHA-256 fingerprint of the CA certificate. | 
| CipherTrust.ExternalCA.sha512Fingerprint | String | SHA-512 fingerprint of the CA certificate. | 

#### Command example

```"!ciphertrust-external-ca-upload cert_entry_id=2327@a48e3cfd-a079-4895-89a7-4fac11b8143d#### Context Example"```

#### Context Example

```json
{
    "CipherTrust": {
        "ExternalCA": {"id": "34c27997-4d5d-4bd3-9ee6-c93ee9abbc7f", "uri": "kylo:kylo:naboo:external_ca:34c27997-4d5d-4bd3-9ee6-c93ee9abbc7f", "account": "kylo:kylo:admin:accounts:kylo", "createdAt": "2024-06-18T16:38:57.598523Z", "updatedAt": "2024-06-18T16:38:57.598523Z", "name": "externalca-34c27997-4d5d-4bd3-9ee6-c93ee9abbc7f", "purpose": {"client_authentication": "Enabled", "user_authentication": "Enabled"}, "serialNumber": "0", "subject": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com", "issuer": "/C=US/ST=TX/L=Austin/O=Gemalto/OU=RnD/CN=ca.kylo.gemalto.com", "notBefore": "2017-08-02T22:42:23Z", "notAfter": "2047-07-26T22:42:23Z", "sha1Fingerprint": "47E47FADCE48664689AD46275EE63168CC4CE809", "sha256Fingerprint": "197EC3BB1827EFEE9A3FD6CF25A7C88E4C86E25D356D00F84EC3E8FE5B943564", "sha512Fingerprint": "C09A87FA4A95F94BED0F005E687FEA097B5F8A2F5670C814B7C887301AD6F7A0CA167E0D3234AA60977A4F46F3884838F255766FCCC24990572F4BD2A769027A"}
    },
    "InfoFile": {
        "EntryID": "2178@a48e3cfd-a079-4895-89a7-4fac11b8143d",
        "Extension": "pem",
        "Info": "application/x-x509-ca-cert",
        "Name": "Certificate.pem",
        "Size": 627,
        "Type": "PEM certificate"
    }
}
```

#### Human Readable Output

>externalca-34c27997-4d5d-4bd3-9ee6-c93ee9abbc7f has been uploaded successfully!

### ciphertrust-group-create

***
Create a new group. The group name is required.

#### Base Command

`ciphertrust-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the group. | Required | 
| description | Description of the group. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CipherTrust.Group.name | String | The name of the group. | 
| CipherTrust.Group.created_at | Date | The time the group was created. | 
| CipherTrust.Group.updated_at | Date | The time the group was last updated. | 
| CipherTrust.Group.user_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences. | 
| CipherTrust.Group.app_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles. | 
| CipherTrust.Group.client_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. client_metadata is typically used by applications to store information about the resource, such as client preferences. | 
| CipherTrust.Group.description | String | The description of the group. | 
| CipherTrust.Group.users_count | Number | The total user count associated with the group. | 

#### Command example

```!ciphertrust-group-create name="example_group" description="this is an example group"```

#### Context Example

```json
{
    "CipherTrust": {
        "Group": {
            "created_at": "2024-06-18T09:16:04.419126Z",
            "description": "this is an example group",
            "name": "example_group",
            "updated_at": "2024-06-18T09:16:04.419126Z"
        }
    }
}
```

#### Human Readable Output

>example_group has been created successfully!

### ciphertrust-group-delete

***
Deletes a group given the group name.

#### Base Command

`ciphertrust-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Name of the group. | Required | 
| force | When set to true, groupmaps within this group will be deleted. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!ciphertrust-group-delete group_name="example_group" force=true```

#### Human Readable Output

>example_group has been deleted successfully!

### ciphertrust-group-list

***
Returns a list of group  Command arguments can be used to filter the results. Groups can be filtered for user or client membership. Connection filter applies only to user group membership and NOT to clients.

#### Base Command

`ciphertrust-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Filter by group name. | Optional | 
| user_id | Filter by user membership. Using the username 'nil' will return groups with no members. Accepts only a user ID. Using '-' at the beginning of user_id will return groups that the user is not part of. | Optional | 
| connection | Filter by connection name or ID. | Optional | 
| client_id | Filter by client membership. Using the client name 'nil' will return groups with no members. Using '-' at the beginning of client_id will return groups that the client is not part of. | Optional | 
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 2000 (in case only page was provided). Maximum entries per page is 2000. | Optional | 
| limit | The maximum number of entries to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CipherTrust.Group.name | String | Name of the group. | 
| CipherTrust.Group.created_at | Date | The time the group was created. | 
| CipherTrust.Group.updated_at | Date | The time the group was last updated. | 
| CipherTrust.Group.user_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences. | 
| CipherTrust.Group.app_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles. | 
| CipherTrust.Group.client_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. client_metadata is typically used by applications to store information about the resource, such as client preferences. | 
| CipherTrust.Group.description | String | Description of the group. | 
| CipherTrust.Group.users_count | Number | The total user count associated with the group. | 

#### Command example

```!ciphertrust-group-list page=1 page_size=10```

#### Context Example

```json
{
    "CipherTrust": {
        "Group": [
            {
                "app_metadata": {
                    "system": true
                },
                "created_at": "2024-02-14T10:08:17.977229Z",
                "name": "admin",
                "updated_at": "2024-05-15T10:26:18.343973Z",
                "users_count": 1
            },
            {
                "app_metadata": {
                    "system": true
                },
                "created_at": "2024-02-14T10:08:18.069026Z",
                "name": "All Clients",
                "updated_at": "2024-05-15T10:23:48.598464Z"
            },
            {
                "app_metadata": {
                    "system": true
                },
                "created_at": "2024-02-14T10:08:18.221758Z",
                "name": "Application Data Protection Admins",
                "updated_at": "2024-02-14T10:08:18.221758Z"
            },
            {
                "app_metadata": {
                    "system": true
                },
                "created_at": "2024-02-14T10:08:18.247687Z",
                "name": "Application Data Protection Clients",
                "updated_at": "2024-02-14T10:08:18.247687Z"
            },
            {
                "app_metadata": {
                    "system": true
                },
                "created_at": "2024-02-14T10:08:17.935614Z",
                "name": "Audit Admins",
                "updated_at": "2024-02-14T10:08:17.935614Z"
            },
            {
                "app_metadata": {
                    "system": true
                },
                "created_at": "2024-02-14T10:08:18.935864Z",
                "name": "Backup Admins",
                "updated_at": "2024-02-14T10:08:18.935864Z"
            },
            {
                "app_metadata": {
                    "system": true
                },
                "created_at": "2024-02-14T10:08:17.850879Z",
                "name": "CA Admins",
                "updated_at": "2024-02-14T10:08:17.850879Z"
            },
            {
                "app_metadata": {
                    "system": true
                },
                "created_at": "2024-02-14T10:08:18.277244Z",
                "name": "CCKM Admins",
                "updated_at": "2024-02-14T10:08:18.277244Z"
            },
            {
                "app_metadata": {
                    "system": true
                },
                "created_at": "2024-02-14T10:08:18.307685Z",
                "name": "CCKM Users",
                "updated_at": "2024-02-14T10:08:18.307685Z"
            },
            {
                "app_metadata": {
                    "system": true
                },
                "created_at": "2024-02-14T10:08:18.766834Z",
                "name": "Client Admins",
                "updated_at": "2024-02-14T10:08:18.766834Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Groups

>|Name|Defined By|No. Of Members|Description|
>|---|---|---|---|
>| admin | System | 1 |  |
>| All Clients | System |  |  |
>| Application Data Protection Admins | System |  |  |
>| Application Data Protection Clients | System |  |  |
>| Audit Admins | System |  |  |
>| Backup Admins | System |  |  |
>| CA Admins | System |  |  |
>| CCKM Admins | System |  |  |
>| CCKM Users | System |  |  |
>| Client Admins | System |  |  |
>
>1 to 10 of 59 Groups

### ciphertrust-group-update

***
Update the properties of a group given the group name.

#### Base Command

`ciphertrust-group-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Name of the group to update. | Required | 
| new_group_name | New name of the group. | Optional | 
| description | New description of the group. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CipherTrust.Group.name | String | The name of the group. | 
| CipherTrust.Group.created_at | Date | The time the group was created. | 
| CipherTrust.Group.updated_at | Date | The time the group was last updated. | 
| CipherTrust.Group.user_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences. | 
| CipherTrust.Group.app_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles. | 
| CipherTrust.Group.client_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. client_metadata is typically used by applications to store information about the resource, such as client preferences. | 
| CipherTrust.Group.description | String | The description of the group. | 
| CipherTrust.Group.users_count | Number | The total user count associated with the group. | 

#### Command example

```!ciphertrust-group-update group_name="example_group" description="this is a modified description"```

#### Context Example

```json
{
    "CipherTrust": {
        "Group": {
            "created_at": "2024-06-18T09:16:04.419126Z",
            "description": "this is a modified description",
            "name": "example_group",
            "updated_at": "2024-06-18T09:16:08.190417Z"
        }
    }
}
```

#### Human Readable Output

>example_group has been updated successfully!

### ciphertrust-local-ca-create

***
Creates a pending local CA. This operation returns a CSR that either can be self-signed by calling the ciphertrust-local-ca-self-sign command or signed by another CA and installed by calling the ciphertrust-local-ca-install command. A local CA keeps the corresponding private key inside the system and can issue certificates for clients, servers or intermediate CAs. The local CA can also be trusted by services inside the system for verification of client certificates.

#### Base Command

`ciphertrust-local-ca-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cn | Common name. | Required | 
| algorithm | RSA or ECDSA (default) algorithms are supported. Signature algorithm (SHA512WithRSA, SHA384WithRSA, SHA256WithRSA, SHA1WithRSA, ECDSAWithSHA512, ECDSAWithSHA384, ECDSAWithSHA256) is selected based on the algorithm and size. Possible values are: RSA, ECDSA. | Optional | 
| copy_from_ca | ID of any local CA. If given, the CSR properties are copied from the given CA. | Optional | 
| dns_names | A comma-separated list of Subject Alternative Names (SAN) values. | Optional | 
| email | A comma-separated list of e-mail addresses. | Optional | 
| ip | A comma-separated list of IP addresses. | Optional | 
| name | A unique name of the CA. If not provided, will be set to localca-&lt;id&gt;. | Optional | 
| name_fields_raw_json | Name fields are "O=organization, OU=organizational unit, L=location, ST=state/province, C=country". Fields can be duplicated if present in different objects. This is a raw json string, for example: "[{"O": "Thales", "OU": "RnD", "C": "US", "ST": "MD", "L": "Belcamp"}, {"OU": "Thales Group Inc."}]". | Optional | 
| name_fields_json_entry_id | Entry ID of the file that contains JSON representation of the name_fields_raw_json. | Optional | 
| size | Key size. RSA: 1024 - 4096 (default: 2048), ECDSA: 256 (default), 384, 521. Possible values are: 256, 384, 521, 1024, 2048, 3072, 4096. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.LocalCA.id | String | Unique identifier for the CA. | 
| CipherTrust.LocalCA.uri | String | Uniform Resource Identifier for the CA. | 
| CipherTrust.LocalCA.account | String | Account associated with the CA. | 
| CipherTrust.LocalCA.application | String | Application associated with the CA. | 
| CipherTrust.LocalCA.devAccount | String | Developer account associated with the CA. | 
| CipherTrust.LocalCA.createdAt | Date | Timestamp when the CA was created. | 
| CipherTrust.LocalCA.updatedAt | Date | Timestamp when the CA was last updated. | 
| CipherTrust.LocalCA.name | String | Name of the CA. | 
| CipherTrust.LocalCA.state | String | State of the CA. | 
| CipherTrust.LocalCA.subject | String | Distinguished Name \(DN\) of the CA subject. | 
| CipherTrust.LocalCA.notBefore | Date | Timestamp before which the certificate is not valid. | 
| CipherTrust.LocalCA.notAfter | Date | Timestamp after which the certificate is not valid. | 
| CipherTrust.LocalCA.sha1Fingerprint | String | SHA1 fingerprint of the CA certificate. | 
| CipherTrust.LocalCA.sha256Fingerprint | String | SHA256 fingerprint of the CA certificate. | 
| CipherTrust.LocalCA.sha512Fingerprint | String | SHA512 fingerprint of the CA certificate. | 

#### Command example

```!ciphertrust-local-ca-create cn="test.com" name="example_local_ca" algorithm="RSA" name_fields_raw_json="[ {\"O\" : \"FakeCompany\", \"OU\": \"RnD\", \"C\": \"US\", \"ST\": \"CA\", \"L\": \"FakeCity\"}, {\"OU\": \"Fake Group Inc.\"}]" email="fakeemail@fakecompany.com,fakeemail1@fakecompany.com" ip="10.10.10.10,20.20.20.20" dns_names="*.fakecompany.com,*.fakecompany.net"```

#### Context Example

```json
{
    "CipherTrust": {
        "LocalCA": {
            "account": "kylo:kylo:admin:accounts:kylo",
            "createdAt": "2024-06-18T09:16:46.346715Z",
            "id": "b6d991fd-9f15-4412-b6e1-84d1e7620fa6",
            "name": "example_local_ca",
            "notAfter": "0001-01-01T00:00:00Z",
            "notBefore": "0001-01-01T00:00:00Z",
            "sha1Fingerprint": "8C8C3A28F2F279FB192320068C877A43ECF17BD9",
            "sha256Fingerprint": "CB9A0BEEBEE3DCE45AF0A7AEB04DBCEE45981CEC6C0E3EDB52F6D6AE48A87A60",
            "sha512Fingerprint": "62E95ABF6BFA34D8B4E8A0835750D596BF277D6D35AB20EEE673CA0871F15FC39A88AC9EB9E84EB8C3A29480B1227B728BC40B7BCA1E020E628EC076BFAAFA9D",
            "state": "pending",
            "subject": "/C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com",
            "updatedAt": "2024-06-18T09:16:46.346715Z",
            "uri": "kylo:kylo:naboo:localca:b6d991fd-9f15-4412-b6e1-84d1e7620fa6"
        }
    },
    "InfoFile": {
        "EntryID": "2111@a48e3cfd-a079-4895-89a7-4fac11b8143d",
        "Extension": "pem",
        "Info": "application/x-x509-ca-cert",
        "Name": "CSR.pem",
        "Size": 1216,
        "Type": "PEM certificate request"
    }
}
```

#### Human Readable Output

>Pending Local CA test.com has been created successfully!

### ciphertrust-local-ca-delete

***
Deletes a local CA certificate.

#### Base Command

`ciphertrust-local-ca-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| local_ca_id | An identifier of the resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!ciphertrust-local-ca-delete local_ca_id="example_local_ca"```

#### Human Readable Output

>example_local_ca has been deleted successfully!

### ciphertrust-local-ca-install

***
Installs a certificate signed by other CA to act as a local CA. Issuer can be both local or external CA. Typically used for intermediate CAs. The CA certificate must match the earlier created CA CSR, have "CA:TRUE" as part of the "X509v3 Basic Constraints", and have "Certificate Signing" as part of "X509v3 Key Usage" in order to be accepted.

#### Base Command

`ciphertrust-local-ca-install`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| local_ca_id | An identifier of the resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Required | 
| cert_entry_id | The entry ID of the file to upload that contains the signed certificate in PEM format to install as a local CA. | Required | 
| parent_id | An identifier of the parent resource. The resource can be either a local or an external CA. The identifier can be either the ID (a UUIDv4) or the URI. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.CAInstall.id | String | A unique identifier for the certificate authority \(CA\). | 
| CipherTrust.CAInstall.uri | String | Uniform Resource Identifier associated with the CA. | 
| CipherTrust.CAInstall.account | String | Account associated with the CA. | 
| CipherTrust.CAInstall.application | String | Application associated with the CA. | 
| CipherTrust.CAInstall.devAccount | String | Developer account associated with the CA. | 
| CipherTrust.CAInstall.name | String | Name of the CA. | 
| CipherTrust.CAInstall.state | String | Current state of the CA \(e.g., active, pending\). | 
| CipherTrust.CAInstall.createdAt | Date | Timestamp of when the CA was created. | 
| CipherTrust.CAInstall.updatedAt | Date | Timestamp of the last update of the CA. | 
| CipherTrust.CAInstall.serialNumber | String | Serial number of the CA's certificate. | 
| CipherTrust.CAInstall.subject | String | Subject of the CA's certificate. | 
| CipherTrust.CAInstall.issuer | String | Issuer of the CA's certificate. | 
| CipherTrust.CAInstall.notBefore | Date | Start date of the CA's certificate validity. | 
| CipherTrust.CAInstall.notAfter | Date | End date of the CA's certificate validity. | 
| CipherTrust.CAInstall.sha1Fingerprint | String | SHA1 fingerprint of the CA's certificate. | 
| CipherTrust.CAInstall.sha256Fingerprint | String | SHA256 fingerprint of the CA's certificate. | 
| CipherTrust.CAInstall.sha512Fingerprint | String | SHA512 fingerprint of the CA's certificate. | 
| CipherTrust.CAInstall.purpose.client_authentication | String | Indicates if client authentication is enabled for the CA. | 
| CipherTrust.CAInstall.purpose.user_authentication | String | Indicates if user authentication is enabled for the CA. | 

#### Command example

```!ciphertrust-local-ca-install cert_entry_id=2412@a48e3cfd-a079-4895-89a7-4fac11b8143d local_ca_id=7951163f-a91d-4b29-91f7-b8175d732fc2 parent_id=b8f345ba-cd21-41ad-8184-56e6442bc52b"```

#### Context Example

```json
{
    "CipherTrust": {
        "CAInstall": {"id": "7951163f-a91d-4b29-91f7-b8175d732fc2", "uri": "kylo:kylo:naboo:localca:7951163f-a91d-4b29-91f7-b8175d732fc2", "account": "kylo:kylo:admin:accounts:kylo", "createdAt": "2024-06-19T12:01:11.978136Z", "updatedAt": "2024-06-19T12:03:11.738936809Z", "name": "localca-7951163f-a91d-4b29-91f7-b8175d732fc2", "state": "active", "parent": "kylo:kylo:naboo:localca:b8f345ba-cd21-41ad-8184-56e6442bc52b", "serialNumber": "104862149230168133443259457904971639639", "subject": "/CN=test_install_xsoar3", "issuer": "/CN=test_install_xsoar", "notBefore": "2024-06-18T12:01:47Z", "notAfter": "2025-06-19T09:09:09Z", "sha1Fingerprint": "DD65DC5FEDF16974AEAE5E3E5A82685E6CCA0441", "sha256Fingerprint": "32522F9E95722699AD4F23E7ADBD224397A1D7ECDFE1357764B86F6965130741", "sha512Fingerprint": "108CB8FB382A18C431DF02B98BAB70DD6B7BCD88350FE2BB74100F0BCE13C2B131AF3B26E9A5095C4791B168F723A239081B6A846DEA21A073D0288E22E28866", "purpose": {"client_authentication": "Enabled", "user_authentication": "Enabled"}}

    } , 
    "InfoFile": {
        "EntryID": "2116@a48e3cfd-a079-4895-89a7-4fac11b8143d",
        "Extension": "pem",
        "Info": "application/x-x509-ca-cert",
        "Name": "Certificate.pem",
        "Size": 1533,
        "Type": "PEM certificate"
    }
}
```

#### Human Readable Output

>7951163f-a91d-4b29-91f7-b8175d732fc2 has been installed successfully!


### ciphertrust-local-ca-list

***
Returns a list of local CA certificates. The results can be filtered, using the command arguments. If local_ca_id is provided, a single local CA certificate is returned and the rest of the filters are ignored. A chained parameter is used to return the full CA chain with the certificate and can be used only if local_ca_id is provided.

#### Base Command

`ciphertrust-local-ca-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subject | Filter by subject. | Optional | 
| local_ca_id | An identifier of the resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Optional | 
| chained | When set to ‘true’ the full CA chain is returned with the certificate. Must be used with the local CA ID. Possible values are: true, false. | Optional | 
| issuer | Filter by issuer. | Optional | 
| state | Filter by state. Possible values are: pending, active. | Optional | 
| cert | Filter by cert. | Optional | 
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 2000 (in case only page was provided). Maximum entries per page is 2000. | Optional | 
| limit | The maximum number of entries to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report. | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.LocalCA.id | String | A unique identifier for the certificate authority \(CA\). | 
| CipherTrust.LocalCA.uri | String | Uniform Resource Identifier associated with the CA. | 
| CipherTrust.LocalCA.account | String | Account associated with the CA. | 
| CipherTrust.LocalCA.name | String | Name of the CA. | 
| CipherTrust.LocalCA.state | String | Current state of the CA \(e.g., pending, active\). | 
| CipherTrust.LocalCA.createdAt | Date | Timestamp of when the CA was created. | 
| CipherTrust.LocalCA.updatedAt | Date | Timestamp of last update of the CA. | 
| CipherTrust.LocalCA.serialNumber | String | Serial number of the CA's certificate. | 
| CipherTrust.LocalCA.subject | String | Subject of the CA's certificate. | 
| CipherTrust.LocalCA.issuer | String | Issuer of the CA's certificate. | 
| CipherTrust.LocalCA.notBefore | Date | Start date of the CA's certificate validity. | 
| CipherTrust.LocalCA.notAfter | Date | End date of the CA's certificate validity. | 
| CipherTrust.LocalCA.sha1Fingerprint | String | SHA1 fingerprint of the CA's certificate. | 
| CipherTrust.LocalCA.sha256Fingerprint | String | SHA256 fingerprint of the CA's certificate. | 
| CipherTrust.LocalCA.sha512Fingerprint | String | SHA512 fingerprint of the CA's certificate. | 
| CipherTrust.LocalCA.purpose.client_authentication | String | Indicates if client authentication is enabled for the CA. | 
| CipherTrust.LocalCA.purpose.user_authentication | String | Indicates if user authentication is enabled for the CA. | 

#### Command example

```!ciphertrust-local-ca-list```

#### Context Example

```json
{
    "CipherTrust": {
        "LocalCA": [
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-18T09:16:46.346715Z",
                "id": "b6d991fd-9f15-4412-b6e1-84d1e7620fa6",
                "issuer": "/C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com",
                "name": "example_local_ca",
                "notAfter": "2027-06-18T09:16:51Z",
                "notBefore": "2024-05-29T00:00:00Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "158212075602881140442360379812918138547",
                "sha1Fingerprint": "A1AE2F3379AB18EEEC97BD43CC3E4BF4379482A4",
                "sha256Fingerprint": "64CE213A62F3135FE74E7CC6D514DCCDBB2638F222B9E846D0C6C3F8381BE088",
                "sha512Fingerprint": "84AE8CD3B6B0C214BAC03BFDE1AD2FE0054D32B6CF7CAF6738958CD07D781409EA01B444DDBBCD28F2F52D79393169840FD87C7967815842A6AC0A624F86543F",
                "state": "active",
                "subject": "/C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com",
                "updatedAt": "2024-06-18T09:16:53.961878Z",
                "uri": "kylo:kylo:naboo:localca:b6d991fd-9f15-4412-b6e1-84d1e7620fa6"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-02T13:50:59.442596Z",
                "id": "3dc1f629-23b6-4cce-876a-c7d07a4862cd",
                "issuer": "/CN=demo_prep_example.com",
                "name": "localca-3dc1f629-23b6-4cce-876a-c7d07a4862cd",
                "notAfter": "2025-06-02T13:58:56Z",
                "notBefore": "2024-06-01T13:58:37Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "129102809746806914708740056180976394480",
                "sha1Fingerprint": "8795D8843988D8ABA7B5ECCCAA8F414FB70A5B08",
                "sha256Fingerprint": "6BE944A57213DBB1B9E4F1BC8211AD6FCEA750F63D82CDD3CA0FA2BF1084442A",
                "sha512Fingerprint": "C673F28EBAF45490A9A4C3E7BF33ED772411327A1326857180F10486F240A22CE9D401398D76D12B0E17B955A7659B04048D7FA27CC7EF2C8A565A55B88B1482",
                "state": "active",
                "subject": "/CN=demo_prep_example.com",
                "updatedAt": "2024-06-18T06:00:07.883133Z",
                "uri": "kylo:kylo:naboo:localca:3dc1f629-23b6-4cce-876a-c7d07a4862cd"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-02T14:32:09.832603Z",
                "id": "c344cb9e-7607-47ac-968a-d6bba7cbd74c",
                "issuer": "/C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com",
                "name": "test_local_ca",
                "notAfter": "2025-06-04T14:10:29Z",
                "notBefore": "2024-06-03T14:10:29Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "226220228835411560013591369440322067707",
                "sha1Fingerprint": "57A5557A19DABE380C560E9696ADC95085317476",
                "sha256Fingerprint": "559AEF7C71DF2A7EF81704A31C6550E0781C42B6237A2171A8B73F4D17FA3FAB",
                "sha512Fingerprint": "1A1CBCA18131894851D9C956BDC0754218E5AEE37CE0E15180B8101F6072E9DF37062CB0B04DCAA220E943C9D2B7DA62730116B5D26E8A363B0C62E6BCFB242C",
                "state": "active",
                "subject": "/C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com",
                "updatedAt": "2024-06-18T06:00:07.871254Z",
                "uri": "kylo:kylo:naboo:localca:c344cb9e-7607-47ac-968a-d6bba7cbd74c"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-29T14:06:12.422696Z",
                "id": "0c064746-950d-49cd-b148-28345099f83e",
                "issuer": "/CN=test-for-list",
                "name": "test",
                "notAfter": "2025-06-04T14:09:28Z",
                "notBefore": "2024-06-03T14:09:28Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "72278925304596589280809592640662340361",
                "sha1Fingerprint": "FA763C8B661592CFCA54AD2D2028F5F786C36BD6",
                "sha256Fingerprint": "91165F6464004500B4A365D5574F07C5BA56A2E1819C6602BCB695D138D61D8F",
                "sha512Fingerprint": "536CAAB4D2E3A2B16920447040EFA858B734260CADCAD1B54E4533063C037EF4EE62574424C63D939573FB54308C8345B135B681770DD35BF140B6AC91FB8A34",
                "state": "active",
                "subject": "/CN=test-for-list",
                "updatedAt": "2024-06-18T06:00:07.852308Z",
                "uri": "kylo:kylo:naboo:localca:0c064746-950d-49cd-b148-28345099f83e"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-05T11:27:40.721049Z",
                "id": "f443d295-875a-4697-baf6-d02c17f23d78",
                "issuer": "/CN=test-create-local-ca",
                "name": "localca-f443d295-875a-4697-baf6-d02c17f23d78",
                "notAfter": "2025-06-05T14:18:53Z",
                "notBefore": "2024-06-04T14:18:53Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "180344290974933345373617443253119448463",
                "sha1Fingerprint": "B18A52AB571BEF1814A3F35BC72DCA32494F5C19",
                "sha256Fingerprint": "BF10A2E5E1CFF768FF05FFABAB73D2E6E374AA22BA5DF76DCB99BEE30A69F94E",
                "sha512Fingerprint": "19AEE9D9CAFBB00BC26CF5738016888EA477A4714C7F23CFECB1C80E8D8BE42F33616266665F5F943E0B9F7B1F51EA74A67118431F4373124833A071140EF6CC",
                "state": "active",
                "subject": "/CN=test-create-local-ca",
                "updatedAt": "2024-06-18T06:00:07.841195Z",
                "uri": "kylo:kylo:naboo:localca:f443d295-875a-4697-baf6-d02c17f23d78"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-30T10:00:40.28504Z",
                "id": "59428dfa-cde9-4f68-907b-e7c0b61bfa4c",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "name": "local_ca_to_self_sign",
                "notAfter": "2027-05-30T10:01:23Z",
                "notBefore": "2024-05-29T00:00:00Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "337185028007684692646558478315771697994",
                "sha1Fingerprint": "F3B518615DD0E1CE749ED25A5C37EE7F6FABFAAB",
                "sha256Fingerprint": "11A5501C7392F271F054528B0616A21DB9A3EC344F804BAA0719EF3F40C7ACAC",
                "sha512Fingerprint": "EF3430071462784B5F14A177BB6CFC7D6B6CEE827810D1DE7B7B0873E33EE8BC336A4432E7BADFEA5884D786C46EF6B94E41E0CACCC4E195328C90C13311F21F",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.823493Z",
                "uri": "kylo:kylo:naboo:localca:59428dfa-cde9-4f68-907b-e7c0b61bfa4c"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-04T12:11:15.189525Z",
                "id": "0fb05898-6817-4d29-a47f-59820e437a22",
                "issuer": "/CN=test_file_csr",
                "name": "localca-0fb05898-6817-4d29-a47f-59820e437a22",
                "notAfter": "2025-06-16T12:25:33Z",
                "notBefore": "2024-06-15T12:25:33Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "118269231003356260767200023246958364211",
                "sha1Fingerprint": "4EBCD1107C6E9D0CD6DE0B1F732BE948E5F2812C",
                "sha256Fingerprint": "DB4B059D1BFA34766DDABFC6AAC46A121E21F4599FC6484FC30688622CBD7645",
                "sha512Fingerprint": "126D8A3003C386C0B8DF308EB40AAD2148D633699FEC52627531B0A019A1EDF1EF6355094F9435FFE10EF15F7AD4F8053FA2080E587E867B2A9FE684B9C325C8",
                "state": "active",
                "subject": "/CN=test_file_csr",
                "updatedAt": "2024-06-18T06:00:07.810481Z",
                "uri": "kylo:kylo:naboo:localca:0fb05898-6817-4d29-a47f-59820e437a22"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-30T11:10:39.755016Z",
                "id": "e1e48b6e-6667-40e3-86cd-f08b3b9e53ba",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "name": "local-ca-install-id",
                "notAfter": "2025-06-16T12:25:33Z",
                "notBefore": "2024-06-15T12:25:33Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "28062530453531757191324395315743257082",
                "sha1Fingerprint": "8E75B6B282A91C154FB25967EADBD82165B54840",
                "sha256Fingerprint": "4A00919731687390BD106F1FD296C08B5FA54CB9B46192B6934A8A1DB8A4DAEC",
                "sha512Fingerprint": "226DA64DE03AB767B70B317E0A56AB4D2167B29F9AF721ED183A0EC62CE9960C26D6482E29767F4875FC3E56B5639555DEB0009D2EE9983FAD46FB184A3268B8",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.797766Z",
                "uri": "kylo:kylo:naboo:localca:e1e48b6e-6667-40e3-86cd-f08b3b9e53ba"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-21T13:19:41.449865Z",
                "id": "1f859430-c78e-40a8-bfd6-a415b30a3a63",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "name": "maya-CA-2",
                "notAfter": "2026-10-02T14:18:54Z",
                "notBefore": "2024-05-20T13:20:15Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "128976853845189850850256632563440174889",
                "sha1Fingerprint": "2ECC4A337649FF08DC0FA558EC7AF87460D16BD4",
                "sha256Fingerprint": "3C2F9BBBA2F4524F0517BE5B267EF60B16DBA28EFEE3D86096180C474BCA0546",
                "sha512Fingerprint": "FDBB9645378AFE65C70CE13A73BB0EC914E2D5D56BDA06D427E04AF846E9B991EC3550A3709358BBFD44D4D6C01EA7F5C016BBFD791B22DBA50E50266DD66448",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.7817Z",
                "uri": "kylo:kylo:naboo:localca:1f859430-c78e-40a8-bfd6-a415b30a3a63"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-29T12:24:34.286644Z",
                "id": "f1d8f086-ae3a-4c95-a879-20d8095dc951",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com",
                "name": "localca-f1d8f086-ae3a-4c95-a879-20d8095dc951",
                "notAfter": "2025-06-16T12:25:33Z",
                "notBefore": "2024-06-15T12:25:33Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "329109383730933252345740275059611042991",
                "sha1Fingerprint": "F82D7E516D012053EA058E2C1224F0C436BD35FD",
                "sha256Fingerprint": "F59CFF7764BBE2E7064DB92CB70691ABAC0897186F8986016EEE5E5215136C59",
                "sha512Fingerprint": "CBEC6CB5A35E0D1D25C911CF7B3BB4233CF556E08A201E2649B2FE6711959707E8124824D2BE01D5663760BE9D216CBEB91B8E33A88C8CCB56F4F9A0B3610A42",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com",
                "updatedAt": "2024-06-18T06:00:07.764977Z",
                "uri": "kylo:kylo:naboo:localca:f1d8f086-ae3a-4c95-a879-20d8095dc951"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-29T12:21:21.389352Z",
                "id": "30ac1fb0-1c3d-4d73-9a23-83e48c8860d7",
                "issuer": "/CN=test.com",
                "name": "localca-30ac1fb0-1c3d-4d73-9a23-83e48c8860d7",
                "notAfter": "2025-06-16T12:25:34Z",
                "notBefore": "2024-06-15T12:25:34Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "65114707427365325108519135462150843996",
                "sha1Fingerprint": "D7892C0251C0B056555F881203901020EE4029AA",
                "sha256Fingerprint": "8DFA6C01D36AE23DA4CFCE6C1A8EA85CA1728851B2EC358D7F8F48B1A2AB024E",
                "sha512Fingerprint": "91D07C84ACC84031D3EC3ECF70823C25CCD18DA51BB9FD1A88EA4ED442486D42714D178835AD482DDC848C44C4EE37933CB566E910BC3FF5EAA957FD688AFA46",
                "state": "active",
                "subject": "/CN=test.com",
                "updatedAt": "2024-06-18T06:00:07.746065Z",
                "uri": "kylo:kylo:naboo:localca:30ac1fb0-1c3d-4d73-9a23-83e48c8860d7"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-29T12:16:09.687194Z",
                "id": "ceacaf33-6572-4bfa-84f2-60ff94d5e007",
                "issuer": "/CN=test.com",
                "name": "localca-ceacaf33-6572-4bfa-84f2-60ff94d5e007",
                "notAfter": "2025-06-16T12:25:35Z",
                "notBefore": "2024-06-15T12:25:35Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "32761860285466905109737610122636607959",
                "sha1Fingerprint": "9221D87DC7BD7CB57CC0027863591A16D1EF7EFC",
                "sha256Fingerprint": "58C6BD22090F5D03CD32EDF408624BBE40C64C529BED3FBF66B125DA9A926C88",
                "sha512Fingerprint": "F952B3623876CA28CD9127947F55318DE5A01927AB1FFCE84BF25B964DE63749AA35B3644F8420572B7E993069F6014176671AA94E993AB1D4548DE78833428A",
                "state": "active",
                "subject": "/CN=test.com",
                "updatedAt": "2024-06-18T06:00:07.713979Z",
                "uri": "kylo:kylo:naboo:localca:ceacaf33-6572-4bfa-84f2-60ff94d5e007"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-29T12:16:09.784609Z",
                "id": "8e4a12e3-b7f7-4a96-adc5-6fecbfdf9df5",
                "issuer": "/CN=test.com",
                "name": "localca-8e4a12e3-b7f7-4a96-adc5-6fecbfdf9df5",
                "notAfter": "2025-06-16T12:25:35Z",
                "notBefore": "2024-06-15T12:25:35Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "133607681255884779182134929191905670600",
                "sha1Fingerprint": "CC14391B56FE3B15647E5FB3D6B0A424C7CC68A7",
                "sha256Fingerprint": "64A53D4F141C4B6D6533351C515882F17091B6503E6B3792871BE293A33FAC45",
                "sha512Fingerprint": "9AE87D3FEB5F378466223B7CC570D9F747CD0CAA73EC4E9AA07B7BEA2646D9D3A78F215D858336984A7D17B926D5A4E873AD7CA0FCBDCFD3D3BAC56736181061",
                "state": "active",
                "subject": "/CN=test.com",
                "updatedAt": "2024-06-18T06:00:07.694943Z",
                "uri": "kylo:kylo:naboo:localca:8e4a12e3-b7f7-4a96-adc5-6fecbfdf9df5"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-22T12:59:55.221059Z",
                "id": "34da3d07-af70-4337-954e-69d005c16935",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo2.com",
                "name": "isempty1?",
                "notAfter": "2025-06-16T12:25:36Z",
                "notBefore": "2024-06-15T12:25:36Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "163510084562999310649486415171752198390",
                "sha1Fingerprint": "696DE542F2D0CD8CBCE65CBF343BA1AC5F910543",
                "sha256Fingerprint": "B99D7EF4FDC5ED893D1BB690088A0823790976BD5A5688A0178D108851BB24A5",
                "sha512Fingerprint": "32A27F0E253D3A5D60E03461E92B98243785D42555A9EEE444644EF428523AA2BDA9B1FC93B65B04ADDB6B75897BDCF0EA8208FD831C72B0AC1E95A90916BC21",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo2.com",
                "updatedAt": "2024-06-18T06:00:07.66463Z",
                "uri": "kylo:kylo:naboo:localca:34da3d07-af70-4337-954e-69d005c16935"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-22T12:58:08.17471Z",
                "id": "a388fb38-ece2-4ae8-a7b4-5821821bc180",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo2.com",
                "name": "isempty?",
                "notAfter": "2025-06-16T12:25:36Z",
                "notBefore": "2024-06-15T12:25:36Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "135850894135202628853705544520531120469",
                "sha1Fingerprint": "110BA6BE46514E7A0FC8CD4C0C0936E9DD1D6E30",
                "sha256Fingerprint": "040070505A9B4616EDCD9FB7138CC59C038BBEC81B4E18A4CFC849BF0ED1AE90",
                "sha512Fingerprint": "3B3EFF0F6BDA314AF77081AF7BA8A8441E4ABF51ABA7562B305FA2148EB6C7D270D0C4067508307C428868AF8950360CE17E842A9C411AA380BD8AEA4F79FB72",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo2.com",
                "updatedAt": "2024-06-18T06:00:07.653675Z",
                "uri": "kylo:kylo:naboo:localca:a388fb38-ece2-4ae8-a7b4-5821821bc180"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-22T12:55:15.479369Z",
                "id": "347cf0c8-8a4e-4c9a-9dbb-0f4375b08904",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "name": "test1",
                "notAfter": "2025-06-16T12:25:37Z",
                "notBefore": "2024-06-15T12:25:37Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "178903473729619830181379965311891574804",
                "sha1Fingerprint": "C2CD5D509447FF7EA4A263EFAC146C7EAE5CE1C5",
                "sha256Fingerprint": "88D01F7125EBD222B9EB7515935676256C68BC420ACD057FD75AC438A3A164F0",
                "sha512Fingerprint": "24867CCB471745B551C453EAE3CCB33E2080D402CB2CF4F13F2DD126156B4F546F0C0EFC65A47C7A841FCC3AF49CF4128D2CFCF1FB145212DC34F9684C18B715",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.642528Z",
                "uri": "kylo:kylo:naboo:localca:347cf0c8-8a4e-4c9a-9dbb-0f4375b08904"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-22T12:54:22.457459Z",
                "id": "133aa865-0c12-4b56-9d9a-6ca513b28ef8",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "name": "localca-&lt;id&gt;",
                "notAfter": "2025-06-16T12:25:37Z",
                "notBefore": "2024-06-15T12:25:37Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "225686445354134570260952387642633959405",
                "sha1Fingerprint": "C636C3383D838EAC1F5400A16371C3416A2FB20C",
                "sha256Fingerprint": "BE30A437423EFC73F21D0BCD024971EC2EEEDAE65415E98E89F69C4BC01C66B5",
                "sha512Fingerprint": "F7D2D38C6251986EB1488D3415726250838D13D327B15B89FFDD018584192ADBB7082782BA26A18BE6A1D54E47CD98DDC22DF10C5DE7D1D49B23065397D882C3",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.632064Z",
                "uri": "kylo:kylo:naboo:localca:133aa865-0c12-4b56-9d9a-6ca513b28ef8"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-02-14T10:08:23.183338Z",
                "id": "b765018b-0a64-419f-b537-c30863aa4002",
                "issuer": "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA",
                "name": "localca-b765018b-0a64-419f-b537-c30863aa4002",
                "notAfter": "2034-02-11T10:08:23Z",
                "notBefore": "2024-02-13T10:08:23Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "24463087808077808513660017390325960995",
                "sha1Fingerprint": "95501310032AC365DA329943544328F1A0D9BFE1",
                "sha256Fingerprint": "17A5F233415F168A67FD60CB4DC12701643D779F9D5E0CA5F3CA478F8DA35977",
                "sha512Fingerprint": "140E4DA76CABE643290FCF767636EF79DBA642D8E4D63B6A33DBF7F0BA97CF0DB081E863115E8B68503F441E57521440AD2880BC15056DAEAEFC2150AD2597DA",
                "state": "active",
                "subject": "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA",
                "updatedAt": "2024-06-18T06:00:07.622654Z",
                "uri": "kylo:kylo:naboo:localca:b765018b-0a64-419f-b537-c30863aa4002"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-01T10:01:02.882943Z",
                "id": "6e83a577-1d18-4fc3-b67c-a5584988d364",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/CN=kylo.com",
                "name": "sarah-2-CA",
                "notAfter": "2025-05-01T10:05:06Z",
                "notBefore": "2024-05-01T10:05:06Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "297957266980521970680269241879076856098",
                "sha1Fingerprint": "1AE42F95F669E8A0F0B23A6389EA3A315E38AC9A",
                "sha256Fingerprint": "9ED2D69C09D6F5D1A20668BD6B26B45C3BF423C4806E2C2DBE99A8F6A5E5C15F",
                "sha512Fingerprint": "451C108C849EFBD58F48650303B04286AA68BE797D66895817CC23A921DD359E42EF4A34CA6EC85190F9153DF93627E5EFC99C9738BE4A6243FEF0563DECF4B4",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.5745Z",
                "uri": "kylo:kylo:naboo:localca:6e83a577-1d18-4fc3-b67c-a5584988d364"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-21T09:08:41.428696Z",
                "id": "bbd1673c-1fc2-42a8-ad37-6f2754fe18ef",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "name": "maya-CA",
                "notAfter": "2025-05-16T12:54:12Z",
                "notBefore": "2024-05-20T12:54:12Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "139248642490513216788901886347651629296",
                "sha1Fingerprint": "81B53CE8DED9C51431C0C2D1EA29E14CE434A7C2",
                "sha256Fingerprint": "BF9600831A6B27ED2E36EA0515102D0EA09176D92097560AAD7D1E0983EE40A4",
                "sha512Fingerprint": "FFDC398F6165ADD78F877703E061CD14FD7AB5627DB319AF7804AFD2FE0F38FA56D46A24B65D9587B29A6DC85410D5D6AE0E642960589231D427B638C21ACFE3",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.554717Z",
                "uri": "kylo:kylo:naboo:localca:bbd1673c-1fc2-42a8-ad37-6f2754fe18ef"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-01T09:25:23.466579Z",
                "id": "9ccf5388-eb33-4b5d-b3bb-6060ab98c1d5",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/CN=kylo.com",
                "name": "sarah-CA",
                "notAfter": "2025-10-02T14:18:54Z",
                "notBefore": "2024-04-30T09:29:51Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "236129256119494718420321950585891385888",
                "sha1Fingerprint": "B17E8EB74815FC621E2B23D179BEBA7FA4263EF2",
                "sha256Fingerprint": "62EE11844937C32BAE0EC5E16355974F9AAE3DD1009C27F6D86096684232CB45",
                "sha512Fingerprint": "CDF22703E7CABE951189129C64EF0DE985425568D3ABD0832A35C22DEDE98544FD95911706710D908F05185DA8716A61269572E7003AB5BF7F2E75ECCCA14D46",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.536067Z",
                "uri": "kylo:kylo:naboo:localca:9ccf5388-eb33-4b5d-b3bb-6060ab98c1d5"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-29T12:21:21.314953Z",
                "id": "ded8d992-c884-4f98-ad4f-68264b263e09",
                "issuer": "/CN=test.com",
                "name": "localca-ded8d992-c884-4f98-ad4f-68264b263e09",
                "notAfter": "2025-06-16T12:25:34Z",
                "notBefore": "2024-06-15T12:25:34Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "192835835797178633282551614520727069145",
                "sha1Fingerprint": "C76A298698199C1B0B3446B102D678D8A11478C6",
                "sha256Fingerprint": "79EC6734DA6300914F7351518793AD238A6EC0141DBBD7ED0F04594C4689004D",
                "sha512Fingerprint": "4ECB9BFD5AF6A81221FB81DB9304A32C7F690B8149630562BE4AE5DE0B522F4A4FE1D7AA8E85D0022F7978B4A3E02288ADEBE45F3C000288F2061E46A2A0F47C",
                "state": "active",
                "subject": "/CN=test.com",
                "updatedAt": "2024-06-18T06:00:07.518207Z",
                "uri": "kylo:kylo:naboo:localca:ded8d992-c884-4f98-ad4f-68264b263e09"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-29T12:23:06.194396Z",
                "id": "2f0c4e7f-b388-427b-a9b3-532e3f330561",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com",
                "name": "localca-2f0c4e7f-b388-427b-a9b3-532e3f330561",
                "notAfter": "2025-06-16T12:25:34Z",
                "notBefore": "2024-06-15T12:25:34Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "190170845302674761124094601994094514926",
                "sha1Fingerprint": "B5AEE4A08BF0953D90D7482367F999FF2F75548C",
                "sha256Fingerprint": "121A166A5BC3DCABBB46AD26DBDF6AB040A7566328CA78D44465F1473B54D8B5",
                "sha512Fingerprint": "35C4C894C469A90F7F7715DB9806AB0F7765ADD00C3A6ECF0DED72F43B89D2A47D690CF0C1A4629146493BCD2F488E2D3B6684AC38417D37CAE88BFFD7F7F3D8",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com",
                "updatedAt": "2024-06-18T06:00:07.500333Z",
                "uri": "kylo:kylo:naboo:localca:2f0c4e7f-b388-427b-a9b3-532e3f330561"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-04T13:37:24.272928Z",
                "id": "2630504e-ab3f-4b85-b176-319c18a8b014",
                "issuer": "/CN=test_file_csr2",
                "name": "localca-2630504e-ab3f-4b85-b176-319c18a8b014",
                "notAfter": "2025-06-16T12:25:32Z",
                "notBefore": "2024-06-15T12:25:32Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "39968239672548719518544113345523146127",
                "sha1Fingerprint": "7FFD27D438E714D922F2DC6A9EFBD86FFA9F9093",
                "sha256Fingerprint": "478BD5B8E1F65667535F251FBDBB18A9652009B8B0A188C45F6261311449630C",
                "sha512Fingerprint": "54A3DE245C4D4B14C7948CFE9E5816162980942E8D12FEBDFC0A7BD80F21B6478ECD1DA64A626239E2F87D3E4E6034996677B0F332BFA81408CB33DD0E2B032E",
                "state": "active",
                "subject": "/CN=test_file_csr2",
                "updatedAt": "2024-06-18T06:00:07.484363Z",
                "uri": "kylo:kylo:naboo:localca:2630504e-ab3f-4b85-b176-319c18a8b014"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:27:24.983009Z",
                "id": "5628ca09-01e7-4a4e-bc72-7259a5e7c70e",
                "issuer": "/CN=test_playbook",
                "name": "localca-5628ca09-01e7-4a4e-bc72-7259a5e7c70e",
                "notAfter": "2025-06-16T12:27:33Z",
                "notBefore": "2024-06-15T12:27:33Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "4568441388696325044749525549789309664",
                "sha1Fingerprint": "243F1E1EA1396D939C9C0697176B0CEFD9C6E7D2",
                "sha256Fingerprint": "0AC8824CD69389F18CDB635D08C58A1ACA92A7C2FC9E6A87BCE2FE5F8321C119",
                "sha512Fingerprint": "2F468190B27939064B888521C6FFD003A6FD1F8BC46952F7395B3858A48D1623963280031B9189F492588CFCBEAC5EE13D73051DD218E5347E3F1CC6B7D20135",
                "state": "active",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-18T06:00:07.472999Z",
                "uri": "kylo:kylo:naboo:localca:5628ca09-01e7-4a4e-bc72-7259a5e7c70e"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-29T11:55:19.867526Z",
                "id": "55c87381-bfe9-425c-aa5e-2bcfe90bb8a9",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "name": "maya-CA-4",
                "notAfter": "2025-06-16T12:25:35Z",
                "notBefore": "2024-06-15T12:25:35Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "103684251574198102057496728651123185286",
                "sha1Fingerprint": "998DD862B212F381E77271762E581EBEC9FF858A",
                "sha256Fingerprint": "CE12A2DE2FDFFF1F59489ACF2A3E2043A652BFF158EC7C745548683BC3F3D958",
                "sha512Fingerprint": "0A084FED2D0B58850FB14928A0EFC9CF5732658A6BE646706AD16F1B6345A7C362B8055E0CA95D36A3FC984117B5DF5D249A446E91834590CDABCA9C680D72A2",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.459517Z",
                "uri": "kylo:kylo:naboo:localca:55c87381-bfe9-425c-aa5e-2bcfe90bb8a9"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-29T12:24:33.945893Z",
                "id": "eff61372-2db0-44cd-bbbd-2563393c55d8",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com",
                "name": "localca-eff61372-2db0-44cd-bbbd-2563393c55d8",
                "notAfter": "2025-06-16T12:25:34Z",
                "notBefore": "2024-06-15T12:25:34Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "225201555731716426434835627487751507394",
                "sha1Fingerprint": "FE608ED4B6C7009D853F57E980F6A5E714446CB3",
                "sha256Fingerprint": "6CA5290925B8E787CE53705BB34DA8DFC42A5D0DA29CA897FF2E8827C401C5E7",
                "sha512Fingerprint": "5AF5E13D9628B3AF063BE32690BAA02B9FAE781030C6CCC4A6560AD27977EECE60AACFB5323DCE3EDF16A4C4F0C2D6652278917351DA43A0970FD8F63A4FC32A",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com",
                "updatedAt": "2024-06-18T06:00:07.442691Z",
                "uri": "kylo:kylo:naboo:localca:eff61372-2db0-44cd-bbbd-2563393c55d8"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-22T13:00:21.409221Z",
                "id": "4373e752-0a9f-4be6-a656-c46aeec54b69",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo2.com",
                "name": "isempty2?",
                "notAfter": "2025-06-16T12:25:35Z",
                "notBefore": "2024-06-15T12:25:35Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "213214243161581230018528102469896633667",
                "sha1Fingerprint": "9DEC2C529EFFDDE98E91CE60AF4D769D2E380851",
                "sha256Fingerprint": "B7209755BF4A7DCC403A786E8C3B6641FDC9BB36690ADD3FEBE6AA495C82BD7A",
                "sha512Fingerprint": "C3A4B266C9C2EDF76B22019A12105C2B18B6F513EAB97214B6C7E56F244B0ED9BB45C77F605B9205EB8B9ADD87CE57A1CD5652002639EA48B744E6FABBD86799",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo2.com",
                "updatedAt": "2024-06-18T06:00:07.421636Z",
                "uri": "kylo:kylo:naboo:localca:4373e752-0a9f-4be6-a656-c46aeec54b69"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-22T12:55:38.694393Z",
                "id": "1286a11c-3658-44e1-a531-2c14801bf4a3",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "name": "test2",
                "notAfter": "2025-06-16T12:25:36Z",
                "notBefore": "2024-06-15T12:25:36Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "43170575982063033673607674252675234514",
                "sha1Fingerprint": "AB204A739469D7AA9AC53E2903986D63B50D981B",
                "sha256Fingerprint": "F2893432FE12E6655CB7B3A89FBCA400A3FC57A204F51B8776C21234213A2C25",
                "sha512Fingerprint": "BC70A8557A93EC647A2768F8C3C0DA607904323570B5B59507F07B88759C0DB312FB9D7CE349CC23F8F9A391D09794A507B8E0E781D8E552D313FC1C9F6A3978",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.410021Z",
                "uri": "kylo:kylo:naboo:localca:1286a11c-3658-44e1-a531-2c14801bf4a3"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-30T11:10:47.601507Z",
                "id": "32b5b614-99c2-4490-83f3-ea7c08474588",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "name": "local-ca-install-parent-id",
                "notAfter": "2025-06-16T12:25:33Z",
                "notBefore": "2024-06-15T12:25:33Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "85223021320069691669631123788141870709",
                "sha1Fingerprint": "A564D6D5DF3D9FAA29742355C6E1F881943ABC9A",
                "sha256Fingerprint": "8B9D262AED2B605C148D84B2E876A6F82B00648ECD422A7EF74EBCF9501794DD",
                "sha512Fingerprint": "BD5F06BB99A6B40ECFEBA36052D546B9826715FA5D2E67C44E3CB94BF38E8CE0B71793BC03CB9211724BE2CF0B06DF738A54C5C399AAD92C89A32D57215635D6",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.397802Z",
                "uri": "kylo:kylo:naboo:localca:32b5b614-99c2-4490-83f3-ea7c08474588"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-03T12:07:06.204841Z",
                "id": "f96e3d3b-6962-4abe-938b-3920134a4a3d",
                "issuer": "/CN=EXAMPLE2.COM",
                "name": "localca-f96e3d3b-6962-4abe-938b-3920134a4a3d",
                "notAfter": "2025-06-16T12:25:33Z",
                "notBefore": "2024-06-15T12:25:33Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "199509253732682618926504109082709033771",
                "sha1Fingerprint": "941B38A061AED06BBA476EF41C4C09E9FA2788D5",
                "sha256Fingerprint": "07CDB840C5AFC7200A666C74E4252A73F63544D3EF9EA86B3536494A15A1BE4B",
                "sha512Fingerprint": "31637AE207EA7E2B980F365C909FB3852ADB1327578DD45053D18BCC9335A7ACAB2EB394113AD97CE09CFBDBC04E5F4C4857C9598692569821DE455720CDF88E",
                "state": "active",
                "subject": "/CN=EXAMPLE2.COM",
                "updatedAt": "2024-06-18T06:00:07.361309Z",
                "uri": "kylo:kylo:naboo:localca:f96e3d3b-6962-4abe-938b-3920134a4a3d"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-22T12:58:54.931549Z",
                "id": "ffbc87ae-ea21-4e61-969c-33d92380a98e",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "name": "maya-CA-3",
                "notAfter": "2025-06-16T12:25:36Z",
                "notBefore": "2024-06-15T12:25:36Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "105363437016056150033773930926775683497",
                "sha1Fingerprint": "DC2A4727BCE5962BEC6F19876F0C43FB9C37FDC6",
                "sha256Fingerprint": "8431E9CC7A2E59B9DFC5AF2A1CEC4F33EA03CCEA26AD80AEBD0FF2C1734FFF47",
                "sha512Fingerprint": "30EE947453429FFBEFFFB99330BF54FCB651349F71300FFC993B0C14194DC3F93EAF739211FBE6E545F131A712FD64D901360DEBA94CB362B573E99A8971CA43",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com",
                "updatedAt": "2024-06-18T06:00:07.350742Z",
                "uri": "kylo:kylo:naboo:localca:ffbc87ae-ea21-4e61-969c-33d92380a98e"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-05-29T12:23:05.785313Z",
                "id": "33a9019f-f74c-46e8-a10e-f059f88ad075",
                "issuer": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com",
                "name": "localca-33a9019f-f74c-46e8-a10e-f059f88ad075",
                "notAfter": "2025-06-16T12:25:34Z",
                "notBefore": "2024-06-15T12:25:34Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "163370278336848373402205300555971853006",
                "sha1Fingerprint": "C5A99A969CA59898BD611E792B3959F0F25330D3",
                "sha256Fingerprint": "B444EEEE151EFA6657C4C2EAF6D0F9A3219198F87CFC5B7986FCE2CFAD413BDA",
                "sha512Fingerprint": "D8E76176164A6ABDEACF279678EF17018CC6AA877DCDE452D576DD77BBB22AC947B667FBAEBCFA52830374568DC8811A13F27E2728519112E4662C94364537DC",
                "state": "active",
                "subject": "/C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com",
                "updatedAt": "2024-06-18T06:00:07.328795Z",
                "uri": "kylo:kylo:naboo:localca:33a9019f-f74c-46e8-a10e-f059f88ad075"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:25:15.343697Z",
                "id": "e7d753e6-fb93-472a-a8c4-9ecf6ebf552b",
                "issuer": "/CN=test_playbook",
                "name": "localca-e7d753e6-fb93-472a-a8c4-9ecf6ebf552b",
                "notAfter": "2025-06-16T12:25:37Z",
                "notBefore": "2024-06-15T12:25:37Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "203497812975623845742505533309745775331",
                "sha1Fingerprint": "5A7FAB18EB8FBE4B7B6248A26589E5F66DC45E72",
                "sha256Fingerprint": "3767F155D8C83BE7C484791097BB85A9CAE1777674C1A7017C3A88E14B502389",
                "sha512Fingerprint": "15E9BA165BAD2DFD1567736772B71EF5DDA38D2B197CB64EE16E616D4C89C8E3A12F7C25224BF934D02DF790B0F8DC64D539D5CDCB39009C54083D4C8AE0E782",
                "state": "active",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-18T06:00:07.304657Z",
                "uri": "kylo:kylo:naboo:localca:e7d753e6-fb93-472a-a8c4-9ecf6ebf552b"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-13T12:31:44.246059Z",
                "id": "2ab5aea7-5f69-4152-b871-6996bc427702",
                "issuer": "/CN=ui_test",
                "name": "localca-2ab5aea7-5f69-4152-b871-6996bc427702",
                "notAfter": "2025-06-13T16:20:50Z",
                "notBefore": "2024-06-13T16:20:50Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "22416116914186521030446027138329400040",
                "sha1Fingerprint": "999F0159EB3ADB9E2C2591BE19DF0964075ECB77",
                "sha256Fingerprint": "17E54883786AD97D5BFD962F39B9A5CA254E34CAE6012541D606808E4CCA76A0",
                "sha512Fingerprint": "BD052596815129BD78732ADF87265A64534A553F8AFBBAD19EF908FDD68373475D74DD159A112D4AF9DB7E5730064BF23BECDB33DBEE53FBD220F095B8ECF66F",
                "state": "active",
                "subject": "/CN=ui_test",
                "updatedAt": "2024-06-18T06:00:07.288485Z",
                "uri": "kylo:kylo:naboo:localca:2ab5aea7-5f69-4152-b871-6996bc427702"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-04T12:17:18.034595Z",
                "id": "3bfed997-da49-48b6-855f-b63a50398731",
                "issuer": "/CN=test_file_csr",
                "name": "localca-3bfed997-da49-48b6-855f-b63a50398731",
                "notAfter": "2025-06-16T12:25:32Z",
                "notBefore": "2024-06-15T12:25:32Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "61805608119136879200923975865797022045",
                "sha1Fingerprint": "4BB883746FED67A77E127C707C80B3F77AE3C64F",
                "sha256Fingerprint": "16DB54A9709FD856AE209EC3486DE5AA27F539D1867DA6C71437AC728537DC16",
                "sha512Fingerprint": "B9DD42BE30B37DBF1D1015CE063D777A0A4D1DD7FFCAA78303A8875CEC02DCEE6AE1E8FFDF85814A9566015C17CA2641421720DE7475FC3C4FFC1A84F5CDB96F",
                "state": "active",
                "subject": "/CN=test_file_csr",
                "updatedAt": "2024-06-18T06:00:07.259932Z",
                "uri": "kylo:kylo:naboo:localca:3bfed997-da49-48b6-855f-b63a50398731"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T10:39:15.21527Z",
                "id": "ac1407ea-5929-481f-804a-50031efc4e48",
                "issuer": "/CN=test_ui_2",
                "name": "localca-ac1407ea-5929-481f-804a-50031efc4e48",
                "notAfter": "2025-06-16T12:25:29Z",
                "notBefore": "2024-06-15T12:25:29Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "214676143757307299652298316136105097078",
                "sha1Fingerprint": "1333A6CFFAA319F3325548315FB0699D1A267C10",
                "sha256Fingerprint": "D064521B7E772D7A224930A6251783B23D108F8578B39D54D38EF7CF9744286F",
                "sha512Fingerprint": "532B4B3E9368F8BD87238113B2E4647A6C1CB672AC08F63CF0D40AD7BF8D630D5C44FF8AC903419F07ADECF3B576CDA3801FC720DEE092B91A0334F3D7EFEE92",
                "state": "active",
                "subject": "/CN=test_ui_2",
                "updatedAt": "2024-06-18T06:00:07.24467Z",
                "uri": "kylo:kylo:naboo:localca:ac1407ea-5929-481f-804a-50031efc4e48"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-13T16:29:06.628728Z",
                "id": "36c36025-2eb8-428b-bbcb-de5eb91b363f",
                "issuer": "/CN=demo_prep_example.com",
                "name": "localca-36c36025-2eb8-428b-bbcb-de5eb91b363f",
                "notAfter": "2025-06-16T12:25:32Z",
                "notBefore": "2024-06-15T12:25:32Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "297192342979904258733709782583904105532",
                "sha1Fingerprint": "2E73FA0002399B64022873F50F06F1803D229F4C",
                "sha256Fingerprint": "FA7FC416B6224D851F68DF5E812616A252F96B3C63C5B422493810DFD27BB707",
                "sha512Fingerprint": "4D8712E9E8682E3B56484C05F0E8B36B31FBC5CEF961D219B1DFAB68B2CBB8A38ECD091B8562147743953B5AEC2410BF794DA9289D0EDABED227938A1E262421",
                "state": "active",
                "subject": "/CN=demo_prep_example.com",
                "updatedAt": "2024-06-18T06:00:07.207647Z",
                "uri": "kylo:kylo:naboo:localca:36c36025-2eb8-428b-bbcb-de5eb91b363f"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:56:25.067985Z",
                "id": "f39a4d50-7024-49e1-8e43-d56827a0394f",
                "name": "localca-f39a4d50-7024-49e1-8e43-d56827a0394f",
                "notAfter": "0001-01-01T00:00:00Z",
                "notBefore": "0001-01-01T00:00:00Z",
                "sha1Fingerprint": "811DD053B0953D8F3CB271BDFB9242B1BE85740A",
                "sha256Fingerprint": "10B00543ECDD7E4938034EFACE8067B321E1335F202ED87F73ADE1F11CF02A82",
                "sha512Fingerprint": "9458EC698F7A8EAFC0D176CB94BBF706B1E259F1DB431B15469E77D05B418C55DE2212C04D486F4C8D434F642403DA6F3C622FE651ECECA69146B0F3C2CAA84F",
                "state": "pending",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-16T12:56:25.067985Z",
                "uri": "kylo:kylo:naboo:localca:f39a4d50-7024-49e1-8e43-d56827a0394f"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:42:08.093418Z",
                "id": "0d17f8f8-124d-46ed-acb9-2484269f8715",
                "name": "localca-0d17f8f8-124d-46ed-acb9-2484269f8715",
                "notAfter": "0001-01-01T00:00:00Z",
                "notBefore": "0001-01-01T00:00:00Z",
                "sha1Fingerprint": "E42A69710FDC0103576A21A1DC4A25047C845297",
                "sha256Fingerprint": "58BBAB336BEAD91938CC0237E990B3716F7C51CFD827D843A24B5045B5207635",
                "sha512Fingerprint": "FC364B5C46EE1BF1FB8542B212B9473AAD6B87AD626162512A0067A54E44A982C66F8F52D27F23F9EC4CD685B574F6C07440940C8B5ECE3BF87A776891DEED37",
                "state": "pending",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-16T12:42:08.093418Z",
                "uri": "kylo:kylo:naboo:localca:0d17f8f8-124d-46ed-acb9-2484269f8715"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:41:01.705733Z",
                "id": "af7c04ad-4cfc-4195-bf6a-83deb52456e7",
                "name": "localca-af7c04ad-4cfc-4195-bf6a-83deb52456e7",
                "notAfter": "0001-01-01T00:00:00Z",
                "notBefore": "0001-01-01T00:00:00Z",
                "sha1Fingerprint": "5BB41C4639A33BE12190D106658C6A8BF8676112",
                "sha256Fingerprint": "1920B69E8C7C49D0054A27546E7D126E8EECC26857C41D2CE6539C4C8BE98830",
                "sha512Fingerprint": "15FB0D6A9213DC749D4D9C118041512D27C73696134C3828A7DD2FFCB31003878E57A740F548394D1FBCF0C6683E762EEE699E1CA6F0C2BFCBD82B2091F814DE",
                "state": "pending",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-16T12:41:01.705733Z",
                "uri": "kylo:kylo:naboo:localca:af7c04ad-4cfc-4195-bf6a-83deb52456e7"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:40:16.44403Z",
                "id": "2789da9f-0049-407b-83f5-0632801f27b3",
                "name": "localca-2789da9f-0049-407b-83f5-0632801f27b3",
                "notAfter": "0001-01-01T00:00:00Z",
                "notBefore": "0001-01-01T00:00:00Z",
                "sha1Fingerprint": "CF6DDE0BF02170E24074079C3EAFEF306B301514",
                "sha256Fingerprint": "4C06EF2672A7DCA2D0AC7627C8C5B0C50039783793C0DE162418C8F07101B0DB",
                "sha512Fingerprint": "672629ABCF59E292CB29E84C496922F889F079C19584BBDFE68241CE91207802708D0FA2559C663C1AB4DEF99D9823DF377319C673BB5B37DFE29585122D2EE8",
                "state": "pending",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-16T12:40:16.44403Z",
                "uri": "kylo:kylo:naboo:localca:2789da9f-0049-407b-83f5-0632801f27b3"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:39:40.629812Z",
                "id": "14f64185-4520-457d-9549-2a0fe2dba1f9",
                "name": "localca-14f64185-4520-457d-9549-2a0fe2dba1f9",
                "notAfter": "0001-01-01T00:00:00Z",
                "notBefore": "0001-01-01T00:00:00Z",
                "sha1Fingerprint": "ECD32C72CD1DCDB00CB0A4C5A0C724839E25921F",
                "sha256Fingerprint": "6726EAA9A423BF9CB1EA59AB507980D2E9E8B5CD7144DA7180602AE8501EA47A",
                "sha512Fingerprint": "1F822BBD11D364729F8DA4A9B32D8369ED2B47490DAE251EAAA0EDACF5421748E5F495428A352F3DBD12843C0534C2D0FED2099E751789B1BD01448EFED6A857",
                "state": "pending",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-16T12:39:40.629812Z",
                "uri": "kylo:kylo:naboo:localca:14f64185-4520-457d-9549-2a0fe2dba1f9"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:31:23.970317Z",
                "id": "9a728681-f77c-43b6-8bd7-dcf99d923d91",
                "name": "localca-9a728681-f77c-43b6-8bd7-dcf99d923d91",
                "notAfter": "0001-01-01T00:00:00Z",
                "notBefore": "0001-01-01T00:00:00Z",
                "sha1Fingerprint": "C9F4DE824A0A36F8697B40A1788B59458ACA047C",
                "sha256Fingerprint": "96BD5594D015ED09F36D6D4D5EE21BD60D64C806FB4A8D14E434FBBE31A254D4",
                "sha512Fingerprint": "97FF1BF5ADD513F679767E1BA54E59FF1E02C7F695566A2B0B73B9E09227BEFC927B544C8F271AD074A414E9AB22D15743AD972374862F0C9ECC4B0096111B27",
                "state": "pending",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-16T12:31:31.573914Z",
                "uri": "kylo:kylo:naboo:localca:9a728681-f77c-43b6-8bd7-dcf99d923d91"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:28:28.390764Z",
                "id": "13c0a0d7-f1ca-4e35-892f-2d0d73154796",
                "name": "localca-13c0a0d7-f1ca-4e35-892f-2d0d73154796",
                "notAfter": "0001-01-01T00:00:00Z",
                "notBefore": "0001-01-01T00:00:00Z",
                "sha1Fingerprint": "92B69050ED571F21438AA7960F9805FCB717BBD0",
                "sha256Fingerprint": "1E751E050E62BA5AEC1A49D42F3D4001C01900318E659ACE1B7E9A60FF90AEB7",
                "sha512Fingerprint": "981B5C46C05762B2D926F24160AEEB54D6C6BD3EB0EF0A19988896CCAF03BC544765534C9F8F737DB25BC0A04251CC1E9B535C93696E73686E6B10E9D8285EFF",
                "state": "pending",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-16T12:31:30.770354Z",
                "uri": "kylo:kylo:naboo:localca:13c0a0d7-f1ca-4e35-892f-2d0d73154796"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-13T14:07:38.369838Z",
                "id": "3f953b5c-f432-4e6f-8b9e-bba0e4f2ec95",
                "issuer": "/CN=test_ui_2",
                "name": "localca-3f953b5c-f432-4e6f-8b9e-bba0e4f2ec95",
                "notAfter": "2024-06-14T14:33:56Z",
                "notBefore": "2024-06-13T14:33:56Z",
                "purpose": {
                    "client_authentication": "Enabled",
                    "user_authentication": "Enabled"
                },
                "serialNumber": "80494301545733687516727664878997013754",
                "sha1Fingerprint": "0A63239115356D9F28CBC20EE21D44B088FBB0D5",
                "sha256Fingerprint": "F8D70C51EFEE50253A2726976FE5797E41BD4B16419C6195F95C1B463F6088DD",
                "sha512Fingerprint": "75B8626F077F97838FA8FAF095E0EB80A101796AB1A59D17AF9EBB25918E578489784C26CCBE1D8A2441F293E4CDB518E1E17397A391B203105E6AFFE9D7A3C0",
                "state": "expired",
                "subject": "/CN=test_ui_2",
                "updatedAt": "2024-06-16T12:31:27.004095Z",
                "uri": "kylo:kylo:naboo:localca:3f953b5c-f432-4e6f-8b9e-bba0e4f2ec95"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:30:05.688794Z",
                "id": "f68f05cd-71e9-4c72-b00c-663cb095a56c",
                "name": "localca-f68f05cd-71e9-4c72-b00c-663cb095a56c",
                "notAfter": "0001-01-01T00:00:00Z",
                "notBefore": "0001-01-01T00:00:00Z",
                "sha1Fingerprint": "23AFC84598A390986DB9F57AE41268C56D18A38A",
                "sha256Fingerprint": "382FB2F8E285F141DDD49473B669C46D3C98A24609375D88C986E0410318DAD4",
                "sha512Fingerprint": "AC2EF409B196D036D832C3616C542DBC1E52D47144776AB78427DBF217D2B70C87E25633C21CA7CABF2DA08A8341A9570954AD494944F572EF66DCD50691B1E1",
                "state": "pending",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-16T12:31:25.956826Z",
                "uri": "kylo:kylo:naboo:localca:f68f05cd-71e9-4c72-b00c-663cb095a56c"
            },
            {
                "account": "kylo:kylo:admin:accounts:kylo",
                "createdAt": "2024-06-16T12:30:33.738148Z",
                "id": "89efc91b-56c2-4575-8d4a-a7497f552889",
                "name": "localca-89efc91b-56c2-4575-8d4a-a7497f552889",
                "notAfter": "0001-01-01T00:00:00Z",
                "notBefore": "0001-01-01T00:00:00Z",
                "sha1Fingerprint": "2AD5DC3F6E1FE4878D37A546EA1826B28C433EAC",
                "sha256Fingerprint": "F5DF3AFF32F86DA33C3CC779E5353763372BB6491119A8E1D33268369B3C2C04",
                "sha512Fingerprint": "CB0E58F33BE454DFCC0AAED47DB0ABAF17ADDD0F9071D30B960CD9587195641B330AB990F10AC66B58ACF2577880CB1D93E9DE52916B3885E1FCD0CE6DD195E9",
                "state": "pending",
                "subject": "/CN=test_playbook",
                "updatedAt": "2024-06-16T12:31:25.948765Z",
                "uri": "kylo:kylo:naboo:localca:89efc91b-56c2-4575-8d4a-a7497f552889"
            }
        ]
    }
}
```

#### Human Readable Output

>### Local Certificate Authorities 

>### Active CAs

>|Name|Subject|Serial #|Activation|Expiration|Client Auth|User Auth|
>|---|---|---|---|---|---|---|
>| example_local_ca | /C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com | 158212075602881140442360379812918138547 | 29 May 2024, 00:00 | 18 Jun 2027, 09:16 | Enabled | Enabled |
>| localca-3dc1f629-23b6-4cce-876a-c7d07a4862cd | /CN=demo_prep_example.com | 129102809746806914708740056180976394480 | 01 Jun 2024, 13:58 | 02 Jun 2025, 13:58 | Enabled | Enabled |
>| test_local_ca | /C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com | 226220228835411560013591369440322067707 | 03 Jun 2024, 14:10 | 04 Jun 2025, 14:10 | Enabled | Enabled |
>| test | /CN=test-for-list | 72278925304596589280809592640662340361 | 03 Jun 2024, 14:09 | 04 Jun 2025, 14:09 | Enabled | Enabled |
>| localca-f443d295-875a-4697-baf6-d02c17f23d78 | /CN=test-create-local-ca | 180344290974933345373617443253119448463 | 04 Jun 2024, 14:18 | 05 Jun 2025, 14:18 | Enabled | Enabled |
>| local_ca_to_self_sign | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com | 337185028007684692646558478315771697994 | 29 May 2024, 00:00 | 30 May 2027, 10:01 | Enabled | Enabled |
>| localca-0fb05898-6817-4d29-a47f-59820e437a22 | /CN=test_file_csr | 118269231003356260767200023246958364211 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| local-ca-install-id | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com | 28062530453531757191324395315743257082 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| maya-CA-2 | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com | 128976853845189850850256632563440174889 | 20 May 2024, 13:20 | 02 Oct 2026, 14:18 | Enabled | Enabled |
>| localca-f1d8f086-ae3a-4c95-a879-20d8095dc951 | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com | 329109383730933252345740275059611042991 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-30ac1fb0-1c3d-4d73-9a23-83e48c8860d7 | /CN=test.com | 65114707427365325108519135462150843996 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-ceacaf33-6572-4bfa-84f2-60ff94d5e007 | /CN=test.com | 32761860285466905109737610122636607959 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-8e4a12e3-b7f7-4a96-adc5-6fecbfdf9df5 | /CN=test.com | 133607681255884779182134929191905670600 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| isempty1? | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo2.com | 163510084562999310649486415171752198390 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| isempty? | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo2.com | 135850894135202628853705544520531120469 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| test1 | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com | 178903473729619830181379965311891574804 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-&lt;id&gt;| /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com | 225686445354134570260952387642633959405 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-b765018b-0a64-419f-b537-c30863aa4002 | /C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA | 24463087808077808513660017390325960995 | 13 Feb 2024, 10:08 | 11 Feb 2034, 10:08 | Enabled | Enabled |
>| sarah-2-CA | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/CN=kylo.com | 297957266980521970680269241879076856098 | 01 May 2024, 10:05 | 01 May 2025, 10:05 | Enabled | Enabled |
>| maya-CA | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com | 139248642490513216788901886347651629296 | 20 May 2024, 12:54 | 16 May 2025, 12:54 | Enabled | Enabled |
>| sarah-CA | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/CN=kylo.com | 236129256119494718420321950585891385888 | 30 Apr 2024, 09:29 | 02 Oct 2025, 14:18 | Enabled | Enabled |
>| localca-ded8d992-c884-4f98-ad4f-68264b263e09 | /CN=test.com | 192835835797178633282551614520727069145 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-2f0c4e7f-b388-427b-a9b3-532e3f330561 | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com | 190170845302674761124094601994094514926 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-2630504e-ab3f-4b85-b176-319c18a8b014 | /CN=test_file_csr2 | 39968239672548719518544113345523146127 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-5628ca09-01e7-4a4e-bc72-7259a5e7c70e | /CN=test_playbook | 4568441388696325044749525549789309664 | 15 Jun 2024, 12:27 | 16 Jun 2025, 12:27 | Enabled | Enabled |
>| maya-CA-4 | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com | 103684251574198102057496728651123185286 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-eff61372-2db0-44cd-bbbd-2563393c55d8 | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com | 225201555731716426434835627487751507394 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| isempty2? | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo2.com | 213214243161581230018528102469896633667 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| test2 | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com | 43170575982063033673607674252675234514 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| local-ca-install-parent-id | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com | 85223021320069691669631123788141870709 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-f96e3d3b-6962-4abe-938b-3920134a4a3d | /CN=EXAMPLE2.COM | 199509253732682618926504109082709033771 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| maya-CA-3 | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=kylo.com | 105363437016056150033773930926775683497 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-33a9019f-f74c-46e8-a10e-f059f88ad075 | /C=US/ST=MD/L=Belcamp/O=Thales/OU=RnD/OU=Thales Group Inc./CN=test.com | 163370278336848373402205300555971853006 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-e7d753e6-fb93-472a-a8c4-9ecf6ebf552b | /CN=test_playbook | 203497812975623845742505533309745775331 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-2ab5aea7-5f69-4152-b871-6996bc427702 | /CN=ui_test | 22416116914186521030446027138329400040 | 13 Jun 2024, 16:20 | 13 Jun 2025, 16:20 | Enabled | Enabled |
>| localca-3bfed997-da49-48b6-855f-b63a50398731 | /CN=test_file_csr | 61805608119136879200923975865797022045 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-ac1407ea-5929-481f-804a-50031efc4e48 | /CN=test_ui_2 | 214676143757307299652298316136105097078 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>| localca-36c36025-2eb8-428b-bbcb-de5eb91b363f | /CN=demo_prep_example.com | 297192342979904258733709782583904105532 | 15 Jun 2024, 12:25 | 16 Jun 2025, 12:25 | Enabled | Enabled |
>
>### Pending CAs

>|Name|Subject|Created|Fingerprint|
>|---|---|---|---|
>| localca-f39a4d50-7024-49e1-8e43-d56827a0394f | /CN=test_playbook | 16 Jun 2024, 12:56 | 811DD053B0953D8F3CB271BDFB9242B1BE85740A |
>| localca-0d17f8f8-124d-46ed-acb9-2484269f8715 | /CN=test_playbook | 16 Jun 2024, 12:42 | E42A69710FDC0103576A21A1DC4A25047C845297 |
>| localca-af7c04ad-4cfc-4195-bf6a-83deb52456e7 | /CN=test_playbook | 16 Jun 2024, 12:41 | 5BB41C4639A33BE12190D106658C6A8BF8676112 |
>| localca-2789da9f-0049-407b-83f5-0632801f27b3 | /CN=test_playbook | 16 Jun 2024, 12:40 | CF6DDE0BF02170E24074079C3EAFEF306B301514 |
>| localca-14f64185-4520-457d-9549-2a0fe2dba1f9 | /CN=test_playbook | 16 Jun 2024, 12:39 | ECD32C72CD1DCDB00CB0A4C5A0C724839E25921F |
>| localca-9a728681-f77c-43b6-8bd7-dcf99d923d91 | /CN=test_playbook | 16 Jun 2024, 12:31 | C9F4DE824A0A36F8697B40A1788B59458ACA047C |
>| localca-13c0a0d7-f1ca-4e35-892f-2d0d73154796 | /CN=test_playbook | 16 Jun 2024, 12:28 | 92B69050ED571F21438AA7960F9805FCB717BBD0 |
>| localca-f68f05cd-71e9-4c72-b00c-663cb095a56c | /CN=test_playbook | 16 Jun 2024, 12:30 | 23AFC84598A390986DB9F57AE41268C56D18A38A |
>| localca-89efc91b-56c2-4575-8d4a-a7497f552889 | /CN=test_playbook | 16 Jun 2024, 12:30 | 2AD5DC3F6E1FE4878D37A546EA1826B28C433EAC |
>
>### Expired CAs

>|Name|Subject|Created|Fingerprint|
>|---|---|---|---|
>| localca-3f953b5c-f432-4e6f-8b9e-bba0e4f2ec95 | /CN=test_ui_2 | 13 Jun 2024, 14:07 | 0A63239115356D9F28CBC20EE21D44B088FBB0D5 |
>
>1 to 48 of 48 Local CAs

### ciphertrust-local-ca-self-sign

***
Self-sign a local CA certificate. This is used to create a root CA. Either duration or notAfter date must be specified. If both notAfter and duration are given, then notAfter date takes precedence over duration. If duration is given without notBefore date, certificate is issued starting from server's current time for the specified duration.

#### Base Command

`ciphertrust-local-ca-self-sign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| local_ca_id | An identifier of the resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Required | 
| duration | The duration of the certificate in days. Either not_after date or duration must be specified. not_after overrides duration if both are given. Default is 365. | Optional | 
| not_after | End date of the certificate. Either not_after date or duration must be specified. not_after overrides duration if both are given. | Optional | 
| not_before | Start date of the certificate. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.CASelfSign.id | String | A unique identifier for the certificate authority \(CA\). | 
| CipherTrust.CASelfSign.uri | String | Uniform Resource Identifier associated with the CA. | 
| CipherTrust.CASelfSign.account | String | Account associated with the CA. | 
| CipherTrust.CASelfSign.application | String | Application associated with the CA. | 
| CipherTrust.CASelfSign.devAccount | String | Developer account associated with the CA. | 
| CipherTrust.CASelfSign.name | String | Name of the CA. | 
| CipherTrust.CASelfSign.state | String | Current state of the CA \(e.g., pending, active\). | 
| CipherTrust.CASelfSign.createdAt | Date | Timestamp of when the CA was created. | 
| CipherTrust.CASelfSign.updatedAt | Date | Timestamp of the last update of the CA. | 
| CipherTrust.CASelfSign.serialNumber | String | Serial number of the CA's certificate. | 
| CipherTrust.CASelfSign.subject | String | Subject of the CA's certificate. | 
| CipherTrust.CASelfSign.issuer | String | Issuer of the CA's certificate. | 
| CipherTrust.CASelfSign.notBefore | Date | Start date of the CA's certificate validity. | 
| CipherTrust.CASelfSign.notAfter | Date | End date of the CA's certificate validity. | 
| CipherTrust.CASelfSign.sha1Fingerprint | String | SHA1 fingerprint of the CA's certificate. | 
| CipherTrust.CASelfSign.sha256Fingerprint | String | SHA256 fingerprint of the CA's certificate. | 
| CipherTrust.CASelfSign.sha512Fingerprint | String | SHA512 fingerprint of the CA's certificate. | 
| CipherTrust.CASelfSign.purpose.client_authentication | String | Indicates if client authentication is enabled for the CA. | 
| CipherTrust.CASelfSign.purpose.user_authentication | String | Indicates if user authentication is enabled for the CA. | 

#### Command example

```!ciphertrust-local-ca-self-sign local_ca_id="example_local_ca" not_after="in three years" not_before="29.5.24"```

#### Context Example

```json
{
    "CipherTrust": {
        "CASelfSign": {
            "account": "kylo:kylo:admin:accounts:kylo",
            "createdAt": "2024-06-18T09:16:46.346715Z",
            "id": "b6d991fd-9f15-4412-b6e1-84d1e7620fa6",
            "issuer": "/C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com",
            "name": "example_local_ca",
            "notAfter": "2027-06-18T09:16:51Z",
            "notBefore": "2024-05-29T00:00:00Z",
            "purpose": {
                "client_authentication": "Enabled",
                "user_authentication": "Enabled"
            },
            "serialNumber": "158212075602881140442360379812918138547",
            "sha1Fingerprint": "A1AE2F3379AB18EEEC97BD43CC3E4BF4379482A4",
            "sha256Fingerprint": "64CE213A62F3135FE74E7CC6D514DCCDBB2638F222B9E846D0C6C3F8381BE088",
            "sha512Fingerprint": "84AE8CD3B6B0C214BAC03BFDE1AD2FE0054D32B6CF7CAF6738958CD07D781409EA01B444DDBBCD28F2F52D79393169840FD87C7967815842A6AC0A624F86543F",
            "state": "active",
            "subject": "/C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com",
            "updatedAt": "2024-06-18T09:16:50.237218111Z",
            "uri": "kylo:kylo:naboo:localca:b6d991fd-9f15-4412-b6e1-84d1e7620fa6"
        }
    },
    "InfoFile": {
        "EntryID": "2116@a48e3cfd-a079-4895-89a7-4fac11b8143d",
        "Extension": "pem",
        "Info": "application/x-x509-ca-cert",
        "Name": "Certificate.pem",
        "Size": 1533,
        "Type": "PEM certificate"
    }
}
```

#### Human Readable Output

>example_local_ca has been self-signed successfully!

### ciphertrust-local-ca-update

***
Update a local CA.

#### Base Command

`ciphertrust-local-ca-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| local_ca_id | An identifier of the resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Required | 
| allow_client_authentication | If set to true, the certificates signed by the specified CA can be used for client authentication. Possible values are: true, false. | Optional | 
| allow_user_authentication | If set to true, the certificates signed by the specified CA can be used for user authentication. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | string | File name. | 
| InfoFile.EntryID | string | The entry ID of the report | 
| InfoFile.Size | number | File size. | 
| InfoFile.Type | string | File type, e.g., "PE". | 
| InfoFile.Info | string | Basic information of the file. | 
| InfoFile.Extension | string | File extension. | 
| CipherTrust.LocalCA.id | String | A unique identifier for the certificate authority \(CA\). | 
| CipherTrust.LocalCA.uri | String | Uniform Resource Identifier associated with the CA. | 
| CipherTrust.LocalCA.account | String | Account associated with the CA. | 
| CipherTrust.LocalCA.name | String | Name of the CA. | 
| CipherTrust.LocalCA.state | String | Current state of the CA \(e.g., pending, active\). | 
| CipherTrust.LocalCA.createdAt | Date | Timestamp of when the CA was created. | 
| CipherTrust.LocalCA.updatedAt | Date | Timestamp of the last update of the CA. | 
| CipherTrust.LocalCA.serialNumber | String | Serial number of the CA's certificate. | 
| CipherTrust.LocalCA.subject | String | Subject of the CA's certificate. | 
| CipherTrust.LocalCA.issuer | String | Issuer of the CA's certificate. | 
| CipherTrust.LocalCA.notBefore | Date | Start date of the CA's certificate validity. | 
| CipherTrust.LocalCA.notAfter | Date | End date of the CA's certificate validity. | 
| CipherTrust.LocalCA.sha1Fingerprint | String | SHA1 fingerprint of the CA's certificate. | 
| CipherTrust.LocalCA.sha256Fingerprint | String | SHA256 fingerprint of the CA's certificate. | 
| CipherTrust.LocalCA.sha512Fingerprint | String | SHA512 fingerprint of the CA's certificate. | 
| CipherTrust.LocalCA.purpose.client_authentication | String | Indicates if client authentication is enabled for the CA. | 
| CipherTrust.LocalCA.purpose.user_authentication | String | Indicates if user authentication is enabled for the CA. | 

#### Command example

```!ciphertrust-local-ca-update local_ca_id="example_local_ca" allow_client_authentication=true allow_user_authentication=true```

#### Context Example

```json
{
    "CipherTrust": {
        "LocalCA": {
            "account": "kylo:kylo:admin:accounts:kylo",
            "createdAt": "2024-06-18T09:16:46.346715Z",
            "id": "b6d991fd-9f15-4412-b6e1-84d1e7620fa6",
            "issuer": "/C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com",
            "name": "example_local_ca",
            "notAfter": "2027-06-18T09:16:51Z",
            "notBefore": "2024-05-29T00:00:00Z",
            "purpose": {
                "client_authentication": "Enabled",
                "user_authentication": "Enabled"
            },
            "serialNumber": "158212075602881140442360379812918138547",
            "sha1Fingerprint": "A1AE2F3379AB18EEEC97BD43CC3E4BF4379482A4",
            "sha256Fingerprint": "64CE213A62F3135FE74E7CC6D514DCCDBB2638F222B9E846D0C6C3F8381BE088",
            "sha512Fingerprint": "84AE8CD3B6B0C214BAC03BFDE1AD2FE0054D32B6CF7CAF6738958CD07D781409EA01B444DDBBCD28F2F52D79393169840FD87C7967815842A6AC0A624F86543F",
            "state": "active",
            "subject": "/C=US/ST=CA/L=FakeCity/O=FakeCompany/OU=RnD/OU=Fake Group Inc./CN=test.com",
            "updatedAt": "2024-06-18T09:16:53.961877601Z",
            "uri": "kylo:kylo:naboo:localca:b6d991fd-9f15-4412-b6e1-84d1e7620fa6"
        }
    },
    "InfoFile": {
        "EntryID": "2121@a48e3cfd-a079-4895-89a7-4fac11b8143d",
        "Extension": "pem",
        "Info": "application/x-x509-ca-cert",
        "Name": "Certificate.pem",
        "Size": 1533,
        "Type": "PEM certificate"
    }
}
```

#### Human Readable Output

>example_local_ca has been updated successfully!

### ciphertrust-local-certificate-delete

***
Deletes a local certificate.

#### Base Command

`ciphertrust-local-certificate-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ca_id | An identifier of the issuer CA resource. This can be either the ID (a UUIDv4), the name, the URI, or the slug (which is the last component of the URI). | Required | 
| local_ca_id | An identifier of the certificate resource.This can be either the ID (a UUIDv4), the URI, or the slug (which is the last component of the URI). | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!ciphertrust-local-certificate-delete ca_id="localca-3dc1f629-23b6-4cce-876a-c7d07a4862cd" local_ca_id="0fb15f00-722c-412e-a1e8-6eb6130e87ba"```

#### Human Readable Output

>0fb15f00-722c-412e-a1e8-6eb6130e87ba has been deleted successfully!

### ciphertrust-user-create

***
Create a new user in a domain (including root), or add an existing domain user to a sub-domain. Users are always created in the local, internal user database, but might have references to external identity providers.
The connection property is optional. If this property is specified when creating new users, it can be the name of a connection or local_account for a local user.
The connection property is only used in the body of the create-user request. It is not present in either request or response bodies of the other user endpoints.
To create a user - username is mandatory. And password is required in most cases except when certificate authentication is used and certificate subject dn is provided.
To enable certificate based authentication for a user, it is required to set certificate_subject_dn and add "user_certificate" authentication method in allowed_auth_methods. This functionality is available only for local users.
To assign a root domain user to a sub-domain - the users are added to the domain of the user who is logging in, and the connection property should be left empty. The user_id or username fields are the only ones that are used while adding existing users to sub-domains; all other fields are ignored.
To enable the two-factor authentication based on username-password and user certificate for a user, it is required to set "certificate_subject_dn" and add "password_with_user_certificate" authentication method in "allowed_auth_methods". For authentication, the user will require both username-password and user certificate. This functionality applies only to local users.

#### Base Command

`ciphertrust-user-create`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| name | Full name of the user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Optional | 
| user_id | The ID of an existing root domain user. This field is used only when adding an existing root domain user to a different domain.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Optional | 
| username | The login name of the user. This attribute is required to create a user, but is omitted when getting or listing a user. It cannot be updated. This attribute may also be used (instead of the user_id) when adding an existing root domain user to a different domain.                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Optional | 
| password | The password used to secure the users account. Allowed passwords are defined by the password policy. Password is optional when "certificate_subject_dn" is set and "user_certificate" is in allowed_auth_methods. In all other cases, password is required. It is not included in user resource responses. Default global password complexity requirement: minimum characters = 8, maximum characters = 30, lower-case letters = 1, upper-case letters = 1, decimal digits = 1, special characters = 1.                                                                                                                                                                                                                   | Optional | 
| email | E-mail of the user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Optional | 
| allowed_auth_methods | A comma-separated list of login authentication methods allowed to the user. Default value - "password". Password Authentication is allowed by default. Setting it to none, i.e., "none", means no authentication method is allowed to the user. If both enable_cert_auth and allowed_auth_methods are provided in the request, enable_cert_auth is ignored. Setting it to "password_with_user_certificate", means two-factor authentication is enabled for the user. The user will require both username-password and user_certificate for authentication. This property does not control login behavior for users in admin group. Possible values are: password, user_certificate, password_with_user_certificate, none. | Optional | 
| allowed_client_types | A comma-separated list of client types that can authenticate using the user's credentials. Default value - "unregistered,public,confidential" i.e., all clients can authenticate the user using user's credentials. Setting it to none, "none", authenticate the user using user's credentials. Setting it to none, "none", means no client can authenticate this user, which effectively means no one can login into this user This property does not control login behavior for users in admin group. Possible values are: unregistered, public, confidential.                                                                                                                                                          | Optional | 
| certificate_subject_dn | The Distinguished Name of the user in certificate.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Optional | 
| connection | The name of a connection or "local_account" for a local user. Default is local_account.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Optional | 
| expires_at | The expires_at field is applicable only for local user account. Only members of the 'admin' and 'User Admins' groups can add an expiration date to an existing local user account or modify the expiration date. Once the expires_at date is reached, the user account gets disabled and the user is not able to perform any actions. Setting the expires_at field to "never", removes the expiration date of the user account.                                                                                                                                                                                                                                                                                           | Optional | 
| is_domain_user | This flag can be used to create the user in a non-root domain where user management is allowed. Possible values are: true, false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional | 
| prevent_ui_login | If true, user is not allowed to login from the web UI. Possible values are: true, false. Default is false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Optional | 
| password_change_required | If set to true, the user will be required to change their password on the next successful login. Possible values are: true, false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Optional | 
| password_policy | The password policy applies only to local user accounts and overrides the global password policy. By default, the global password policy is applied to the users.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CipherTrust.Users.user_id | String | A unique identifier for API call usage. | 
| CipherTrust.Users.username | String | The login name of the user. This attribute is required to create a user, but is omitted when getting or listing user. It cannot be updated. | 
| CipherTrust.Users.connection | String | This attribute is required to create a user, but is not included in user resource responses. Can be the name of a connection or 'local_account' for a local user. Defaults to 'local_account'. | 
| CipherTrust.Users.email | String | E-mail of the user. | 
| CipherTrust.Users.name | String | Full name of the user. | 
| CipherTrust.Users.certificate_subject_dn | String | The Distinguished Name of the user in certificate. | 
| CipherTrust.Users.enable_cert_auth | Boolean | Deprecated: Use allowed_auth_methods instead. Enable certificate based authentication flag. If set to true, the user will be able to login using a certificate. | 
| CipherTrust.Users.user_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences. | 
| CipherTrust.Users.app_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles. | 
| CipherTrust.Users.logins_count | Number | The number of logins. | 
| CipherTrust.Users.last_login | Date | Timestamp of the last login. | 
| CipherTrust.Users.created_at | Date | Timestamp of when user was created. | 
| CipherTrust.Users.updated_at | Date | Timestamp of last update of the user. | 
| CipherTrust.Users.allowed_auth_methods | Unknown | List of login authentication methods allowed to the user. | 
| CipherTrust.Users.expires_at | Date | The expires_at is applicable only for local user accounts. The admin or a user who is part of the admin group can add an expiration date to an existing local user account or modify the expiration date. Once the expires_at date is reached, the user account gets disabled and the user is not able to perform any actions. | 
| CipherTrust.Users.password_policy | String | The password policy applies only to local user accounts and overrides the global password policy. By default, the global password policy is applied to the users. | 
| CipherTrust.Users.allowed_client_types | Unknown | List of client types allowed to the user. | 
| CipherTrust.Users.nickname | String | Nickname of the user. | 
| CipherTrust.Users.failed_logins_count | Number | Number of failed login attempts. | 
| CipherTrust.Users.account_lockout_at | Date | Timestamp when the account was locked out. | 
| CipherTrust.Users.failed_logins_initial_attempt_at | Date | Timestamp of the initial failed login attempt. | 
| CipherTrust.Users.last_failed_login_at | Date | Timestamp of the last failed login attempt. | 
| CipherTrust.Users.password_changed_at | Date | Timestamp of when the password was last changed. | 
| CipherTrust.Users.password_change_required | Boolean | Indicates if a password change is required. | 
| CipherTrust.Users.auth_domain | String | Authentication domain of the user. | 
| CipherTrust.Users.login_flags | Unknown | Flags related to login permissions. | 

#### Command example

```!ciphertrust-user-create username="example_user" password="123ABC!123abc" allowed_auth_methods="password,user_certificate" allowed_client_types="none" certificate_subject_dn="OU=organization unit,O=organization,L=location,ST=state,C=country"```

#### Context Example

```json
{
    "CipherTrust": {
        "Users": {
            "account_lockout_at": null,
            "allowed_auth_methods": [
                "password",
                "user_certificate"
            ],
            "allowed_client_types": [],
            "auth_domain": "00000000-0000-0000-0000-000000000000",
            "certificate_subject_dn": "C=country,ST=state,L=location,O=organization,OU=organization unit",
            "created_at": "2024-06-18T09:16:19.507957Z",
            "email": "example_user@local",
            "enable_cert_auth": true,
            "failed_logins_count": 0,
            "failed_logins_initial_attempt_at": null,
            "last_failed_login_at": null,
            "last_login": null,
            "login_flags": {
                "prevent_ui_login": false
            },
            "logins_count": 0,
            "name": "example_user",
            "nickname": "example_user",
            "password_change_required": false,
            "password_changed_at": "2024-06-18T09:16:19.502063Z",
            "updated_at": "2024-06-18T09:16:19.507957Z",
            "user_id": "local|25561825-af19-46b6-ba2e-e92985568f6b",
            "username": "example_user"
        }
    }
}
```

#### Human Readable Output

>example_user has been created successfully!

### ciphertrust-user-delete

***
Deletes a user given the user's user ID. If the current user is logged into a sub-domain, the user is deleted from that sub-domain. If the current user is logged into the root domain, the user is deleted from all domains it belongs to.

#### Base Command

`ciphertrust-user-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID of the user. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!ciphertrust-user-delete user_id="local|9a1769b4-86e0-4e24-8316-ea4e7b76c23c"```

#### Human Readable Output

>local|9a1769b4-86e0-4e24-8316-ea4e7b76c23c has been deleted successfully!

### ciphertrust-user-password-change

***
Change the current user's password. Can only be used to change the password of the currently authenticated user. The user will not be able to change their password to the same password.

#### Base Command

`ciphertrust-user-password-change`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| new_password | The new password. | Required | 
| password | The user's current password. | Required | 
| username | The login name of the current user. | Required | 
| auth_domain | The domain where the user needs to be authenticated. This is the domain where the user is created. Defaults to the root domain. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!ciphertrust-user-password-change username="example_user" password="123ABC!123abc" new_password="new_123ABC!123abc"```

#### Human Readable Output

>Password has been changed successfully for example_user!

### ciphertrust-user-to-group-add

***
Add a user to a group. This command is idempotent: calls to add a user to a group in which they already belong will return an identical, OK response.

#### Base Command

`ciphertrust-user-to-group-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Name of the group. By default it will be added to the Key Users Group. Default is Key Users. | Required | 
| user_id | The user ID of the user. Can be retrieved by using the command ciphertrust-users-list. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CipherTrust.Group.name | String | The name of the group. | 
| CipherTrust.Group.created_at | Date | The time the group was created. | 
| CipherTrust.Group.updated_at | Date | The time the group was last updated. | 
| CipherTrust.Group.user_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences. | 
| CipherTrust.Group.app_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles. | 
| CipherTrust.Group.client_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. client_metadata is typically used by applications to store information about the resource, such as client preferences. | 
| CipherTrust.Group.description | String | The description of the group. | 
| CipherTrust.Group.users_count | Number | The total user count associated with the group. | 

#### Command example

```!ciphertrust-user-to-group-add group_name="example_group" user_id="local|9a1769b4-86e0-4e24-8316-ea4e7b76c23c"```

#### Context Example

```json
{
    "CipherTrust": {
        "Group": {
            "created_at": "2024-06-18T09:16:04.419126Z",
            "description": "this is a modified description",
            "name": "example_group",
            "updated_at": "2024-06-18T09:16:30.879065Z",
            "users_count": 1
        }
    }
}
```

#### Human Readable Output

>local|9a1769b4-86e0-4e24-8316-ea4e7b76c23c has been added successfully to example_group

### ciphertrust-user-to-group-remove

***
Removes a user from a group.

#### Base Command

`ciphertrust-user-to-group-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Name of the group. | Required | 
| user_id | The user ID of the user. Can be retrieved by using the command ciphertrust-users-list. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!ciphertrust-user-to-group-remove group_name="example_group" user_id="local|9a1769b4-86e0-4e24-8316-ea4e7b76c23c"```

#### Human Readable Output

>local|9a1769b4-86e0-4e24-8316-ea4e7b76c23c has been deleted successfully from example_group

### ciphertrust-user-update

***
Change the properties of a user, for instance, the name, the password, or metadata. Permissions would normally restrict this to users with admin privileges. Non admin users wishing to change their own passwords should use the ciphertrust-user-password-change command.

#### Base Command

`ciphertrust-user-update`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| name | The user's full name.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional | 
| user_id | The user ID of the user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Required | 
| username | The login name of the user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Optional | 
| password | The password used to secure the user's account.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Optional | 
| email | The email of the user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Optional | 
| password_change_required | If set to true, user will be required to change their password on next successful login. Possible values are: true, false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Optional | 
| allowed_auth_methods | List of login authentication methods allowed to the user. Setting it to none, i.e., "none", means no authentication method is allowed to the user. If both enable_cert_auth and allowed_auth_methods are provided in the request, enable_cert_auth is ignored. Setting it to "password_with_user_certificate", means two-factor authentication is enabled for the user. The user will require both username-password and user_certificate for authentication. User cannot have "password" or "user_certificate" with "password_with_user_certificate" in allowed_auth_methods. This property does not control login behavior for users in admin group. Possible values are: password, user_certificate, password_with_user_certificate, none. | Optional | 
| allowed_client_types | A comma-separated list of client types that can authenticate using the user's credentials. Setting it to none, i.e., "none", means no client can authenticate this user, which effectively means no one can login into this user. This property does not control login behavior for users in admin group. Possible values are: unregistered, public, confidential.                                                                                                                                                                                                                                                                                                                                                                            | Optional | 
| certificate_subject_dn | The Distinguished Name of the user in certificate. For example, OU=organization unit,O=organization,L=location,ST=state,C=country.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Optional | 
| expires_at | The "expires_at" field is applicable only for local user account. Only members of the 'admin' and 'User Admins' groups can add an expiration date to an existing local user account or modify the expiration date. Once the "expires_at" date is reached, the user account gets disabled and the user is not able to perform any actions. Setting the "expires_at" argument to "never", removes the expiration date of the user account.                                                                                                                                                                                                                                                                                                      | Optional | 
| failed_logins_count | Set it to 0 to unlock a locked user account.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional | 
| prevent_ui_login | If true, user is not allowed to login from the web UI. Possible values are: true, false. Default is false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Optional | 
| password_policy | The password policy applies only to local user accounts and overrides the global password policy. By default, the global password policy is applied to the users.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CipherTrust.Users.user_id | String | A unique identifier for API call usage. | 
| CipherTrust.Users.username | String | The login name of the user. This attribute is required to create a user, but is omitted when getting or listing a user. It cannot be updated. | 
| CipherTrust.Users.connection | String | This attribute is required to create a user, but is not included in user resource responses. Can be the name of a connection or 'local_account' for a local user, defaults to 'local_account'. | 
| CipherTrust.Users.email | String | E-mail of the user. | 
| CipherTrust.Users.name | String | Full name of the user. | 
| CipherTrust.Users.nickname | String | Nickname of the user. | 
| CipherTrust.Users.certificate_subject_dn | String | The Distinguished Name of the user in certificate. | 
| CipherTrust.Users.enable_cert_auth | Boolean | Deprecated: Use allowed_auth_methods instead. Enable certificate based authentication flag. If set to true, the user will be able to login using a certificate. | 
| CipherTrust.Users.user_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences. | 
| CipherTrust.Users.app_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles. | 
| CipherTrust.Users.logins_count | Number | Number of logins. | 
| CipherTrust.Users.last_login | Date | Timestamp of the last login. | 
| CipherTrust.Users.created_at | Date | Timestamp of when the user was created. | 
| CipherTrust.Users.updated_at | Date | Timestamp of the last update of the user. | 
| CipherTrust.Users.allowed_auth_methods | Unknown | List of login authentication methods allowed to the user. | 
| CipherTrust.Users.expires_at | Date | The expires_at is applicable only for local user accounts. The admin or a user who is part of the admin group can add an expiration date to an existing local user account or modify the expiration date. Once the expires_at date is reached, the user account gets disabled and the user is not able to perform any actions. | 
| CipherTrust.Users.password_policy | String | The password policy applies only to local user accounts and overrides the global password policy. By default, the global password policy is applied to the users. | 
| CipherTrust.Users.allowed_client_types | Unknown | List of client types allowed to the user. | 
| CipherTrust.Users.failed_logins_count | Number | Number of failed login attempts. | 
| CipherTrust.Users.failed_logins_initial_attempt_at | Date | Timestamp of the initial failed login attempt. | 
| CipherTrust.Users.account_lockout_at | Date | Timestamp of when the account was locked. | 
| CipherTrust.Users.last_failed_login_at | Date | Timestamp of the last failed login attempt. | 
| CipherTrust.Users.password_changed_at | Date | Timestamp of when the password was last changed. | 
| CipherTrust.Users.password_change_required | Boolean | Indicates if a password change is required at next login. | 
| CipherTrust.Users.login_flags | Unknown | Flags related to login, such as prevent_ui_login. | 

#### Command example

```!ciphertrust-user-update user_id="local|9a1769b4-86e0-4e24-8316-ea4e7b76c23c" failed_logins_count=0 expires_at="never"```

#### Context Example

```json
{
    "CipherTrust": {
        "Users": {
            "account_lockout_at": null,
            "allowed_auth_methods": [
                "password"
            ],
            "allowed_client_types": [
                "unregistered",
                "public",
                "confidential"
            ],
            "certificate_subject_dn": "",
            "created_at": "2024-06-13T07:45:25.006675Z",
            "email": "test_user@local",
            "enable_cert_auth": false,
            "failed_logins_count": 0,
            "failed_logins_initial_attempt_at": null,
            "last_failed_login_at": "2024-06-17T10:08:19.683975Z",
            "last_login": null,
            "login_flags": {
                "prevent_ui_login": false
            },
            "logins_count": 0,
            "name": "new_test_user",
            "nickname": "test_user",
            "password_change_required": false,
            "password_changed_at": "2024-06-13T07:45:24.999078Z",
            "updated_at": "2024-06-18T09:16:23.422473Z",
            "user_id": "local|9a1769b4-86e0-4e24-8316-ea4e7b76c23c",
            "username": "test_user"
        }
    }
}
```

#### Human Readable Output

>local|9a1769b4-86e0-4e24-8316-ea4e7b76c23c has been updated successfully!

### ciphertrust-users-list

***
Returns a list of users.

#### Base Command

`ciphertrust-users-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Filter by the user's name. | Optional | 
| user_id | If provided, gets the user with the specified user ID.  If the user ID 'self' is provided, it will return the current user's information. | Optional | 
| username | The user’s username. | Optional | 
| email | The user’s email. | Optional | 
| groups | A comma-separated list of group names. Using 'nil' as the group name will return users that are not part of any group. | Optional | 
| exclude_groups | A comma-separated list of groups to exclude. | Optional | 
| auth_domain_name | The user’s auth domain. | Optional | 
| account_expired | Whether to filter the list of users whose expiration time has passed. Possible values are: true, false. | Optional | 
| allowed_auth_methods | A comma-separated list of login authentication methods allowed to the users. A special value `empty` can be specified to get users to whom no authentication method is allowed. Possible values are: password, user_certificate, password_with_user_certificate, empty. | Optional | 
| allowed_client_types | A comma-separated list of client types that can authenticate the user. Possible values are: unregistered, public, confidential. | Optional | 
| password_policy | The assigned password policy. | Optional | 
| return_groups | If set to 'true', it returns the group's name in which user is associated along with all users information. Possible values are: true, false. | Optional | 
| page | Page to return. | Optional | 
| page_size | Number of entries per page. Defaults to 2000 (in case only page was provided). Maximum entries per page is 2000. | Optional | 
| limit | The maximum number of entries to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CipherTrust.Users.username | String | The login name of the user. This attribute is required to create a user, but is omitted when getting or listing a user. It cannot be updated. | 
| CipherTrust.Users.connection | String | This attribute is required to create a user, but is not included in user resource responses. Can be the name of a connection or 'local_account' for a local user, defaults to 'local_account'. | 
| CipherTrust.Users.email | String | E-mail of the user. | 
| CipherTrust.Users.name | String | Full name of the user. | 
| CipherTrust.Users.certificate_subject_dn | String | The Distinguished Name of the user in certificate. | 
| CipherTrust.Users.enable_cert_auth | Boolean | Deprecated: Use allowed_auth_methods instead. Enable certificate based authentication flag. If set to true, the user will be able to login using a certificate. | 
| CipherTrust.Users.user_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. user_metadata is typically used by applications to store information about the resource which the end-users are allowed to modify, such as user preferences. | 
| CipherTrust.Users.app_metadata | Unknown | A schema-less object, which can be used by applications to store information about the resource. app_metadata is typically used by applications to store information which the end-users are not themselves allowed to change, like group membership or security roles. | 
| CipherTrust.Users.logins_count | Number | Number of logins. | 
| CipherTrust.Users.last_login | Date | Timestamp of the last login. | 
| CipherTrust.Users.created_at | Date | Timestamp of when the user was created. | 
| CipherTrust.Users.updated_at | Date | Timestamp of the last update of the user. | 
| CipherTrust.Users.allowed_auth_methods | Unknown | List of login authentication methods allowed to the user. | 
| CipherTrust.Users.expires_at | Date | The expires_at is applicable only for local user accounts. The admin or a user who is part of the admin group can add an expiration date to an existing local user account or modify the expiration date. Once the expires_at date is reached, the user account gets disabled and the user is not able to perform any actions. | 
| CipherTrust.Users.password_policy | String | The password policy applies only to local user accounts and overrides the global password policy. By default, the global password policy is applied to the users. | 
| CipherTrust.Users.allowed_client_types | Unknown | List of client types allowed to the user. | 
| CipherTrust.Users.last_failed_login_at | Date | Timestamp of the last failed login. | 
| CipherTrust.Users.failed_logins_count | Number | Number of failed logins. | 
| CipherTrust.Users.failed_logins_initial_attempt_at | Date | Timestamp of the first failed login. | 
| CipherTrust.Users.account_lockout_at | Date | Timestamp of the account lockout. | 
| CipherTrust.Users.nickname | String | Nickname of the user. | 
| CipherTrust.Users.user_id | String | The user's unique identifier. | 
| CipherTrust.Users.password_changed_at | Date | Timestamp of when the password was last changed. | 
| CipherTrust.Users.password_change_required | Boolean | Flag indicating if password change is required. | 
| CipherTrust.Users.groups | Unknown | List of groups the user belongs to. | 
| CipherTrust.Users.auth_domain | String | Authentication domain ID. | 
| CipherTrust.Users.login_flags | Unknown | Flags related to user login. | 
| CipherTrust.Users.auth_domain_name | String | Name of the authentication domain. | 

#### Command example

```!ciphertrust-users-list limit=10```

#### Context Example

```json
{
    "CipherTrust": {
        "Users": [
            {
                "account_lockout_at": null,
                "allowed_auth_methods": [
                    "password"
                ],
                "allowed_client_types": [
                    "unregistered",
                    "public",
                    "confidential"
                ],
                "auth_domain": "00000000-0000-0000-0000-000000000000",
                "auth_domain_name": "root",
                "certificate_subject_dn": "",
                "created_at": "2024-02-14T10:08:19.228482Z",
                "email": "admin@local",
                "enable_cert_auth": false,
                "failed_logins_count": 0,
                "failed_logins_initial_attempt_at": null,
                "last_failed_login_at": "2024-06-13T07:53:10.344208Z",
                "last_login": "2024-06-18T09:16:15.458706Z",
                "login_flags": {
                    "prevent_ui_login": false
                },
                "logins_count": 1518,
                "name": "admin",
                "nickname": "admin",
                "password_change_required": false,
                "password_changed_at": "2024-02-14T11:36:13.102117Z",
                "updated_at": "2024-06-18T09:16:15.464732Z",
                "user_id": "local|1e83aa21-0141-458a-8d77-e7d21192a82f",
                "user_metadata": {
                    "current_domain": {
                        "id": "00000000-0000-0000-0000-000000000000",
                        "name": "root"
                    },
                    "persistedData": {
                        "00000000-0000-0000-0000-000000000000": {}
                    }
                },
                "username": "admin"
            },
            {
                "account_lockout_at": null,
                "allowed_auth_methods": [
                    "password"
                ],
                "allowed_client_types": [
                    "unregistered",
                    "public",
                    "confidential"
                ],
                "auth_domain": "00000000-0000-0000-0000-000000000000",
                "auth_domain_name": "root",
                "certificate_subject_dn": "",
                "created_at": "2024-06-13T07:45:25.006675Z",
                "email": "test_user@local",
                "enable_cert_auth": false,
                "expires_at": "2025-06-13T12:06:45.370974Z",
                "failed_logins_count": 3,
                "failed_logins_initial_attempt_at": "2024-06-16T10:47:22.433357Z",
                "last_failed_login_at": "2024-06-17T10:08:19.683975Z",
                "last_login": null,
                "login_flags": {
                    "prevent_ui_login": false
                },
                "logins_count": 0,
                "name": "new_test_user",
                "nickname": "test_user",
                "password_change_required": false,
                "password_changed_at": "2024-06-13T07:45:24.999078Z",
                "updated_at": "2024-06-17T10:08:19.683975Z",
                "user_id": "local|9a1769b4-86e0-4e24-8316-ea4e7b76c23c",
                "username": "test_user"
            },
            {
                "account_lockout_at": null,
                "allowed_auth_methods": [
                    "password"
                ],
                "allowed_client_types": [
                    "unregistered",
                    "public",
                    "confidential"
                ],
                "auth_domain": "00000000-0000-0000-0000-000000000000",
                "auth_domain_name": "root",
                "certificate_subject_dn": "",
                "created_at": "2024-06-13T12:30:36.870178Z",
                "email": "test_ui_create@local",
                "enable_cert_auth": false,
                "failed_logins_count": 0,
                "failed_logins_initial_attempt_at": null,
                "last_failed_login_at": null,
                "last_login": null,
                "login_flags": {
                    "prevent_ui_login": false
                },
                "logins_count": 0,
                "name": "test_ui_create",
                "nickname": "test_ui_create",
                "password_change_required": false,
                "password_changed_at": "2024-06-13T12:30:36.860143Z",
                "password_policy": "global",
                "updated_at": "2024-06-13T12:30:36.870178Z",
                "user_id": "local|ba75d58e-c8de-40fa-bb93-008a7263d59e",
                "user_metadata": {
                    "connection": "local_account"
                },
                "username": "test_ui_create"
            }
        ]
    }
}
```

#### Human Readable Output

>### Users

>|Username|Full Name|Email|Created|Updated|Expires|Id|Last Login|Logins|Last Failed Login|Password Changed|Password Change Required|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| admin | admin | admin@local | 14 Feb 2024, 10:08 | 18 Jun 2024, 09:16 | Never | local\|1e83aa21-0141-458a-8d77-e7d21192a82f | 18 Jun 2024, 09:16 | 1518 | 13 Jun 2024, 07:53 | 14 Feb 2024, 11:36 | false |
>| test_user | new_test_user | test_user@local | 13 Jun 2024, 07:45 | 17 Jun 2024, 10:08 | 13 Jun 2025, 12:06 | local\|9a1769b4-86e0-4e24-8316-ea4e7b76c23c | Never Logged In | 0 | 17 Jun 2024, 10:08 | 13 Jun 2024, 07:45 | false |
>| test_ui_create | test_ui_create | test_ui_create@local | 13 Jun 2024, 12:30 | 13 Jun 2024, 12:30 | Never | local\|ba75d58e-c8de-40fa-bb93-008a7263d59e | Never Logged In | 0 | Never Failed A Login | 13 Jun 2024, 12:30 | false |
>
>1 to 3 of 3 Users