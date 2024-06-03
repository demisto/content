## Thales CipherTrust Manager Integration

Use the Thales CipherTrust Manager integration to manage secrets and protect sensitive data through Thales CipherTrust Manager.

### Overview

CipherTrust Manager simplifies key lifecycle management tasks. It enables organizations to centrally manage encryption keys for the Thales CipherTrust Data Security Platform and third-party products. Role-based access provides control to keys and policies, multitenancy support, and robust auditing and reporting of all key management and encryption operations.

### Configuration Notes - Authenticating to Thales CipherTrust Manager

The Thales CipherTrust Manager integration utilizes the Thales CipherTrust Manager REST API to communicate with the Thales CipherTrust Manager server. The REST API is hosted at the following base URL: `{Server URL}/api/v1`.

#### Access Token

API calls are authenticated using access tokens. An access token is a string representing an authorization issued to the client, often referred to as an API authentication token. Access tokens expire and so must be refreshed periodically. A new access token is created with the user's credentials upon each command.

#### Token Generation

The integration employs API token generation for user credentials by accessing the `/auth/tokens/` endpoint with the 'password' grant-type. This endpoint allows the exchange of a username and password for an access token for the root domain.

### Parameters

| Parameter Name | Required 
|----------------|---------
| Server URL     | Yes     
| Username       | Yes     
| Password       | Yes     

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




