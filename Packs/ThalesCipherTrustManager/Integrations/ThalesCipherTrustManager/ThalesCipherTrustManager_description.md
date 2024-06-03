## Thales CipherTrust Manager Integration

Use the Thales CipherTrust Manager integration to manage secrets and protect sensitive data through Thales CipherTrust Manager.

### Overview

CipherTrust Manager simplifies key lifecycle management tasks, including secure key generation, backup/restore, clustering, deactivation, and deletion. It enables organizations to centrally manage encryption keys for the Thales CipherTrust Data Security Platform and third-party products. Role-based access provides control to keys and policies, multitenancy support, and robust auditing and reporting of all key management and encryption operations.

The CipherTrust Manager is built on prevailing cloud-based technologies, providing a cloud-friendly key management solution. It employs a microservice-based architecture, allowing for easy deployment and scalability within your environment. This architecture simplifies administration, ensures compliance, and maximizes security by providing centralized management of keys, policies, and essential functions.

### Configuration Notes - Authenticating to Thales CipherTrust Manager

The Thales CipherTrust Manager integration utilizes the Thales CipherTrust Manager REST API to communicate with the Thales CipherTrust Manager server. The REST API is hosted at the following base URL: `{Server URL}/api/v1`.

#### Access Token

API calls are authenticated using access tokens. An access token is a string representing an authorization issued to the client, often referred to as an API authentication token. Access tokens expire and so must be refreshed periodically. A new access token is created with the user's credentials upon each command.

#### Token Generation

The integration employs API token generation for user credentials by accessing the `/auth/tokens/` endpoint with the 'password' grant-type. This endpoint allows the exchange of a username and password for an access token for the root domain.

### Parameters

| Parameter Name | Required | Default Value | Section |
|----------------|----------|---------------|---------|
| Server URL     | Yes      |               | Connect |
| Username       | Yes      |               | Connect |
| Password       | Yes      |               | Connect |

### Main Use Cases for the Thales CipherTrust Manager Integration

The Thales CipherTrust Manager integration supports several key use cases:

#### 1. Groups Management

Groups management is essential for organizing users and defining permissions within the Thales CipherTrust Manager.

- **Overview**:
  Groups carry permissions for performing specific tasks and consist of a set of users and/or clients authorized to perform these tasks. The CipherTrust Manager defines Special System Users, System Defined Groups, and User Defined Groups - providing the option to create customized groups.

  - **Creating Groups**: 
    - **Command**: `ciphertrust-group-create`
    - **Description**: Allows the creation of new groups.
  - **Deleting Groups**:
    - **Command**: `ciphertrust-group-delete`
    - **Description**: Deletes a group.
  - **Updating Groups**:
    - **Command**: `ciphertrust-group-update`
    - **Description**: Updates the details of an existing group.
  - **Adding User to Group**:
    - **Command**: `ciphertrust-user-to-group-add`
    - **Description**: Adds a user to a specified group.
  - **Removing User from Group**:
    - **Command**: `ciphertrust-user-to-group-remove`
    - **Description**: Removes a user from a specified group.

-   - **Listing Groups**:
    - **Command**: `ciphertrust-group-list`
    - **Description**: Returns a list of group resources.


#### 2. Users Management

User management is critical for ensuring secure access and proper account management within the Thales CipherTrust Manager.

- **Creating Users**:
  - **Command**: `ciphertrust-user-create`
  - **Description**: Allows administrators to create new users within the CipherTrust Manager.
- **Listing Users**:
  - **Command**: `ciphertrust-users-list`
  - **Description**: Returns a list of all user resources, filtered by various parameters.
- **Updating Users**:
  - **Command**: `ciphertrust-user-update`
  - **Description**: Allows for updating user details such as name, password, email, and authentication methods.
- **Deleting Users**:
  - **Command**: `ciphertrust-user-delete`
  - **Description**: Deletes a user.
- **Changing User Password**:
  - **Command**: `ciphertrust-user-password-change`
  - **Description**: Allows a user to change its own password.

#### 3. Certificate Authority

Managing digital certificates is crucial for maintaining secure communications and ensuring data integrity.

- **Creating Local Certificate Authorities**:
  - **Command**: `ciphertrust-local-ca-create`
  - **Description**: Creates a new local certificate authority.
- **Listing Local Certificate Authorities**:
  - **Command**: `ciphertrust-local-ca-list`
  - **Description**: Returns a list of local certificate authorities.
- **Updating Local Certificate Authorities**:
  - **Command**: `ciphertrust-local-ca-update`
  - **Description**: Updates the details of an existing local certificate authority.
- **Deleting Local Certificate Authorities**:
  - **Command**: `ciphertrust-local-ca-delete`
  - **Description**: Deletes a local certificate authority.
- **Self-Signing Local Certificate Authorities**:
  - **Command**: `ciphertrust-local-ca-self-sign`
  - **Description**: Self-signs a local certificate authority.
- **Installing Certificates to Local Certificate Authorities**:
  - **Command**: `ciphertrust-local-ca-install`
  - **Description**: Installs a certificate to a local certificate authority.

- **Issuing Certificates**:
  - **Command**: `ciphertrust-certificate-issue`
  - **Description**: Issues a new certificate.
- **Listing Certificates**:
  - **Command**: `ciphertrust-certificate-list`
  - **Description**: Returns a list of certificates.
- **Deleting Local Certificates**:
  - **Command**: `ciphertrust-local-certificate-delete`
  - **Description**: Deletes a local certificate.
- **Revoking Certificates**:
  - **Command**: `ciphertrust-certificate-revoke`
  - **Description**: Revokes a certificate.
- **Resuming Certificates**:
  - **Command**: `ciphertrust-certificate-resume`
  - **Description**: Resumes a revoked certificate.

- **Uploading External Certificates**:
  - **Command**: `ciphertrust-external-certificate-upload`
  - **Description**: Uploads an external certificate.
- **Deleting External Certificates**:
  - **Command**: `ciphertrust-external-certificate-delete`
  - **Description**: Deletes an external certificate.
- **Updating External Certificates**:
  - **Command**: `ciphertrust-external-certificate-update`
  - **Description**: Updates an external certificate.
- **Listing External Certificates**:
  - **Command**: `ciphertrust-external-certificate-list`
  - **Description**: Returns a list of external certificates.



