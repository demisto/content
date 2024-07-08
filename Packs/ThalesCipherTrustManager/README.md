# Thales CipherTrust Manager

Thales CipherTrust Manager integrates with Palo Alto Network’s Cortex XSOAR to streamline the management of sensitive data and secure access. The integration provides security teams with essential tools to configure, manage, and monitor user groups and digital certificates efficiently. For instance, when a suspicious action is detected within the CipherTrust Manager, such as unauthorized access attempts or unusual certificate requests, security teams can immediately modify user permissions, enforce stricter authentication processes, or revoke compromised certificates.


## What does this pack do?

This pack provides comprehensive tools and functionalities centered around three main use cases to enhance security and management within the platform:

- **Groups Management**: It allows for the organization and definition of permissions within User Defined and System Defined Groups. This is essential for structuring operational hierarchy and ensuring effective access control across the platform.

- **Users Management**: The pack supports efficient user account management with secure access capabilities. It facilitates authentication across multiple systems, including LDAP and AD, enabling a streamlined and secure user management process.

- **Certificate Authority Management**: The pack includes features for managing digital certificates, which are vital for maintaining secure communication channels. It enables the creation and management of both local and external Certificate Authorities (CAs), and the generation and issuance of certificates to ensure communication security.


### Use Cases

This pack supports a variety of use cases essential for secure and efficient platform management:

- **Group Management Operations**:
  - **Creating, Deleting, Updating Groups**: Control permissions for performing specific tasks or organize users into groups.
  - **Policy Application**: Utilize group membership to assign permissions across different policies.

- **User Management Operations**:
  - **Creating, Deleting, Editing Users**: Manage user authentication and control login behavior.
  - **Store Application-Specific Information**: Maintain user-specific data which may include preferences or security roles.

- **User to Group Association**:
  - **Adding User to Group**: Facilitate the inclusion of users into specific groups to align with organizational policies and access control.

- **Certificate Authority Management**:
  - **Create Local and External CAs**: Establish new Certificate Authorities that can be utilized for internal interfaces and services.
  
- **Digital Certificates Management**:
  - **Issue and Install Certificates**: Manage the issuance and installation of server and client digital certificates along with certificate signing requests (CSR).
  - **Revoke and Resume Certificates**: Provide functionality to revoke or resume certificates, specifically those signed by local CAs, ensuring compliance with security standards.

For detailed description of each of the use cases, see the integration documentation.


## Permissions

For details on the Attribute-based Access Control (ABAC) permissions required for operations on resources, see the [CipherTrust Documentation](https://thalesdocs.com/ctp/cm/latest/admin/cm_admin/abac-permissions/index.html).


