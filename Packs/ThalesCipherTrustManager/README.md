# Thales CipherTrust Manager

Thales CipherTrust Manager integrates with Palo Alto Network’s Cortex XSOAR to streamline the management of sensitive data and secure access. The integration provides security teams with essential tools to configure, manage, and monitor user groups and digital certificates efficiently. For instance, when a suspicious action is detected within the CipherTrust Manager, such as unauthorized access attempts or unusual certificate requests, security teams can immediately modify user permissions, enforce stricter authentication processes, or revoke compromised certificates.


## What does this pack do?
By leveraging Thales CipherTrust Manager with Cortex XSOAR, organizations can enhance the integration and automation of their security operations. This collaboration empowers security teams to:
- Monitor and manage user groups and digital certificates centrally.
- Automate responses to security incidents involving sensitive data and user credentials.
- Enforce security policies automatically following specific triggers or alerts.
- Improve overall security posture by ensuring quick and decisive actions are taken against potential threats.

### Use Cases

The pack includes an integration that supports several practical use cases:

- **Groups Management**: Organize users and define permissions through User Defined and System Defined Groups, critical for maintaining operational hierarchy and effective access control within the platform.

- **Users Management**: Secure access and manage accounts efficiently. This functionality supports authentication across various systems including LDAP and AD, ensuring robust and versatile user management capabilities.

- **Certificate Authority Management**: Handle digital certificates crucial for secure communications. This includes the ability to create and manage both local and external Certificate Authorities (CAs), and generate and issue certificates, ensuring that secure communication channels are established and maintained.

For detailed description of each of the use cases, see the integration documentation.


## Permissions Overview

This section outlines the permissions and command functionalities related to managing groups and users within the system.
For details on the Attribute-based Access Control (ABAC) permissions required for operations on resources, see the [CipherTrust Documentation](https://thalesdocs.com/ctp/cm/latest/admin/cm_admin/abac-permissions/index.html).


### Commands Related to Groups

Users and Clients can be added to Groups. Users' and Clients' group membership is available to the authorization system, so policies can use users' and clients' group membership to assign permissions.

### Commands Related to Users

Initially, there is only one Application Administrator, and the name of this user is "admin". The "admin" user is a special user who:
- Cannot be deleted.
- Will always have access to all resources.

This is enforced by the policy engine to prevent accidental lockouts.

