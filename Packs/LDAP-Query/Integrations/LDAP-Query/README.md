The LDAP-Query Integration allows seamless interaction with LDAP servers, enabling users to query and authenticate LDAP entries using various identifiers such as Common Name (CN) and User ID (UID). This integration supports querying functionalities for LDAP servers, including fetching detailed user information.
This integration was integrated and tested with version 1.0.2 of LDAP-Query

## Configure LDAP-Query on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for LDAP-Query.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server IP or Host Name (e.g., 192.168.0.1) |  | True |
    | Port. If not specified, default port is 389, or 636 for LDAPS. |  | False |
    | User DN (e.g., cn=admin,ou=users,dc=domain,dc=com) |  | True |
    | Password |  | True |
    | Base DN (e.g., DC=domain,DC=com) |  | True |
    | Connection Type |  | True |
    | SSL Version | The SSL\\TLS version to use in SSL or Start TLS connections types. Default is None. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ldap-query

***
Query LDAP by CN or UID and optionally retrieve a specific attribute.

#### Base Command

`ldap-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cn | The Common Name (CN) to query. | Optional |
| uid | The User ID (UID) to query. | Optional |
| attribute | The specific attribute to retrieve. If not specified, all attributes will be returned. | Optional |

#### Context Output

There is no context output for this command.
