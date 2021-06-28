## Integration with Safewalk reporting services

## Use Cases

- Fetch incidents from Safewalk Server
- Get transaction logs
- Get license inventory
- Search for user incidents
- Query user attributes
---
## Configure Safewalk on XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Safewalk_Management.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Safewalk URL (https://safewalk-server.company.com) | True |
| apitoken | API Token (see Detailed Instructions) | True |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
