## Prisma Cloud IAM
- This section explains how to configure the instance of Prisma Cloud IAM in Cortex XSOAR.

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PrismaCloudIAM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Base URL | True |
    | Username | True |
    | Password | True |
    | Customer name | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Allow creating users | False |
    | Allow updating users | False |
    | Allow enabling users | False |
    | Allow disabling users | False |
    | Automatically create user if not found in update command | False |
    | Incoming Mapper | True |
    | Outgoing Mapper | True |

4. Click **Test** to validate the URLs, token, and connection.
