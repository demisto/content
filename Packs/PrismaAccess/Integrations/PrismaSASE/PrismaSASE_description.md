This integration was integrated and tested with version 1.0 of Prisma SASE API.

## Create an account in Prisma SASE UI:

1. Navigate to **Common Services** > **Identity & Access** > **Servers & Services**.
2. Add or create a service account with the proper privileges.
3. Make a note of the **Client ID** and **Client Secret**.  These will be used to configure the integration.


## Prisma SASE API
[Prisma SASE API](https://pan.dev/sase).

## Required Permissions

To use the integration commands, ensure the ***Prisma Access & NGFW Configuration*** has one of the following roles assigned:

- Multitenant Superuser
- Superuser

To use the **prisma-sase-cie-user-get** command, ensure the ***Cloud Identity Engine*** has one of the following roles assigned:

- Deployment Administrator
- Multitenant Superuser
- Superuser
- View Only Administrator