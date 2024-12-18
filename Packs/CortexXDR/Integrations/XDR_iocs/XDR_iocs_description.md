### Configurations

---

#### Generate an API Key and Key ID

To enable secure communication with Cortex XDR, you need to generate an API Key and Key ID. Follow these steps:

1. In your Cortex XDR platform, go to **Settings** > **Configurations** > **API Keys**.
2. Click the **+New Key** button in the top right corner.
3. Set the **Security Level** to **Advanced** and select a **Role** appropriate for your permissions.
4. Copy the API Key displayed in the **Generated Key** field.
5. From the **ID** column, copy the Key ID.

##### Note 1:

When configuring a role for the API Key's permission you can create a custom role or use a built-in role. The highest privileged built-in role is the Instance Admin. If you wish to use a built-in role with less permission but maximum command capabilities, use the Privileged Responder role.

##### Note 2:

Securely store the API Key, as it will not be displayed again.

#### Retrieve API URL

1. In the Cortex XDR platform, go to **Settings**> **Configurations** > **API Keys**.
2. Click the **Copy API URL** button in the top-right corner.

**Note**: Only a single instance of this integration can be supported at a time. Configuring multiple instances will cause conflicts and disrupt proper functionality.
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/cortex-xdr---ioc)