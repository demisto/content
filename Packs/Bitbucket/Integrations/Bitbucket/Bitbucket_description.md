## Bitbucket Integration Help

Bitbucket Cloud has deprecated app passwords (from **June 9, 2026**) in favor of scoped API tokens. For more information, see the [Bitbucket Cloud documentation](https://developer.atlassian.com/cloud/bitbucket/rest/intro/#app-passwords).

### Authenticate with an API Token

1. Go to **Atlassian account settings** -> **Security** -> **API tokens** (https://id.atlassian.com/manage-profile/security/api-tokens).

2. **Create an API token with scopes**.

3. In the integration instance settings, configure:

   * **User Name** = your **Atlassian account email address**.

   * **API Token** = the token you copied.

### Authenticate with OAuth 2.0 Client Credentials

Create an **OAuth consumer** in the Bitbucket workspace and enable the client-credentials grant:

1. In Bitbucket Cloud, go to **Workspace settings** -> under **Apps and features** select **OAuth clients**.

2. Select the required **Permissions/scopes** (e.g., read access to Account, Repositories, Projects, Pull requests, and Issues, matching the commands you intend to run).

3. In the integration instance settings, configure:

   * **Client ID** = the consumer **Key**.

   * **Client Secret** = the consumer **Secret**.

---

### Known Limitations

* To perform the project commands, ensure the **API Token** or **OAuth consumer** has **Read** permissions for **Projects**.
