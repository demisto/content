## Bitbucket Integration Help

Bitbucket Cloud has deprecated app passwords (which will cease to work entirely on **June 9, 2026**) in favor of **Scoped API tokens**. [https://developer.atlassian.com/cloud/bitbucket/rest/intro/\#app-passwords](https://developer.atlassian.com/cloud/bitbucket/rest/intro/#app-passwords)

To authenticate with an API Token:

1. Go to **Atlassian account settings** -> **Security** -> **API tokens** (https://id.atlassian.com/manage-profile/security/api-tokens).

2. **Create an API token with scopes**.

3. In the integration instance:

   * **User Name** = your **Atlassian account email address**.

   * **API Token** = the token you copied.

To authenticate with OAuth 2.0 client credentials:

Create an **OAuth consumer** in the Bitbucket workspace and enable the client-credentials grant:

1. In Bitbucket Cloud, go to **Workspace settings** -> under **Apps and features** select **OAuth clients**.

2. Select the required **Permissions/scopes** (e.g., read access to Account, Repositories, Projects, Pull requests, and Issues, matching the commands you intend to run).

3. In the integration instance:

   * **Client ID** = the consumer **Key**.

   * **Client Secret** = the consumer **Secret**.

---

### Known Limitations

* To perform the project commands, ensure the **API Token** or **OAuth consumer** has **Read** permissions for **Projects**.
* In order to perform the ***bitbucket-issue-create*** command, an issue tracker is required.
* In order to create an issue tracker, click the relevant repo > Repository settings > Issue tracker, and create it.
