## Idira Identity Response

### Authentication

The integration authenticates with the Idira Identity Security Platform Shared Services (ISPSS) using the **OAuth 2.0 client-credentials** flow. It requests a Bearer token from `https://<tenant>.id.cyberark.cloud/oauth2/platformtoken` and sends it on every subsequent Identity API call.

Complete the following steps in Identity Administration before configuring the integration instance.

### Step 1: Create a service user (OAuth confidential client)

1. In Identity Administration, go to **Core Services** > **Users**, and click **Add User**.
2. Enter a login name, display name, and password.
3. In the **Status** area, select **Is OAuth confidential client**. Also select **Is Service User** and **Password never expires**.
4. Click **Create User**.

**Note**: the service **username (without domain)** is your **Client ID**, and the service **password** is your **Client Secret**.

### Step 2: Grant the service user the required rights

Assign the service user a role that grants **system-administrator** or **user-management** rights. Identity workforce actions (lock/disable user, force logout, expire password, remove role) require these rights.

Privilege Cloud actions (account, session, and credential commands) also require the relevant Safe permissions (List Accounts, Initiate CPM operations, Add account), and Secure Infrastructure Access (SIA) policy actions require the `DpaAdmin` role.

### Step 3: Configure the integration instance

| Parameter | Value |
| --- | --- |
| **Identity URL** | The Idira Identity tenant FQDN, e.g. `https://abc1234.id.cyberark.cloud` |
| **Client ID** | The service username without domain |
| **Client Secret** | The service user password |
| **Privilege Cloud URL** | Optional. The Privilege Cloud PVWA host, e.g. `https://abc1234.privilegecloud.cyberark.cloud`. Required only for the account, session, and credential commands. |
| **Secure Infrastructure Access (SIA) URL** | Optional. The SIA host, e.g. `https://abc1234.dpa.cyberark.cloud`. Required only for the access-policy commands. |
