## Keeper Secrets Manager

### Authentication

#### Configuration Token Method
It is required to fill in only the *KSM Configuration* parameter.
For more details, see the [Keeper Secrets Manager documentation](https://docs.keeper.io/secrets-manager/secrets-manager/overview).

### Authorize Cortex XSOAR for Keeper Secrets Manager Access

#### [Enable](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide#enable-secrets-manager) Secrets Manager
1. In the Keeper [Admin Console](https://keepersecurity.com/console/), select Secrets Manager and check if it is enabled or start a Free Trial.
2. Select Admin.
3. Select the desired Node in your Enterprise and switch to Roles tab.
4. Select existing role or add a new one and click Enforcement Policies button.
5. Inside **Keeper Secrets Manager** policy - enable *Allow users to generate and approve Application Access Requests*.

#### [Setup](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide#setup-secrets-manager) Secrets Manager

1. In the Keeper [Web Vault](https://keepersecurity.com/vault/) or Desktop App, create a **Shared** Folder.
2. Add Secrets to the folder.
3. Create a [Secrets Manager Application](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide#create-a-secrets-manager-application)
4. Share some records and/or folders to the new application.
5. Create a [Secrets Manager Client Device](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide#create-a-secrets-manager-client-device) and copy the *One-Time Access Token*
6. Use [Keeper Secrets Manager CLI](https://docs.keeper.io/secrets-manager/secrets-manager/secrets-manager-command-line-interface) to initialize the device configuration. Download latest [KSM CLI](https://github.com/Keeper-Security/secrets-manager/releases?q=ksm+cli) release from GitHub and execute:
>`ksm init default <ONE_TIME_TOKEN>`
7. Copy the `ksm init` command output and enter it in the *KSM Configuration* parameter.

### Fetch credentials from Keeper Secrets Manager Application
In order to fetch credentials to the Cortex XSOAR credentials store, you should follow the next steps:
1. Check *Fetches credentials* parameter.
2. *Optional:* Check *Concat username to credential object name* if needed, to make names unique.
3. *Optional:* Fill a CSV list of credential names to fetch.  
**Note:** If CSV list is empty - All credentials will be fetched.  
**Note:** If *Concat* option is used, adjust CSV names accordingly.

After the Keeper Secrets Manager integration instance is created, the credentials will be fetched to the Cortex XSOAR credentials store in the following format:

Credential Name: RECORD_TITLE

*Credential Name with Concat: RecordTitle_LoginFieldValue*

Username: LOGIN_FIELD_VALUE

Password: PASSWORD_FIELD_VALUE