Delinea DevOps Secrets Vault is a high velocity vault that centralizes secrets management, enforces access, and provides automated logging trails. DevOps Secrets Vault is an API-as-a-Service, which makes getting up and running easy. No installation of the vault or database is required and Delinea even handles all the updates. This integration was integrated and tested with version 6.0 of DelineaDSV. Supported Cortex XSOAR versions: 5.0.0 and later.
Manage credentials for applications, databases, CI/CD tools, and services without causing friction in the development process.

## Configure DelineaDSV on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DelineaDSV.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://example.com) | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Client ID | True |
    | Client Secret | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dsv-secret-get
***
Getting a secret fom DSV


#### Base Command

`dsv-secret-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Secret name for DSV. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| secret | String | Received JSON object secret | 

#### Command Example
```!dsv-secret-get name="accounts/xsoar"```

#### Context Example
```json
{
    "DSV": {
        "Secret": {
            "attributes": {},
            "created": "2022-05-17T10:55:41Z",
            "createdBy": "users:thy-one:testuser@accessecm.com",
            "data": {
                "password": "XSOARPassword",
                "username": "xsoar"
            },
            "description": "",
            "id": "e88f725b-ff1c-4902-961e-fcdf3c7f712f",
            "lastModified": "2022-05-17T10:55:41Z",
            "lastModifiedBy": "users:thy-one:testuser@accessecm.com",
            "path": "accounts:xsoar",
            "version": "1"
        }
    }
}
```
