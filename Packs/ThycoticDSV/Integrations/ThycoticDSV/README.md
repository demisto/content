Thycotic DevOps Secrets Vault is a high velocity vault that centralizes secrets management, enforces access, and provides automated logging trails.
DevOps Secrets Vault is an API-as-a-Service, which makes getting up and running easy. No installation of the vault or database is required and Thycotic even handles all the updates.
This integration was integrated and tested with version 6.0 of ThycoticDSV.
Supported Cortex XSOAR versions: 5.0.0 and later.

## Configure ThycoticDSV in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.com\) | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| client_id | Client id for client_credentials grant type | True |
| client_secret | Client secret for client_credentials grant type | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dsv-secret-get
***
Get secret for client


#### Base Command

`dsv-secret-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name secret for operation Get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| secret | String | JSON object secret | 


#### Command Example
```!dsv-secret-get name="accounts/xsoar"```

#### Context Example
```json
{
    "DSV": {
        "Secret": {
            "attributes": {},
            "created": "2020-12-15T11:50:45Z",
            "createdBy": "users:thy-one:anikolaev@accessecm.com",
            "data": {
                "password": "XSOARPassword",
                "username": "xsoar"
            },
            "description": "",
            "id": "e88f725b-ff1c-4902-961e-fcdf3c7f712f",
            "lastModified": "2020-12-20T14:17:03Z",
            "lastModifiedBy": "users:thy-one:anikolaev@accessecm.com",
            "path": "accounts:xsoar",
            "version": "1"
        }
    }
}
```

#### Human Readable Output

>{'id': 'e88f725b-ff1c-4902-961e-fcdf3c7f712f', 'path': 'accounts:xsoar', 'attributes': {}, 'description': '', 'data': {'password': 'XSOARPassword', 'username': 'xsoar'}, 'created': '2020-12-15T11:50:45Z', 'lastModified': '2020-12-20T14:17:03Z', 'createdBy': 'users:thy-one:anikolaev@accessecm.com', 'lastModifiedBy': 'users:thy-one:anikolaev@accessecm.com', 'version': '1'}