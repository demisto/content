Manage credentials for applications, databases, CI/CD tools, and services without causing friction in the development process.
This integration was integrated and tested with version 1.37.0 of DelineaDSV

## Configure DelineaDSV in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://example.com) | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Client ID | True |
| Client Secret | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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