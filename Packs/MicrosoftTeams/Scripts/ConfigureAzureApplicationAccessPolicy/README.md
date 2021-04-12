This script is grants a user the permissions needed to create a Teams meeting.
It connects to MS Teams, creating an application access policy to a chosen application and then grants a user permissions.
For more information, see [Microsoft documentation - Allow applications to access online meetings on behalf of a user](https://docs.microsoft.com/en-us/graph/cloud-communication-online-meeting-application-access-policy)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | powershell |
| Tags | basescript |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| username | The login admin's username. |
| password | The login admin's password. |
| identity | The email of the user who will receive permissions to create a meeting. |
| app_id | The relevant app's ID from the app studio. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ConfigureAzureApplicationAccessPolicy.Status | Whether the access policy was given. | String |
| ConfigureAzureApplicationAccessPolicy.Account | The email of the user who received permissions to create a meeting. | String |
| ConfigureAzureApplicationAccessPolicy.AppID | The relevant app's ID from the app studio. | String |

## Script Example
```!ConfigureAzureApplicationAccessPolicy app_id="37b5b9d5" identity="demisto@palo.com" username="admin@palo.com" password="12345"```

## Context Example
```json
{
    "ConfigureAzureApplicationAccessPolicy": {
        "Status": "Access policy was given",
        "Account": "demisto@palo.com",
        "AppID": "37b5b9d5"
    }
}
```

## Human Readable Output
>Access policy was given.


