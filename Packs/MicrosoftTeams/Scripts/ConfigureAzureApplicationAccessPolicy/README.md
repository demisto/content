This script is granting a user the necessary permissions in order to create a Teams meeting.
It's connecting to MS Teams, creating an application access policy to a chosen application and then granting a user permissions.
For more information look at [Microsoft documentation - Allow applications to access online meetings on behalf of a user](https://docs.microsoft.com/en-us/graph/cloud-communication-online-meeting-application-access-policy)

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
| identity | The email of the user that will get permissions to create a meeting. |
| app_id | The relevant app's ID from the app studio. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ConfigureAzureApplicationAccessPolicy.Status | Whether the access policy was given. | String |

## Script Example
```!ConfigureAzureApplicationAccessPolicy app_id="37b5b9d5" identity="demisto@palo.com" username="admin@palo.com" password="12345"```

## Context Example
```json
{
    "ConfigureAzureApplicationAccessPolicy": {
        "Status": "Access policy was given"
    }
}
```

## Human Readable Output
>Access policy was given.


