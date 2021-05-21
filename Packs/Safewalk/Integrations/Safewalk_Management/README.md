## Integration with Safewalk identity management service ##
---
## Use Cases
---
- Create users
- Delete users attempts
- Create tokens
- Assign user license
- Update users personal information
---
## Configure Safewalk on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Safewalk_Management.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Safewalk URL (https://safewalk-server.company.com) | True |
| apitoken | API Token (see Detailed Instructions) | True |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### safewalk-delete-user-accessattempts
***
Unlocks a single user.

##### Base Command

`safewalk-delete-user-accessattempts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to unlock. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!safewalk-delete-user-accessattempts username=user@company.com```

