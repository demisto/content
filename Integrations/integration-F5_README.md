Manages F5 firewall rules
This integration was integrated and tested with version xx of F5 firewall
## Configure F5 firewall on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for F5 firewall.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | URL | True |
| port | Port | True |
| credentials | Credentials | True |
| advancedLogin | Advanced login - set to true to authenticate via LDAP, AD etc | False |
| insecure | Trust any certificate (unsecure) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### f5-create-policy
***
Creates an F5 firewall policy
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`f5-create-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### f5-create-rule
***
Creates a rule in a specific policy
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`f5-create-rule`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The policy name the rule will be associated with | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### f5-list-rules
***
List all the rules of a specific policy
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`f5-list-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The policy name that the rules displayed are associated with | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### f5-modify-rule
***
Modifies an F5 rule in a specific policy
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`f5-modify-rule`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| The policy name the rule is associated with | policy-name | Required | 
| rule-name | The rule name to modify | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### f5-del-rule
***
Delete an F5 rule
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`f5-del-rule`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The policy name the rule is associated with | Required | 
| rule-name | The rule name to delete | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### f5-modify-global-policy
***
Add specific policy to global policy
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`f5-modify-global-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enforcedPolicy | The new enforced policy to add to global policy | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### f5-show-global-policy
***
Display global policy
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`f5-show-global-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### f5-del-policy
***
Delete a policy
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`f5-del-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The policy name to delete | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### f5-list-all-user-sessions
***
Lists all the sessions with client ip for the given username
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`f5-list-all-user-sessions`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource-ip | Client IP address | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


## Additional Information

## Known Limitations