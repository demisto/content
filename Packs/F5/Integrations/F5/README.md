Manages F5 firewall rules
This integration was integrated and tested with version xx of F5 firewall
## Configure F5 firewall on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for F5 firewall.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | URL | True |
| port | Port | False |
| credentials | Credentials | True |
| advancedLogin | Advanced login \- set to true to authenticate via LDAP, AD etc | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### f5-create-policy
***
Creates an F5 firewall policy.


#### Base Command

`f5-create-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the policy to create | Required | 
| description | The description of the policy | Required | 
| copyFrom | The policy to copy rules from to use as template for new policy | Optional | 
| partition | The partition (Default: Common) | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### f5-create-rule
***
Creates a rule in a specific policy


#### Base Command

`f5-create-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The policy name the rule will be associated with. | Required | 
| ruleList | Specifies a list of rules to evaluate. See security firewall rule-list. If a rule-list is specified then only the schedule and status properties effect the rule. | Optional | 
| name | The rule name | Optional | 
| status | enabled, disabled or scheduled | Optional | 
| ipProtocol | lowercase version of protocol listed in the UI | Optional | 
| action | accept, drop, reject | Optional | 
| placeBefore | first | Optional | 
| source | the ip sources in csv format | Optional | 
| destination | the ip destinations in csv format | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### f5-list-rules
***
Lists all the rules of a specific policy.


#### Base Command

`f5-list-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The policy name that the rules displayed are associated with | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### f5-modify-rule
***
Modifies an F5 rule in a specific policy


#### Base Command

`f5-modify-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The policy name the rule is associated with. | Required | 
| rule-name | The rule name to modify. | Required | 
| action | accept, drop, reject | Optional | 
| ipProtocol | one of any described in the UI, but in all lowercase | Optional | 
| placeBefore | first or... | Optional | 
| source | csv list of sources | Optional | 
| destination | csv list of destinations | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### f5-del-rule
***
Delete an F5 firewall rule.


#### Base Command

`f5-del-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The policy name the rule is associated with. | Required | 
| rule-name | The name of the rule to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### f5-modify-global-policy
***
Adds the specific policy to a global policy.


#### Base Command

`f5-modify-global-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enforcedPolicy | The new enforced policy to add to the global policy. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### f5-show-global-policy
***
Display global policy.


#### Base Command

`f5-show-global-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### f5-del-policy
***
Delete a policy.


#### Base Command

`f5-del-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy-name | The name of the policy to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### f5-list-all-user-sessions
***
Lists all the sessions with client IP for the given username.


#### Base Command

`f5-list-all-user-sessions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource-ip | Client IP address. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


