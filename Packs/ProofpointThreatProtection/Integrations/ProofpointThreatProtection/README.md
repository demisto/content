Threat Protection APIs are REST APIs that allow Proofpoint On Demand customers to retrieve, add, update or delete certain PoD configurations.
## Configure Proofpoint Threat Protection in Cortex


| **Parameter** | **Required** |
| --- | --- |
| URL | True |
| Client ID | True |
| Client Secret | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Cluster ID | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### proofpoint-tp-blocklist-get

***
Get all entries in the Organizational Block List.

#### Base Command

`proofpoint-tp-blocklist-get`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofpointThreatProtection.Blocklist | unknown | A list of entries in the blocklist. | 

### proofpoint-tp-blocklist-add-or-delete-entry

***
Add/Delete entry from the Organizational Block List.

#### Base Command

`proofpoint-tp-blocklist-add-or-delete-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to perform. Possible values are: add, delete. | Required | 
| attribute | Supported attributes for the Organizational Block List. Possible values are: \$from, \$hfrom, \$ip, \$host, \$helo, \$rcpt. | Required | 
| operator | Supported operators for the Organizational Block List. Possible values are: equal, not_equal, contain, not_contain. | Required | 
| value | The entry that the action is to be performed upon in the Organizational Block List. | Required | 
| comment | A short comment about the entry (max 150 chars). "comment" is ignored for the "delete" action. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofpointThreatProtection.Blocklist | unknown | Standard HTTP response with status code 200. | 

### proofpoint-tp-safelist-get

***
Get all entries in the Organizational Safe List.

#### Base Command

`proofpoint-tp-safelist-get`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofpointThreatProtection.Safelist | unknown | A list of entries in the Organizational Safe List. | 

### proofpoint-tp-safelist-add-or-delete-entry

***
Add To/Delete From the Organizational Safe List.

#### Base Command

`proofpoint-tp-safelist-add-or-delete-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to perform. Possible values are: add, delete. | Required | 
| attribute | Supported attributes for the Organizational Safe List. Possible values are: \$from, \$hfrom, \$ip, \$host, \$helo, \$rcpt. | Required | 
| operator | Supported operators for the Organizational Safe List. Possible values are: equal, not_equal, contain, not_contain. | Required | 
| value | The entry that the action is to be performed upon in the Organizational Safe List. | Required | 
| comment | A short comment about the entry (max 150 chars). "comment" is optional for "add" action and ignored for the "delete" action. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofpointThreatProtection.Safelist | unknown | Standard HTTP response with status code 200. | 