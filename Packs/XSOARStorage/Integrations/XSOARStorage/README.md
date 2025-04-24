Facilitates the storage and retrieval of key/value pairs within XSOAR.
## Configure XSOAR Storage in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Max Size of Store in bytes (Maximum of 1024000) | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### xsoar-store-list
***
List the keys available.


#### Base Command

`xsoar-store-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| namespace | The namespace to retrieve keys from. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XSOAR.Store | unknown | The namespace and keys. | 


#### Command Example
``` ```

#### Human Readable Output



### xsoar-store-put
***
Places data in the store under the provided key.


#### Base Command

`xsoar-store-put`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | The key to store data under. | Required | 
| data | The data to store. | Required | 
| namespace | The namespace to store data in. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### xsoar-store-get
***
Retrieve data stored in the provided key.


#### Base Command

`xsoar-store-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | The Key value. | Required | 
| namespace | The namespace to retrieve data from. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XSOAR.Store | unknown |  | 


#### Command Example
``` ```

#### Human Readable Output

