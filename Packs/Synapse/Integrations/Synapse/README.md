Synapse intelligence analysis platform.
This integration was integrated and tested with version xx of Synapse
## Configure Synapse on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Synapse.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://synapse.vertex.link\) | True |
| port | REST API Port \(default is 4443\). | True |
| credentials | Username and password to user to authenticate to Synapse. | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| timezone | Timezone \(optional\) | False |
| bad_tag | Malicious Tag | False |
| good_tag | Benign Tag | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Returns IP information and reputation.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.IP.ip | String | The IP address of the indicator. | 
| Synapse.IP.tags | String | The tags applied to the IP address. | 
| DBotScore.Indicator | String | The value assigned by DBot for the indicator. | 
| DBotScore.Type | String | The type assigned by DBot for the indicator. | 
| DBotScore.Score | Number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 


#### Command Example
``` ```

#### Human Readable Output



### url
***
Returns URL information and reputation.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.URL.url | String | The data of the URL indicator. | 
| Synapse.URL.tags | String | The tags applied to the url. | 
| DBotScore.Indicator | String | The value assigned by DBot for the indicator. | 
| DBotScore.Type | String | The type assigned by DBot for the indicator. | 
| DBotScore.Score | Number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| URL.Data | string | The data of the URL indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 


#### Command Example
``` ```

#### Human Readable Output



### domain
***
Returns Domain information and reputation.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Domain.domain | String | The fully qualified domain name. | 
| Synapse.Domain.tags | String | The tags applied to the domain. | 
| DBotScore.Indicator | String | The value assigned by DBot for the indicator. | 
| DBotScore.Type | String | The type assigned by DBot for the indicator. | 
| DBotScore.Score | Number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | string | The name of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 


#### Command Example
``` ```

#### Human Readable Output



### file
***
Returns File information and reputation.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of File Hashes (accepts MD5, SHA1, SHA256, SHA512). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.File.hash | String | The queried file hash. | 
| Synapse.File.MD5 | String | The MD5 hash of the file. | 
| Synapse.File.SHA1 | String | The SHA1 hash of the file. | 
| Synapse.File.SHA256 | String | The SHA256 hash of the file. | 
| Synapse.File.SHA512 | String | The SHA256 hash of the file. | 
| Synapse.File.query | String | The formatted query in storm syntax. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | String | For malicious files, the full description. | 
| DBotScore.Indicator | String | The value assigned by DBot for the indicator. | 
| DBotScore.Type | String | The type assigned by DBot for the indicator. | 
| DBotScore.Score | Number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 


#### Command Example
``` ```

#### Human Readable Output



### synapse-storm-query
***
Execute a Synapse Storm query.


#### Base Command

`synapse-storm-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Synapse storm query (i.e. "inet:ipv4=1.2.3.4") | Required | 
| limit | Limit the number of results returned. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Nodes.created | String | Timestamp when the node was first created in the Synapse Cortex. | 
| Synapse.Nodes.form | String | The type of node \(i.e. "inet:ipv4" for an IP address\). | 
| Synapse.Nodes.tags | String | The tags associated with the resulting node. | 
| Synapse.Nodes.valu | String | The node primary value \(i.e. "1.2.3.4" for an IP\). | 


#### Command Example
``` ```

#### Human Readable Output



### synapse-list-users
***
Lists current users in Synapse Cortex.


#### Base Command

`synapse-list-users`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Users.Admin | Boolean | True/False whether the Synapse user is an admin. | 
| Synapse.Users.Email | String | The email address of the Synapse user. | 
| Synapse.Users.Iden | String | The unique identifier of the Synapse user. | 
| Synapse.Users.Name | String | The user's Synapse username. | 
| Synapse.Users.Roles | String | The roles applied to the Synapse user. | 
| Synapse.Users.Rules | String | The rules applied to the Synapse user. | 


#### Command Example
``` ```

#### Human Readable Output



### synapse-list-roles
***
Lists current roles in Synapse Cortex.


#### Base Command

`synapse-list-roles`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Roles.Iden | String | The unique identifier of the Synapse Role. | 
| Synapse.Roles.Name | String | The name of the Synapse Role. | 
| Synapse.Roles.Rules | String | The rules applied to the Synapse Role. | 


#### Command Example
``` ```

#### Human Readable Output



### synapse-create-user
***
Create a new Synapse user.


#### Base Command

`synapse-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | New username to be created. | Required | 
| password | Optionally set the new user's password. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Users.Admin | Boolean | True/False whether the Synapse user is an admin. | 
| Synapse.Users.Email | String | The email address of the Synapse user. | 
| Synapse.Users.Iden | String | The unique identifier of the Synapse user. | 
| Synapse.Users.Name | String | The user's Synapse username. | 
| Synapse.Users.Roles | String | The roles applied to the Synapse user. | 
| Synapse.Users.Rules | String | The rules applied to the Synapse user. | 


#### Command Example
``` ```

#### Human Readable Output



### synapse-create-role
***
Create a new Synapse role.


#### Base Command

`synapse-create-role`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role | New role to create in Synapse. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Roles.Iden | String | The unique identifier of the Synapse Role. | 
| Synapse.Roles.Name | String | The name of the Synapse Role. | 
| Synapse.Roles.Rules | String | The rules applied to the Synapse Role. | 


#### Command Example
``` ```

#### Human Readable Output



### synapse-grant-user-role
***
Grants a user access to role based perrmissions.


#### Base Command

`synapse-grant-user-role`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User's "iden" property - not the username. | Required | 
| role | Role's "iden" property - not the name of the role. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Users.Admin | Boolean | True/False whether the Synapse user is an admin. | 
| Synapse.Users.Email | String | The email address of the Synapse user. | 
| Synapse.Users.Iden | String | The unique identifier of the Synapse user. | 
| Synapse.Users.Name | String | The user's Synapse username. | 
| Synapse.Users.Roles | String | The roles applied to the Synapse user. | 
| Synapse.Users.Rules | String | The rules applied to the Synapse user. | 


#### Command Example
``` ```

#### Human Readable Output



### synapse-query-model
***
Query the Synapse data model and return details for given type or form (i.e. "inet:ipv4" for an IPv4 IP address).


#### Base Command

`synapse-query-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Type/Form query (i.e. "inet:ipv4" or "inet"fqdn") | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Model.Doc | String | The docstring associated with the particular Synapse model element. | 
| Synapse.Model.Example | String | An example of the given Synapse element. | 
| Synapse.Model.Form | String | A form is the definition of an object in the Synapse data model \(node\). | 
| Synapse.Model.Properties | String | The unique properties associated with the given Synapse object. | 
| Synapse.Model.Type | String | A Type is the definition of a data element within the data model. | 
| Synapse.Model.Valu | String | The given value of the Synapse object type. | 


#### Command Example
``` ```

#### Human Readable Output


