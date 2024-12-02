Commvault Cloud provides pre-built integrations, automation workflows, and playbooks to streamline operations, enhance threat intelligence integration, and gain actionable insights through advanced reporting and analytics.
This integration was integrated and tested with version 6.9.0 of CommvaultSecurityIQ.

## Configure Commvault Cloud in Cortex


   | **Parameter**| **Required**|
   | ---| ---|
   | Long running instance| False|
   | Mapper (incoming)| True|
   | Commvault Webservice Url| True|
   | Commvault API Token| True|
   | Azure KeyVault Url| False|
   | Azure KeyVault Tenant ID| False|
   | Azure KeyVault Client ID| False|
   | Azure KeyVault Client Secret| False|
   | Port mapping (&lt;port&gt; or &lt;host port&gt;:&lt;docker port&gt;)| False|
   | Incident type| False|
   | Fetch incidents| False|
   | Incidents Fetch Interval| False|
   | Forwarding Rule| False|
   | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days)| False|
   | Max events to fetch| False|


##### Note :- If "Fetch Incidents" parameter is selected then make sure "Long running instance" capability of the integration is disabled.
##### Note :- Set Mapper (incoming) to "Commvault Suspicious File Activity Mapper"
## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### commvault-security-set-disable-data-aging

***
Disables data aging on CS

#### Base Command

`commvault-security-set-disable-data-aging`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CommvaultSecurityIQ.DisableDataAging | string | Status returned after calling disable data aging API | 

### commvault-security-get-generate-token

***
Generate Token

#### Base Command

`commvault-security-get-generate-token`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CommvaultSecurityIQ.GenerateToken | string | Status indicating whether successfully generated access token or not | 

### commvault-security-get-access-token-from-keyvault

***
Read the access token from KeyVault

#### Base Command

`commvault-security-get-access-token-from-keyvault`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CommvaultSecurityIQ.GetAccessToken | string | Status returned after getting the access token from KeyVault | 

### commvault-security-set-disable-saml-provider

***
Disable SAML provider

#### Base Command

`commvault-security-set-disable-saml-provider`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CommvaultSecurityIQ.DisableSaml | string | Status indicating whether successfully disabled SAML provider or not | 

### commvault-security-get-copy-files-list-to-war-room

***
Copy the list of affected files list to war room

#### Base Command

`commvault-security-get-copy-files-list-to-war-room`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### commvault-security-set-disable-user

***
Disables user

#### Base Command

`commvault-security-set-disable-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_email | Email id of the user to be disabled. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CommvaultSecurityIQ.DisableUser | string | Response indicating whether successfully disabled user or not. | 

### commvault-security-set-cleanroom-add-vm-to-recovery-group

***
Add VM to Cleanroom

#### Base Command

`commvault-security-set-cleanroom-add-vm-to-recovery-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm_name | VM name. | Required | 
| clean_recovery_point | Recovery point timestamp to which we add the VM. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CommvaultSecurityIQ.AddEntityToCleanroom | string | Response indicating whether successfully added the VM to the recovery point or not. | 