Microsoft 365 Defender is a unified pre- and post-breach enterprise defense suite that natively coordinates detection,
prevention, investigation, and response across endpoints, identities, email, and applications to provide integrated
protection against sophisticated attacks.

## Authentication Using the Device Code Flow
Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Microsoft 365 Defender with Cortex XSOAR.

To connect to the Microsoft 365 Defender:

1. Fill in the required parameters.
2. Run the ***!microsoft-365-defender-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!microsoft-365-defender-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

*Note: In case of a password change, the `microsoft-365-defender-auth-reset` command should be executed followed by the authentication process described above.*
### Cortex XSOAR App

In order to use the Cortex XSOAR application, use the default application ID.
```9093c354-630a-47f1-b087-6768eb9427e6```

### Self-Deployed Application - Device Code Flow

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. For more details, follow [Self Deployed Application - Device Code Flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow).

#### Required Permissions
The required API permissions are for the ***Microsoft Threat Protection*** app.
 * offline_access - Delegate
 * AdvancedHunting.Read - Delegated
 * Incident.ReadWrite.All - Application - See section 4 in [this article](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-user-context?view=o365-worldwide#create-an-app)
 * AdvancedHunting.Read.All - Application - See section 4 in [this article](https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-user-context?view=o365-worldwide#create-an-app)

## Self-Deployed Application - Client Credentials Flow

Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. In the instance configuration, select the ***client-credentials*** checkbox.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Client Secret*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.

#### Required Permissions
 * AdvancedHunting.Read.All - Application
 * Incident.ReadWrite.All - Application

## Configure Microsoft 365 Defender on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft 365 Defender.
3. Click **Add instance** to create and configure a new integration instance.
4. To ensure that mirroring works:
   1. Select  **Incident Mirroring Direction**. Choose the direction to mirror the incident: Incoming (from Microsoft 365 Defender to Cortex XSOAR), Outgoing (from Cortex XSOAR to Microsoft 365 Defender), or Incoming And Outgoing (from/to Cortex XSOAR and Microsoft 365 Defender).
   2. Select the **Fetches incidents** radio button.
   3. Under **Incident type**, select **Microsoft 365 Defender Incident**. 
   4. Under **Mapper (incoming)**, select **Microsoft 365 Defender - Incoming Mapper**.
   5. Under **Mapper (outgoing)**, select **Microsoft 365 Defender - Outgoing Mapper**.
   6. To enable mirroring to close a ticket in Cortex XSOAR, check the **Close Mirrored Cortex XSOAR Incidents** checkbox.
   7. To enable mirroring to close an incident in Microsoft 365 Defender, check the **Close Mirrored Microsoft 365 Defender Incidents** checkbox.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Endpoint URI | The United States: api-us.security.microsoft.com<br/>Europe: api-eu.security.microsoft.com<br/>The United Kingdom: api-uk.security.microsoft.co | True |
| ID or Client ID |  | False |
| Token or Tenant ID |  | False |
| Application ID | The API key to use to connect. | False |
| Use Client Credentials Authorization Flow | Use a self-deployed Azure application and authenticate using the Client Credentials flow. | False |
| Tenant ID (for Client Credentials mode) |  | False |
| Client Secret (for Client Credentials mode) |  | False |
| Client Secret |  | False |
| Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp; secrets" page of the app. | False |
| Private Key |  | False |
| Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp; secrets" page of the app. | False |
| Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
| Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
| Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Fetch incidents timeout | The time limit in seconds for fetch incidents to run. Leave this empty to cancel the timeout limit. | False |
| Number of incidents for each fetch. | Due to API limitations, the maximum is 100. | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Application ID (Deprecated) |  | False |
| Tenant ID (for Client Credentials mode) (Deprecated) |  | False |
| Client Secret (for Client Credentials mode) (Deprecated) |  | False |
| Incidents Fetch Interval |  | False |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from Microsoft 365 Defender to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to  Microsoft 365 Defender\), or Incoming and Outgoing \(from/to Cortex XSOAR and  Microsoft 365 Defender\). | False |
| Close Mirrored Cortex XSOAR Incidents | Incoming Mirroring - when selected, closing the Microsoft 365 Defender incident is mirrored in Cortex XSOAR. | False |
| Close Mirrored Microsoft 365 Defender Incidents | Outgoing Mirroring - when selected, closing the Cortex XSOAR incident is mirrored in Microsoft 365 Defender. | False |
| Comment Entry Tag To Microsoft 365 Defender | Choose a tag to add to an entry to mirror it as a comment into Microsoft 365 Defender. | False |
| Comment Entry Tag From Microsoft 365 Defender | Choose a tag to add to an entry to mirror it as a comment from Microsoft 365 Defender. | False |

5. Run the !microsoft-365-defender-auth-test command to validate the authentication process.

## Incident Mirroring

### Mirroring In (Microsoft 365 Defender → XSOAR)

When incidents are mirrored into XSOAR from Microsoft 365 Defender:

1. **Comments** mirrored from Microsoft 365 Defender will be added to the incident as entries in XSOAR and tagged with the **Comment Entry Tag From Microsoft 365 Defender**.  
   * By default, the tag is set to: `CommentFromMicrosoft365Defender`.  

2. If an incident is closed in Microsoft 365 Defender (`status` = **Resolved**) and Close Mirrored Cortex XSOAR Incidents is enabled:  
   * The **"classification"** field in Microsoft 365 Defender will be mapped to the **Close Reason** field in XSOAR.  


### Mirroring Out (XSOAR → Microsoft 365 Defender)

When incidents are mirrored out from XSOAR to Microsoft 365 Defender:

1. **Supported Fields**:  
   The following fields are mirrored:  
   * **Microsoft 365 Defender Status**  
   * **Assigned User**  
   * **Microsoft 365 Defender Classification**  
   * **Microsoft 365 Defender Tags**  

2. **Comments**:  
   * XSOAR entries with the **Comment Entry Tag To Microsoft 365 Defender** tag are mirrored as comments in Microsoft 365 Defender.  
   * **Note**: Comments cannot be edited or deleted in Microsoft 365 Defender, as this functionality is not supported.

3. If an incident is closed in XSOAR and Close Mirrored Microsoft 365 Defender Incidents is enabled:  
   * The **Close Reason** field is mirrored to the `status`, `classification` and `determination` fields in Microsoft 365 Defender.  


### Closing Logic

#### Incoming Closing Logic (Microsoft 365 Defender → XSOAR)

When an incident is resolved in Microsoft 365 Defender:

1. If the `status` = **Resolved**:  
   * The **"classification"** field will be mapped to the **Close Reason** field in XSOAR using the **Close Reason Mapping Table**.  
   * The **"classification"** and  **"determination"** fields will be mirrored into the **Microsoft 365 Defender Classification** field in XSOAR.

**Example**:  

* An incident closed in Microsoft 365 Defender with:  
  * `status` = **Resolved**
  * `Classification` = **True Positive**  
  * `Determination` = **Phishing**  

  Results in XSOAR:  
  * `Close Reason` = **Resolved**  
  * `Microsoft 365 Defender Classification` = **True Positive - Phishing**

**Close Reason Mapping Table (Incoming)**:

| Classification in Microsoft 365 Defender | Close Reason in XSOAR      |
|-----------------------------------------|----------------------------|
| Not set                                 | Other                      |
| True Positive                           | Resolved                   |
| False Positive                          | False Positive             |
| Informational / Expected Activity       | Resolved                   |


#### Outgoing Closing Logic (XSOAR → Microsoft 365 Defender)

Disclaimer: The closing form currently does not support the **Microsoft 365 Defender Classification** field, and False Positive Classification is not yet enforced when selecting "False Positive" as the close reason. 
If classification is required, please manually update the **Microsoft 365 Defender Classification** via the layout before closing the incident.

When closing incidents from XSOAR to Microsoft 365 Defender, the following logic is applied to map the **Close Reason** field:
1. **General Status Update**:  
   When an incident is marked as closed in XSOAR, the `status` field in Microsoft 365 Defender will always be set to **Resolved**.  

2. **Close Reason: Resolved or False Positive**  
  If the **Close Reason** in XSOAR is **Resolved**, the **Microsoft 365 Defender Classification** field is mirrored to classification and determination fields **as-is** into Microsoft 365 Defender without any changes.

3. **Close Reason: Other or Duplicate**  
   If the **Close Reason** in XSOAR is either **Other** or **Duplicate**, the following updates occur:  
   * **classification** → `Unknown`  
   * **determination** → `NotAvailable`  


**Close Reason Mapping Table (Outgoing)**:

| Close Reason in XSOAR | Classification in Microsoft 365 Defender | Determination in Microsoft 365 Defender | Status in Defender |
|-----------------------|------------------------------------------|-----------------------------------------|--------------------|
| Resolved              | Mirrored as-is                           | Mirrored as-is                          | Resolved           |
| FalsePositive         | FalsePositive                            | Mirrored as-is \ Other                  | Resolved           |
| Other                 | Unknown                                  | NotAvailable                            | Resolved           |
| Duplicate             | Unknown                                  | NotAvailable                            | Resolved           |



#### Notes

1. **Configuration Requirements for Closing Incidents**:  
   To close incidents in both directions, ensure the following settings in XSOAR:  
   * **Close Mirrored XSOAR Incident** checkbox = **True**  
   * **Close Mirrored Microsoft 365 Defender Incident** checkbox = **True**  

   If these checkboxes are **False**, only the `Microsoft 365 Defender Status` and `Microsoft 365 Defender Classification` fields will be updated, and incidents will not be closed.


### Configure Incident Mirroring

**This feature is compliant with XSOAR version 6.0 and above.**  
When mirroring incidents, you can make changes in Microsoft 365 Defender that will be reflected in Cortex XSOAR, or vice versa. 

The following instructions include steps for configuring the integration and incoming and outgoing mappers. However, they do not cover every option available in the integration nor classification and mapping features. 
For information about classification and mapping see [Classification and Mapping](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Classification-and-Mapping).  

**Note:**  

* For Cortex XSOAR version 6.1 only, the final source of truth for an incident are the values in Cortex XSOAR.  For example, if you change the severity in Cortex XSOAR and then change it back in Microsoft 365 Defender, the final value that will be presented is the one in Cortex XSOAR. For versions 6.2 and later, if mirroring is in both directions then the latest update is the source of truth. 
* The mirroring settings apply only for incidents that are fetched after applying the settings. 
* To use a custom mapper, you must first duplicate the mapper and edit the field in the copy of the mapper. If you detach the out of the box mapper and make changes to it, the pack does not automatically get updates.

#### STEP 1 - Configure the Microsoft 365 Defender Integration Instance for Mirroring.

1. Navigate to **Integrations** and search for ** Microsoft 365 Defender**.
2. Click **Add instance**.
3. Select **Fetches incidents**.
4. Select the **Incident Mirroring Direction**:  
   * **Incoming** - Mirrors changes on the Microsoft 365 Defender incident in to the Cortex XSOAR incident.
   * **Outgoing** - Mirrors changes on the Cortex XSOAR incident to the Microsoft 365 Defender incident.
   * **Incoming And Outgoing** - Mirrors changes both in and out on both incidents.
5. Under **Incident type**, select Microsoft 365 Defender Incident. 
6. Under **Mapper (incoming)**, for default mapping select Microsoft 365 Defender - Incoming Mapper. For custom mapping, follow the instructions in STEP 2 and then select the custom mapper name.
7. Under **Mapper (outgoing)**, for default mapping select Microsoft 365 Defender - Outgoing Mapper. For custom mapping, follow the instructions in STEP 3 and then select the custom mapper name.
8. Enter the relevant **Comment Entry Tag To Microsoft 365 Defender** and **Comment Entry Tag From Microsoft 365 Defender** values.  
These values are mapped to the **dbotMirrorTags** incident field in Cortex XSOAR, which defines how Cortex XSOAR handles comments when you tag them in the War Room. 
**Note:**  
These tags work only for mirroring comments from Cortex XSOAR to Microsoft 365 Defender.
9. To enable mirroring when closing an incident in Cortex XSOAR and Microsoft 365 Defender, select the **Close Mirrored Cortex XSOAR Incidents** and **Close Mirrored Microsoft 365 Defender Incidents** checkboxes respectively.
10. Click **Save & Exit**.

#### STEP 2 (Optional) Configure the Incoming Mapper by Incident Type

**Note:**
Any modifications require that the mappers be cloned before any changes can be applied.

1. Navigate to **Classification and Mapping** and for **Incidents** search for the **Microsoft 365 Defender - Incoming Mapper**.
2. Select it and click **Duplicate**.
3. Under the **Incident Type** dropdown, select Microsoft 365 Defender Incident.
4. Verify the mapper has these fields mapped. They will pull the values configured on the integration instance settings at the time of ingestion.
    * **dbotMirrorId** - dbotMirrorId - the field used by the third-party integration to identify the incident. This should be the incidentId of the Microsoft 365 Defender Incident.
    * **dbotMirrorDirection** - determines whether mirroring is incoming, outgoing, or both. Default is Both. This should match the instance configuration.        
    * **dbotMirrorInstance** - determines the Microsoft 365 Defender instance with which to mirror. This should match the instance configuration.
    * **dbotMirrorLastSync** - determines the field by which to indicate the last time that the systems synchronized.
    * **dbotMirrorTags** - determines the tags that you need to add in Cortex XSOAR for entries to be pushed to Microsoft 365 Defender. They should be copied from the tags in the instance configuration. These are also the tags that must be put on the War Room record in order for it to sync.


#### STEP 3 - Modify the Outgoing Mapper  

**Note:**  
Any modifications require that the mappers be cloned before any changes can be applied.

1. Navigate to **Classification and Mapping**, and for **Incidents** search for the **Microsoft 365 Defender - Outgoing Mapper.**
2. Select it and click **Duplicate**.  
  The left side of the screen shows the Microsoft 365 Defender fields to which to map and the right side of the
screen shows the Cortex XSOAR fields by which you are mapping.
3. Under the **Incident Type** dropdown, select the relevant incident type (for example **Microsoft 365 Defender Incident**).
4. Under **Schema Type**, select **incident**. The Schema Type represents the Microsoft 365 Defender entity that
you are mapping to.
5. On the right side of the screen, under **Incident**, select the incident based on which you want to
match.
6. Change the mapping according to your needs, including any fields you want mapped outward to Microsoft 365 Defender.
7. Save your changes.

#### STEP 4 - Create an Incident in Microsoft 365 Defender  

For purposes of this use case, it can be a simple incident. The new incident will be ingested in Cortex XSOAR in approximately one minute.

#### STEP 5 - Add a Comment from Cortex XSOAR to Microsoft 365 Defender

In the example below, we have written *A comment from Cortex XSOAR to Microsoft 365 Defender*.

1. Create an entry in the incidents' war room.
2. Click Actions > Tags and add the Comment Entry Tag To Microsoft 365 Defender tag.
3. Navigate back to the incident in Microsoft 365 Defender and within approximately one minute, the changes will be reflected there, too. The note is mirrored out as a comment in Microsoft 365 Defender.  
  You can make additional changes like closing the incident or changing the assignee and those will be reflected in both systems.


## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

### microsoft-365-defender-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results. (for device-code mode)


#### Base Command

`microsoft-365-defender-auth-start`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!microsoft-365-defender-auth-start```

#### Human Readable Output


>###Authorization instructions
>1. To sign in, use a web browser to open the page {URL}
>and enter the code {code} to authenticate.
>2. Run the !microsoft-365-defender-auth-complete command in the War Room.


### microsoft-365-defender-auth-complete

***
Run this command to complete the authorization process. Should be used after running the microsoft-365-defender-auth-start command. (for device-code mode)


#### Base Command

`microsoft-365-defender-auth-complete`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!microsoft-365-defender-auth-complete```

#### Human Readable Output

>✅ Authorization completed successfully.


### microsoft-365-defender-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`microsoft-365-defender-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!microsoft-365-defender-auth-reset```

#### Human Readable Output


>Authorization was reset successfully. 
>You can now run !microsoft-365-defender-auth-start and
>!microsoft-365-defender-auth-complete.



### microsoft-365-defender-auth-test
***
Tests the connectivity to the Microsoft 365 Defender.


#### Base Command

`microsoft-365-defender-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-365-defender-auth-test```

#### Human Readable Output
>✅ Success!


### microsoft-365-defender-incidents-list

***
Get the most recent incidents.

#### Base Command

`microsoft-365-defender-incidents-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Categorize incidents (as Active, Resolved, or Redirected). Possible values are: Active, Resolved, Redirected. | Optional | 
| assigned_to | Owner of the incident. | Optional | 
| limit | Number of incidents in the list. Maximum is 100. Default is 100. | Optional | 
| offset | Number of entries to skip. | Optional | 
| timeout | The time limit in seconds for the http request to run. Default is 30. | Optional | 
| odata | Filter incidents using odata query: https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-list-incidents?view=o365-worldwide. Example: `{"$filter":"lastUpdateTime gt 2022-08-29T06:00:00.29Z"}`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Microsoft365Defender.Incident.incidentId | Number | Incident's ID. | 
| Microsoft365Defender.Incident.redirectIncidentId | Unknown | Only populated in case an incident is grouped together with another incident, as part of the incident processing logic. | 
| Microsoft365Defender.Incident.incidentName | String | The name of the incident. | 
| Microsoft365Defender.Incident.createdTime | Date | The date and time \(in UTC\) the incident was created. | 
| Microsoft365Defender.Incident.lastUpdateTime | Date | The date and time \(in UTC\) the incident was last updated. | 
| Microsoft365Defender.Incident.assignedTo | String | Owner of the incident. | 
| Microsoft365Defender.Incident.classification | String | Specification of the incident. Possible values are: Unknown, FalsePositive, and TruePositive. | 
| Microsoft365Defender.Incident.determination | String | The determination of the incident. Possible values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, and Other. | 
| Microsoft365Defender.Incident.status | String | The current status of the incident. Possible values are: Active, Resolved, and Redirected. | 
| Microsoft365Defender.Incident.severity | String | Severity of the incident. Possible values are: UnSpecified, Informational, Low, Medium, and High. | 
| Microsoft365Defender.Incident.alerts | Unknown | List of alerts relevant for the incidents. | 
| Microsoft365Defender.Incident.tags | unknown | List of custom tags associated with an incident, for example to flag a group of incidents with a common characteristic. | 
| Microsoft365Defender.Incident.comments | unknown | List of comments created by secops when managing the incident, for example additional information about the classification selection. | 

#### Command Example

```!ms-365-defender-incidents-list status=Active limit=10 assigned_to=user```

#### Human Readable Output

>### Incidents:

>|Incident name|Tags|Severity|Incident ID|Categories|Impacted entities|Active alerts|Service sources|Detection sources|First activity|Last activity|Status|Assigned to|Classification|Device groups|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Automated investigation started manually on one endpoint | tag1, tag2 | Informational | 263 | SuspiciousActivity | user | 5 / 12 | MicrosoftDefenderForEndpoint | AutomatedInvestigation | 2021-03-22T12:34:31.8123759Z | 2021-03-22T12:59:07.526847Z | Active | email| Unknown | computer |
>| Impossible travel activity involving one user |  | Medium | 264 | InitialAccess | user | 1 / 1 | MicrosoftCloudAppSecurity | MCAS | 2021-04-05T06:56:06.833Z | 2021-04-05T15:34:25.736Z | Resolved | email | Unknown |  |



### microsoft-365-defender-incident-get
***
Get incident with the given ID.


#### Base Command

`microsoft-365-defender-incident-get`
#### Input

### microsoft-365-defender-incident-get

***
Gets the incident with the given ID.

#### Base Command

`microsoft-365-defender-incident-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Incident's ID. | Required | 
| timeout | The time limit in seconds for the http request to run. Default is 30. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Microsoft365Defender.Incident.incidentId | number | Incident's ID. | 
| Microsoft365Defender.Incident.redirectIncidentId | unknown | Only populated in case an incident is grouped together with another incident, as part of the incident processing logic. | 
| Microsoft365Defender.Incident.incidentName | string | The name of the incident. | 
| Microsoft365Defender.Incident.createdTime | date | The date and time \(in UTC\) the incident was created. | 
| Microsoft365Defender.Incident.tags | unknown | List of custom tags associated with an incident, for example to flag a group of incidents with a common characteristic. | 
| Microsoft365Defender.Incident.lastUpdateTime | date | The date and time \(in UTC\) the incident was last updated. | 
| Microsoft365Defender.Incident.assignedTo | string | Owner of the incident. | 
| Microsoft365Defender.Incident.classification | string | Specification of the incident. Possible values are: Unknown, FalsePositive, and TruePositive. | 
| Microsoft365Defender.Incident.determination | string | The determination of the incident. Possible values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, and Other. | 
| Microsoft365Defender.Incident.severity | string | Severity of the incident. Possible values are: UnSpecified, Informational, Low, Medium, and High. | 
| Microsoft365Defender.Incident.status | string | The current status of the incident. Possible values are: Active, Resolved, and Redirected. | 
| Microsoft365Defender.Incident.alerts | unknown | List of alerts relevant for the incidents. | 
| Microsoft365Defender.Incident.tags | unknown | List of custom tags associated with an incident, for example to flag a group of incidents with a common characteristic. | 
| Microsoft365Defender.Incident.comments | unknown | List of comments created by secops when managing the incident, for example additional information about the classification selection. | 

### microsoft-365-defender-incident-update

***
Update the incident with the given ID.

#### Base Command

`microsoft-365-defender-incident-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Categorize incidents (as Active, Resolved, or Redirected). Possible values are: Active, Resolved, Redirected, InProgress. | Optional | 
| assigned_to | Owner of the incident. | Optional | 
| id | Incident's ID. | Required | 
| classification | The specification for the incident. Possible values are: Unknown, FalsePositive, TruePositive, InformationalExpectedActivity. | Optional | 
| determination | Determination of the incident. Must be used with the classification field. Possible values depend on the classification field: TruePositive - MultiStagedAttack, MaliciousUserActivity, Malware, Phishing, CompromisedAccount, UnwantedSoftware, Other (default), InformationalExpectedActivity- SecurityTesting, LineOfBusinessApplication, ConfirmedActivity, Other (default), FalsePositive - NotMalicious, NoEnoughDataToValidate, Other (default), Unknown - NotAvailable. Possible values are: NotAvailable, Malware, SecurityTesting, UnwantedSoftware, MultiStagedAttack, MaliciousUserActivity, CompromisedAccount, Phishing, LineOfBusinessApplication, ConfirmedActivity, NotMalicious, Other. | Optional | 
| comment | Comment to be added to the incident. | Optional | 
| tags | A comma-separated list of custom tags associated with an incident. For example: tag1,tag2,tag3. | Optional | 
| timeout | The time limit in seconds for the http request to run. Default is 30. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Microsoft365Defender.Incident.incidentId | Number | Incident's ID. | 
| Microsoft365Defender.Incident.redirectIncidentId | Unknown | Only populated in case an incident is grouped together with another incident, as part of the incident processing logic. | 
| Microsoft365Defender.Incident.incidentName | String | The name of the incident. | 
| Microsoft365Defender.Incident.createdTime | Date | The date and time \(in UTC\) the incident was created. | 
| Microsoft365Defender.Incident.lastUpdateTime | Date | The date and time \(in UTC\) the incident was last updated. | 
| Microsoft365Defender.Incident.assignedTo | String | Owner of the incident. | 
| Microsoft365Defender.Incident.classification | String | Specification of the incident. Possible values are: Unknown, FalsePositive, and TruePositive. | 
| Microsoft365Defender.Incident.determination | String | The determination of the incident. Possible values are: NotAvailable, Apt, Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, and Other. | 
| Microsoft365Defender.Incident.severity | String | Severity of the incident. Possible values are: UnSpecified, Informational, Low, Medium, and High. | 
| Microsoft365Defender.Incident.status | String | The current status of the incident. Possible values are: Active, Resolved, and Redirected. | 
| Microsoft365Defender.Incident.alerts | Unknown | List of alerts relevant for the incidents. | 
| Microsoft365Defender.Incident.tags | unknown | List of custom tags associated with an incident, for example to flag a group of incidents with a common characteristic. | 
| Microsoft365Defender.Incident.comments | unknown | List of comments created by secops when managing the incident, for example additional information about the classification selection. | 



#### Command Example

```!microsoft-365-defender-incident-update id=264 tags=test5```

#### Human Readable Output

>### Updated incident No. 263:

>|Incident name|Tags|Severity|Incident ID|Categories|Impacted entities|Active alerts|Service sources|Detection sources|First activity|Last activity|Status|Assigned to|Classification|Device groups|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Automated investigation started manually on one endpoint | test5 | Informational | 263 | SuspiciousActivity |  | 10 / 12 | MicrosoftDefenderForEndpoint | AutomatedInvestigation | 2021-03-22T12:34:31.8123759Z | 2021-03-22T12:59:07.526847Z | Active | User | Unknown | computer |



### microsoft-365-defender-advanced-hunting

***
Advanced hunting is a threat-hunting tool that uses specially constructed queries to examine the past 30 days of event data in Microsoft 365 Defender.
Details on how to write queries you can find [here](https://docs.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language?view=o365-worldwide).

#### Base Command

`microsoft-365-defender-advanced-hunting`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Advanced hunting query. | Required | 
| timeout | The time limit in seconds for the http request to run. Default is 30. | Optional | 
| limit | Number of entries.  Enter -1 for unlimited query. Default is 50. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Microsoft365Defender.Hunt.query | String | The query used, also acted as a key. | 
| Microsoft365Defender.Hunt.results. | Unknown | The results of the query. | 


#### Command Example
```!microsoft-365-defender-advanced-hunting query=AlertInfo```

#### Human Readable Output
>###  Result of query: AlertInfo:
>|Timestamp|AlertId|Title|Category|Severity|ServiceSource|DetectionSource|AttackTechniques|
>|---|---|---|---|---|---|---|---|
>| 2021-04-25T10:11:00Z | alertId | eDiscovery search started or exported | InitialAccess | Medium | Microsoft Defender for Office 365 | Microsoft Defender for Office 365 |  |
### get-mapping-fields

***
Returns the list of fields to map in outgoing mirroring. This command is only used for debugging purposes.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### update-remote-system

***
Updates the remote incident with local incident changes. This method is only used for debugging purposes and will not update the current incident.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### get-remote-data

***
Get remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes only.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident ID. | Required | 
| lastUpdate | The UTC timestamp in seconds of the last update. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### get-modified-remote-data

***
Get the list of incidents that were modified since the last update time. This method is used for debugging purposes. The get-modified-remote-data command is used as part of the Mirroring feature that was introduced in Cortex XSOAR version 6.1.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Date string representing the local time. The incident is only returned if it was modified after the last update time. | Optional | 

#### Context Output

There is no context output for this command.
