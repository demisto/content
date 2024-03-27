Modernize Digital Forensics and Incident Response with Binalyze.Automate evidence and image acquisition and assigning triage  rule tasks. Isolate, reboot, shutdown,  retrieve logs, update version of your assets.
## Configure Binalyze Air on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Binalyze Air.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., https://&lt;host:port&gt;) | True |
    | API Key | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### binalyze-get-assets

***
Get Assets from Binalyze, if no filter is provided all assets are returned.

#### Base Command

`binalyze-get-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationid | The ID of the organization that you want to retrieve assets from. Default is 0. | Required | 
| searchterm | You may filter your search based on the string that you have provide in this argument, for instance you may provide device-name, ip address, tag, os type as an input to filter your results. | Optional | 

#### Context Output

There is no context output for this command.
### binalyze-get-drone-analyzers

***
Get Drone Analyzers from Binlayze Platform

#### Base Command

`binalyze-get-drone-analyzers`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### binalyze-get-tasks

***
Get tasks from the specified organization.

#### Base Command

`binalyze-get-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationid | Organization id to look for tasks in Binalyze AIR. Default is 0. | Required | 

#### Context Output

There is no context output for this command.
### binalyze-get-acquisition-profiles

***
Get Acquisition profiles in the specified organization.

#### Base Command

`binalyze-get-acquisition-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationid | Organization id to look for acquisition profiles in Binalyze AIR. Default is 0. | Required | 

#### Context Output

There is no context output for this command.
### binalyze-start-acquisition-webhook

***
You can use webhook to start acquisition by  specifying ip address of the client that you acquire and name of the webhook, the name of the webooh and the token is required as an input.

#### Base Command

`binalyze-start-acquisition-webhook`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipaddress | IP address that you want to start acquisiton via webhook. | Optional | 
| webhookname | the name of the webhook should not contain any space. Spaces should be replaced with '-' character. Example Webhook 1 should be written as Example-webook-1. | Required | 
| webhooktoken | Token value for webhook authentication. | Required | 

#### Context Output

There is no context output for this command.
### binalyze-assign-triage-task-by-filter

***
Assign a triage task to an asset/all assets. You can use input arguments to filter your triage assignees.

#### Base Command

`binalyze-assign-triage-task-by-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | The case id on Binalyze AIR. | Optional | 
| mitreattackenabled | Valid values are True,False. Possible values are: True, False. | Required | 
| managedstatus | The managed status of the asset on Binalyze AIR. Possible values are: managed, unmanaged, off-network. Default is managed. | Optional | 
| ipaddress | Fill this section empty if you do not want to filter results based on an ip address. | Optional | 
| Name | Name filter parameter while assigning triage task on Binalyze platform. | Optional | 
| SearchTerm | Search Filter for Triage Task, this seciton is optional. | Optional | 
| isolationstatus | Valid values are isolating,isolated,unisolating,unisolated. Possible values are: isolating, isolated, unsolating, unisolated. Default is unisolated. | Required | 
| triageruleids | Rule ids for Triage Rules that are on the Binalyze Platform. Specified rules will carry out the triage task on the defined hosts based on this parameter. | Optional | 
| platform | Valid values are windows,linux,darwin. Possible values are: windows, linux, darwin. Default is windows. | Optional | 
| tags | You may filter the search based on a tag, if no filter applied all tags will be contained in the search. | Optional | 
| includedendpointids | If no endpoint id is provided all endpoints will be included in the assets. | Optional | 
| organizationsIds | Id of the organization that you want to assign the triage task on Binalyze Platform. Default is 0. | Required | 

#### Context Output

There is no context output for this command.
### binalyze-get-users

***
Get Users from Binalyze AIR platform on the specified organization.

#### Base Command

`binalyze-get-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationid | None Default is 0. | Required | 

#### Context Output

There is no context output for this command.
### binalyze-create-case

***
Create Case on the Binalyze Platfrom based on the specified organization.

#### Base Command

`binalyze-create-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationid | The organization id that you want to create the case in. Default is 0. | Required | 
| casename | The Name of the Case that you want to create on Binalyze Platform. | Required | 
| owneruserid | Case creator user's owner id, you may get the owner id's by executing get users command. Default is OwOEWPR7rrf1eI7SbKGYtBIC. | Required | 

#### Context Output

There is no context output for this command.
### binalyze-get-cases

***
Get Cases from Binalyze Platform based on the specified organization id.

#### Base Command

`binalyze-get-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationid | The id field for an organization is required that you want to get the cases from. Default is 0. | Required | 

#### Context Output

There is no context output for this command.
### binalyze-get-triage-rules

***
Get triage rules from Binalyze AIR, you may filter the results based on your search.

#### Base Command

`binalyze-get-triage-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchterm | Search Term to look for in Triage Rules in Binalyze Platform. If this field is empty no filter will be applied and all triage rules will be returned. | Optional | 
| organizationid | Organization ID defined on the Binalyze AIR Platform. Default is 0. | Required | 

#### Context Output

There is no context output for this command.
### binalyze-assign-evidence-acquisition

***
Assign evidence acquisition task to an asset under the specified organization on Binalyze AIR.

#### Base Command

`binalyze-assign-evidence-acquisition`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | Case ID in Binalyze AIR. | Optional | 
| acquisitionProfileID | Binalyze Acquisition Profile ID. Default is full. | Required | 
| searchterm | filter search for the acquisition profiles. | Optional | 
| droneconfig_autopilot | Valid values are True or False. Default is True. | Required | 
| droneconfig_enabled | Default value is True. Possible values are: True, False. Default is True. | Optional | 
| droneconfig_analyzers | Some analyzer examples are "bha",       "wsa",       "aa",       "ara". | Optional | 
| droneconfig_keywords | Keywords for drone configuration parameters, an optional parameter. | Optional | 
| compression | Compression of the Acquistion File. Possible values are: True, False. Default is True. | Optional | 
| managedStatus | Valid values are managed,unmanaged,off-network. Possible values are: managed, unmanaged, off-network. Default is managed. | Optional | 
| isolationStatus | Valid values are isolating,isolated,unisolating,unisolated. Possible values are: isolating, isolated, unisolating, unisolated. Default is unisolated. | Optional | 
| platform | Valid values are windows,linux,darwin. Possible values are: windows, linux, darwin. Default is windows. | Optional | 
| ipAddress | Fill empty if this field if you do not want to filter your search for acquisition profile. | Optional | 
| organizationIds | OrganizationID parameter, default is 0. Define this parameter according which organizations you would like to assign the evidence acquisition task. Default is 0. | Required | 
| name | Name of the Acquisition Profile on Binalyze Platform. | Optional | 
| cpulimit | Task configuration to lmit optimal CPU usage while acquisition. Default is 25. | Required | 
| includedendpointids | If no endpoint id is provided all endpoints will be included in the assets. | Optional | 
| tags | You may filter the search based on a tag, if no filter applied all tags will be contained in the search. | Optional | 

#### Context Output

There is no context output for this command.
### binalyze-assign-shutdown-task

***
Assign shutdown task to an asset on Binalyze AIR.

#### Base Command

`binalyze-assign-shutdown-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Device Name of the Asset. | Optional | 
| ipAddress | If you do not specify any IP address, all ip addresses will be included in the specified organization for the reboot task. | Optional | 
| searchterm | Search term for assets, if not search term provided all asset results will be returned. | Optional | 
| organizationIds | OrganizationID parameter, default is 0. Define this parameter according which organizations you would like to assign the acquisition task. Default is 0. | Required | 

#### Context Output

There is no context output for this command.
### binalyze-assign-isolation-task

***
Assign isolation task to an asset on Binalyze AIR

#### Base Command

`binalyze-assign-isolation-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchterm | Search term for assets, if not search term provided all asset results will be returned. | Optional | 
| ipAddress | If you do not specify any IP address, all ip addresses will be included in the specified organization for the reboot task. | Optional | 
| organizationIds | OrganizationID parameter, default is 0. Define this parameter according which organizations you would like to assign the acquisition task. Default is 0. | Required | 
| name | Device Name of the Asset. | Optional | 

#### Context Output

There is no context output for this command.
### binalyze-assign-log-retrieval-task

***
Retrieve Logs from an asset on Binalyze AIR

#### Base Command

`binalyze-assign-log-retrieval-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchterm | Search term for assets, if not search term provided all asset results will be returned. | Optional | 
| ipAddress | If you do not specify any IP address, all ip addresses will be included in the specified organization for the reboot task. | Optional | 
| organizationIds | OrganizationID parameter, default is 0. Define this parameter according which organizations you would like to assign the log retrieval task. Default is 0. | Required | 
| name | Device Name of the Asset. | Optional | 
| tags | Tags attached to the assets on Binalyze AIR platform. | Optional | 

#### Context Output

There is no context output for this command.
### binalyze-assign-version-update-task

***
Update the version of your assets on your Binalyze AIR Platform

#### Base Command

`binalyze-assign-version-update-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchterm | Search term for assets, if no search term provided all asset results will be returned. | Optional | 
| ipAddress | If you do not specify any IP address, all ip addresses will be included in the specified organization for the reboot task. | Optional | 
| organizationIds | OrganizationID parameter, default is 0. Define this parameter according which organizations you would like to assign the acquisition task. Default is 0. | Required | 
| name | Device Name of the Asset. | Optional | 
| tags | Tags attached to the assets on Binalyze AIR platform. | Optional | 

#### Context Output

There is no context output for this command.
### binalyze-assign-reboot-task

***
Assign reboot task to an asset on Binalyze AIR platform.

#### Base Command

`binalyze-assign-reboot-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchterm | Search term for assets, if not search term provided all asset results will be returned. | Optional | 
| ipAddress | If you do not specify any IP address, all ip addresses will be included in the specified organization for the reboot task. | Optional | 
| organizationIds | OrganizationID parameter, default is 0. Define this parameter according which organizations you would like to assign the acquisition task. Default is 0. | Required | 
| name | Device Name of the Asset. | Optional | 
| tags | Tags attached to the assets on Binalyze AIR platform. | Optional | 

#### Context Output

There is no context output for this command.
### binalyze-assign-image-acquisition-task

***
Assign image acquisition task to an assets on Binalyze AIR platform.

#### Base Command

`binalyze-assign-image-acquisition-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| compression | Compression of the Image File. Possible values are: True, False. Default is True. | Required | 
| name | Device Name of the asset. | Optional | 
| ipAddress | IP address of the asset on Binalyze Platform. | Optional | 
| organizationid | OrganizationID parameter, default is 0. Define this parameter according which organizations you would like to assign the acquisition task. Default is 0. | Required | 
| platform | Valid values are windows,linux,darwin. Possible values are: windows, linux, darwin. Default is windows. | Optional | 
| tags | You may filter the search based on a tag, if no filter applied all tags will be contained in the search. | Optional | 
| EndpointId | The endpoint ID that you want take the image of on Binalyze AIR Platform. | Required | 
| EndpointVolume | Volume to take Image from the endpoint. | Required | 
| RepositoryID | The repository ID of the repository to save disk image. | Required | 
| RepositoryPath | The repository path to save the disk image. | Required | 
| caseid | Case ID on the Binalyze AIR. | Required | 

#### Context Output

There is no context output for this command.
