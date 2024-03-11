SafeBreach automatically executes thousands of breach methods from its extensive and growing Hacker’s Playbook™ to validate security control effectiveness. Simulations are automatically correlated with network, endpoint, and SIEM solutions providing data-driven SafeBreach Insights for holistic remediation to harden enterprise defenses.
This integration was integrated and tested with version 2024Q1.4 of Safebreach.

## Configure Safebreach on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Safebreach.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | This is base URL for your instance. | True |
    | API Key | This is API key for your instance, this can be created in Safe Breach User                      Administration -&amp;gt; API keys, it must be saved as there is no way to view it again. | True |
    | Password |  | True |
    | Account ID | This is account ID of account with which we want to get data from safebreach | True |
    | Verify SSL Certificate | This Field is useful for checking if the certificate of SSL for HTTPS is valid or not | False |
    | Use system proxy settings | This Field is useful for asking integration to use default system proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### safebreach-approve-simulator

***
This command approves the simulator with the specified simulator_id.

#### Base Command

`safebreach-approve-simulator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulator_id | ID of simulator to approve, in case unsure then please call safebreach-get-all-simulators and search for simulator name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Simulator.IsEnabled | String | Whether the simulator is enabled or not. | 
| SafeBreach.Simulator.SimulatorId | String | The Id of given simulator. | 
| SafeBreach.Simulator.Name | String | name for given simulator. | 
| SafeBreach.Simulator.AccountId | String | Account Id of account Hosting given simulator. | 
| SafeBreach.Simulator.IsCritical | String | Whether the simulator is critical. | 
| SafeBreach.Simulator.IsExfiltration | String | If Simulator is exfiltration target. | 
| SafeBreach.Simulator.IsInfiltration | String | If simulator is infiltration target. | 
| SafeBreach.Simulator.IsMailTarget | String | If simulator is mail target. | 
| SafeBreach.Simulator.IsMailAttacker | String | If simulator is mail attacker. | 
| SafeBreach.Simulator.IsPreExecutor | String | Whether the simulator is pre executor. | 
| SafeBreach.Simulator.IsAwsAttacker | String | if the given simulator is aws attacker. | 
| SafeBreach.Simulator.IsAzureAttacker | String | If the given simulator is azure attacker. | 
| SafeBreach.Simulator.ExternalIp | String | external ip of given simulator. | 
| SafeBreach.Simulator.InternalIp | String | internal ip of given simulator. | 
| SafeBreach.Simulator.IsWebApplicationAttacker | String | Whether the simulator is Web application attacker. | 
| SafeBreach.Simulator.PreferredInterface | String | Preferred simulator interface. | 
| SafeBreach.Simulator.PreferredIp | String | Preferred Ip of simulator. | 
| SafeBreach.Simulator.Hostname | String | Hostname of given simulator. | 
| SafeBreach.Simulator.ConnectionType | String | connection_type of given simulator. | 
| SafeBreach.Simulator.SimulatorStatus | String | status of the simulator. | 
| SafeBreach.Simulator.ConnectionStatus | String | connection status of simulator. | 
| SafeBreach.Simulator.SimulatorFrameworkVersion | String | Framework version of simulator. | 
| SafeBreach.Simulator.OperatingSystemType | String | operating system type of given simulator. | 
| SafeBreach.Simulator.OperatingSystem | String | Operating system of given simulator. | 
| SafeBreach.Simulator.ExecutionHostname | String | Execution Hostname of the given simulator. | 
| SafeBreach.Simulator.Deployments | String | deployments simulator is part of. | 
| SafeBreach.Simulator.CreatedAt | String | Creation datetime of simulator. | 
| SafeBreach.Simulator.UpdatedAt | String | Update datetime of given simulator. | 
| SafeBreach.Simulator.DeletedAt | String | deletion datetime of given simulator. | 
| SafeBreach.Simulator.Assets | String | Assets of given simulator. | 
| SafeBreach.Simulator.SimulationUsers | String | simulator users list. | 
| SafeBreach.Simulator.Proxies | String | Proxies of simulator. | 
| SafeBreach.Simulator.AdvancedActions | String | Advanced simulator details. | 

### safebreach-generate-api-key

***
This command creates an API key with the name and optionally the description provided. The API key created will be shown on the Settings > API Keys page of SafeBreach Management. Important: The API key generated can be seen only once, so it is recommended to store/save it in a safe place for further use.

#### Base Command

`safebreach-generate-api-key`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | <br/>                      Name of the API Key to create. This will be the name shown in UI for API key under API keys section<br/>                      . | Required | 
| description | <br/>                      Description of the API Key to create. This is not a required field but it is recommended to store a<br/>                      description for easier identification if your use case requires using multiple API keys for multiple tasks.<br/>                      . | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.GeneratedAPIKey.Name | String | The Name of API Key generated through this command,                           This will match the input name of the command. | 
| SafeBreach.GeneratedAPIKey.Description | String | The Description of API Key created.                           this will be same as input description given for the command. | 
| SafeBreach.GeneratedAPIKey.CreatedBy | String | The id of user who generated this API key. | 
| SafeBreach.GeneratedAPIKey.CreatedBt | String | The creation date and time of API key. | 
| SafeBreach.GeneratedAPIKey.Key | String | The value of API key generated. store this for further use as this will only be shown once | 

### safebreach-create-deployment

***
This command creates a deployment, grouping the list of simulators provided with a name and optionally a description.

#### Base Command

`safebreach-create-deployment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the deployment to create. this will be shown as name in deployments page of safebreach. | Required | 
| description | Description of the deployment to create. This will show as description of the deployment in your safebreach instance. It is generally preferable to give description while creating a deployment for easier identification. | Optional | 
| simulators | Deployment manages multiple simulators as single group. This parameter receives a comma separated list of IDs of all simulators that should be part of this deployment Simulator ID can be retrieved from safebreach-get-all-simulator-details . | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.CreateDeployment.Id | Number | The ID of deployment created. this Id can be used to update ,delete deployment as                      deployment_id field of the deployment. | 
| SafeBreach.CreateDeployment.AccountId | String | This field shows account ID of user who has created the account. | 
| SafeBreach.CreateDeployment.Name | String | The name of deployment created. this will be name which will be shown on deployments page                      of safebreach and name that is given as input to the command. | 
| SafeBreach.CreateDeployment.CreatedAt | String | The creation date and time of deployment , this will be closer to                      command execution time if the deployment creation is successful. | 
| SafeBreach.CreateDeployment.Description | String | The description of the deployment created will be shown in description                           part of the table in safebreach. | 
| SafeBreach.CreateDeployment.Simulators | String | The simulators that are part of deployment. | 

### safebreach-create-user

***
This command creates a user, including credentials and permissions.

#### Base Command

`safebreach-create-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the user to create. | Required | 
| email | Email of the user to Create. | Required | 
| is_active | If the user will be activated upon creation. Setting this parameter to 'true' active as soon as this command succeeds. Setting to 'false', will require to activate the user by an administrator. Possible values are: true, false. Default is true. Possible values are: true, false. Default is true. | Optional | 
| email_post_creation | Whether to send an email with login information to a newly crated user. Possible values are: true, false. Default is false. Possible values are: true, false. Default is true. | Optional | 
| password | Enforce password change on user creation. Possible values are: true, false. Default is false. | Required | 
| change_password_on_create | Should user change password on creation. when this is set to true then user will have to reset password on the next login, this can be used if we want user to reset password as soon as they login. Possible values are: true, false. Default is false. | Optional | 
| user_role | Role of the user being created. Possible values are: viewer, administrator, contentDeveloper, operator. Default is viewer. Possible values are: viewer, administrator, contentDeveloper, operator. Default is viewer. | Optional | 
| deployments | Comma separated ID of all deployments the user should be part of. The deployment IDs can be retrieved from 'list-deployments' command or from UI directly but care should be noted that only deployment ids of deployments which haven't been deleted will be shown here and after creation of user. for example if 1,2,3 are deployment ids given while creation but if 2 is deleted then when user is created , he will only have 1,3. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.CreatedUserData.Id | Number | The ID of User created. | 
| SafeBreach.CreatedUserData.Name | String | The name of User created. | 
| SafeBreach.CreatedUserData.Email | String | The email of User created. | 
| SafeBreach.CreatedUserData.Createdat | String | The creation time of User. | 
| SafeBreach.CreatedUserData.Roles | String | The roles and permissions of User created. | 
| SafeBreach.CreatedUserData.Description | String | The description of User if any is given at creation time, it will be populated here. | 
| SafeBreach.CreatedUserData.Role | String | The role assigned to user during creation. | 
| SafeBreach.CreatedUserData.Deployments | String | The deployments user is part of. | 

### safebreach-delete-api-key

***
This command deletes the API key with the name as specified in SafeBreach Management. It is not case sensitive.

#### Base Command

`safebreach-delete-api-key`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_name | Name of the API Key to Delete. This will be used for searching key with given name and then once it matches, that API key will be deleted. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.DeletedAPIKey.Name | Number | The Name of API Key deleted. | 
| SafeBreach.DeletedAPIKey.Description | String | Description of API Key deleted. | 
| SafeBreach.DeletedAPIKey.CreatedBy | String | The id of user who generated this API key. | 
| SafeBreach.DeletedAPIKey.CreatedAt | String | The creation time and date of API key. | 
| SafeBreach.DeletedAPIKey.DeletedAt | String | The deletion time and date of API key. The deletion date and time are generally                      close to the command execution time and date. | 

### safebreach-delete-deployment

***
This command deletes a deployment with the deployment_id (retrieved using the get-all-deployments command).

#### Base Command

`safebreach-delete-deployment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deployment_id | ID of the deployment to delete. The ID his can be searched with list-deployments command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.DeletedDeployment.Id | Number | The ID of deployment which has been deleted. | 
| SafeBreach.DeletedDeployment.AccountId | String | The account Id of user who deleted the deployment. | 
| SafeBreach.DeletedDeployment.Name | String | The name of deployment before the deployment was deleted. | 
| SafeBreach.DeletedDeployment.CreatedAt | String | The creation date and time of deployment which has been deleted. | 
| SafeBreach.DeletedDeployment.Description | String | The description of deployment before it was deleted. | 
| SafeBreach.DeletedDeployment.Simulators | String | The simulators that are part of deployment before it was deleted. | 

### safebreach-clear-integration-issues

***
This command deletes connector-related errors and warnings for the specified connector_id (retrieved using the get-all-integration-issues command).

#### Base Command

`safebreach-clear-integration-issues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The ID of Integration to have its errors/warnings deleted. Both errors and warnings will be deleted. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.ClearIntegrationIssues.Error | Number | Error count after deletion of errors for the given Integration. | 
| SafeBreach.ClearIntegrationIssues.Result | String | error deletion status whether true or false. | 

### safebreach-delete-scheduled-scenarios

***
This command deletes the scheduled scenario with the specified schedule_id.

#### Base Command

`safebreach-delete-scheduled-scenarios`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | schedule ID of scheduled scenario to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.DeletedScheduledScenario.Id | String | the Id of the scheduled scenario. | 
| SafeBreach.DeletedScheduledScenario.IsEnabled | Boolean | if scheduled scenario is enabled. | 
| SafeBreach.DeletedScheduledScenario.UserSchedule | String | the user readable form of the scheduled scenario. | 
| SafeBreach.DeletedScheduledScenario.RunDate | String | the run date of the scheduled scenario. | 
| SafeBreach.DeletedScheduledScenario.CronTimezone | String | the time zone of the scheduled scenario. | 
| SafeBreach.DeletedScheduledScenario.Description | String | the description of the scheduled scenario. | 
| SafeBreach.DeletedScheduledScenario.ScenarioId | String | the test ID of the scheduled scenario. | 
| SafeBreach.DeletedScheduledScenario.CreatedAt | String | the creation datetime of the scheduled scenario. | 
| SafeBreach.DeletedScheduledScenario.UpdatedAt | String | the updated datetime of the scheduled scenario. | 
| SafeBreach.DeletedScheduledScenario.DeletedAt | String | the deletion time of the scheduled scenario. | 

### safebreach-delete-simulator

***
This command deletes simulator with given ID.to get simulator_id use safebreach-get-all-simulators command.

#### Base Command

`safebreach-delete-simulator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulator_id | Id of the simulator we want to delete. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.DeletedSimulator.IsEnabled | String | Whether the simulator is enabled or not. | 
| SafeBreach.DeletedSimulator.SimulatorId | String | The Id of given simulator. | 
| SafeBreach.DeletedSimulator.Name | String | name for given simulator. | 
| SafeBreach.DeletedSimulator.AccountId | String | Account Id of account Hosting given simulator. | 
| SafeBreach.DeletedSimulator.IsCritical | String | Whether the simulator is critical. | 
| SafeBreach.DeletedSimulator.IsExfiltration | String | If Simulator is exfiltration target. | 
| SafeBreach.DeletedSimulator.IsInfiltration | String | If simulator is infiltration target. | 
| SafeBreach.DeletedSimulator.IsMailTarget | String | If simulator is mail target. | 
| SafeBreach.DeletedSimulator.IsMailAttacker | String | If simulator is mail attacker. | 
| SafeBreach.DeletedSimulator.IsPreExecutor | String | Whether the simulator is pre executor. | 
| SafeBreach.DeletedSimulator.IsAwsAttacker | String | if the given simulator is aws attacker. | 
| SafeBreach.DeletedSimulator.IsAzureAttacker | String | If the given simulator is azure attacker. | 
| SafeBreach.DeletedSimulator.ExternalIp | String | external ip of given simulator. | 
| SafeBreach.DeletedSimulator.InternalIp | String | internal ip of given simulator. | 
| SafeBreach.DeletedSimulator.IsWebApplicationAttacker | String | Whether the simulator is Web application attacker. | 
| SafeBreach.DeletedSimulator.PreferredInterface | String | Preferred simulator interface. | 
| SafeBreach.DeletedSimulator.PreferredIp | String | Preferred Ip of simulator. | 
| SafeBreach.DeletedSimulator.Hostname | String | Hostname of given simulator. | 
| SafeBreach.DeletedSimulator.ConnectionType | String | connection_type of given simulator. | 
| SafeBreach.DeletedSimulator.SimulatorStatus | String | status of the simulator. | 
| SafeBreach.DeletedSimulator.ConnectionStatus | String | connection status of simulator. | 
| SafeBreach.DeletedSimulator.SimulatorFrameworkVersion | String | Framework version of simulator. | 
| SafeBreach.DeletedSimulator.OperatingSystemType | String | operating system type of given simulator. | 
| SafeBreach.DeletedSimulator.OperatingSystem | String | Operating system of given simulator. | 
| SafeBreach.DeletedSimulator.ExecutionHostname | String | Execution Hostname of the given simulator. | 
| SafeBreach.DeletedSimulator.Deployments | String | deployments simulator is part of. | 
| SafeBreach.DeletedSimulator.CreatedAt | String | Creation datetime of simulator. | 
| SafeBreach.DeletedSimulator.UpdatedAt | String | Update datetime of given simulator. | 
| SafeBreach.DeletedSimulator.DeletedAt | String | deletion datetime of given simulator. | 
| SafeBreach.DeletedSimulator.Assets | String | Assets of given simulator. | 
| SafeBreach.DeletedSimulator.SimulationUsers | String | simulator users list. | 
| SafeBreach.DeletedSimulator.Proxies | String | Proxies of simulator. | 
| SafeBreach.DeletedSimulator.AdvancedActions | String | Advanced simulator details. | 

### safebreach-delete-test-with-id

***
This command deletes tests with given test ID.

#### Base Command

`safebreach-delete-test-with-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| test_id | Id of test to be deleted. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.DeletedTest.ScenarioId | String | scenario ID of the test. | 
| SafeBreach.DeletedTest.SimulationName | String | Name of the simulation. | 
| SafeBreach.DeletedTest.SecurityActionPerControl | String | Security Actions of the simulation. | 
| SafeBreach.DeletedTest.TestId | String | Test id of the test. | 
| SafeBreach.DeletedTest.Status | String | status of the test. | 
| SafeBreach.DeletedTest.PlannedSimulationsAmount | String | Planned simulations count of the test. | 
| SafeBreach.DeletedTest.SimulatorExecutions | String | simulator executions of the test. | 
| SafeBreach.DeletedTest.AttackExecutions | String | list of attacks that are part of the simulation. | 
| SafeBreach.DeletedTest.RanBy | String | user who started the simulation. | 
| SafeBreach.DeletedTest.SimulatorCount | String | simulators count per account. | 
| SafeBreach.DeletedTest.EndTime | String | End Time of the test. | 
| SafeBreach.DeletedTest.StartTime | String | start time of the test. | 
| SafeBreach.DeletedTest.finalStatus.stopped | String | stopped count of attacks. | 
| SafeBreach.DeletedTest.finalStatus.missed | String | missed count of attacks. | 
| SafeBreach.DeletedTest.finalStatus.logged | String | logged count of attacks. | 
| SafeBreach.DeletedTest.finalStatus.detected | String | detected count of attacks. | 
| SafeBreach.DeletedTest.finalStatus.prevented | String | prevented count of attacks. | 

### safebreach-delete-user

***
This command deletes a user with given data.

#### Base Command

`safebreach-delete-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | ID of user to be deleted. The Id can be retrieved by using get-all-users command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.DeletedUserData.Id | Number | The ID of User whose data has been deleted. | 
| SafeBreach.DeletedUserData.Name | String | The name of User deleted. | 
| SafeBreach.DeletedUserData.Email | String | The email of User deleted. | 
| SafeBreach.DeletedUserData.Createdat | String | the time at which the user who has been selected has been created | 
| SafeBreach.DeletedUserData.Updatedat | String | last updated time. | 
| SafeBreach.DeletedUserData.Deletedat | String | Deletion time of user. | 
| SafeBreach.DeletedUserData.Roles | String | The roles of User before they were deleted. | 
| SafeBreach.DeletedUserData.Description | String | The description of User who has been deleted. | 
| SafeBreach.DeletedUserData.Role | String | The roles and permissions of User who has been deleted. | 
| SafeBreach.DeletedUserData.Deployments | String | The deployments related to user before he was deleted. | 

### safebreach-get-integration-issues

***
This command gives all integrations related issues and warning. this will show the integrations error and warnings which are generally displayed in installed integrations page.

#### Base Command

`safebreach-get-integration-issues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| error_type | this will help see issues which are either errors or warnings or both based on the input . Possible values are: , ERROR, WARNING. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.IntegrationErrors.IntegrationId | Number | The ID of Integration. A general notation that has been followed here is                      as follows, if the  id has _default at the end then its a default connector else its a custom connector | 
| SafeBreach.IntegrationErrors.IntegrationName | String | Name of the integration | 
| SafeBreach.IntegrationErrors.Action | String | The action of Integration error. This describes where exactly did the error occur,                        if its search,then it implies error/warning happened when connector was trying that process | 
| SafeBreach.IntegrationErrors.SuccessState | String | status of integration error. This implies whether the connector was able to                       successfully perform the operation or if it failed partway.                       So false implies it failed partway and true implies it was successfully completed | 
| SafeBreach.IntegrationErrors.ErrorDescription | String | This is the exact error description shown on safebreach integration error/warning page.                        This description can be used for understanding of what exactly happened for the integration to fail. | 
| SafeBreach.IntegrationErrors.Timestamp | String | Time at which error/warning occurred. This can be used to pinpoint error which occurred                      across integrations if time of origin was remembered | 

### safebreach-get-running-simulations

***
This command gets simulations which are in running or queued state.

#### Base Command

`safebreach-get-running-simulations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.ActiveSimulations.test id | String | this is test ID of the simulation. | 
| SafeBreach.ActiveSimulations.SimulationId | String | the simulation id of the simulation. | 
| SafeBreach.ActiveSimulations.AttackId | String | the attack ID of the simulation. | 

### safebreach-get-running-tests

***
This command gets tests which are in running state.

#### Base Command

`safebreach-get-running-tests`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.ActiveTest.Id | Number | Id of Actively running test. | 
| SafeBreach.ActiveTest.Name | String | Name of the test being run. | 
| SafeBreach.ActiveTest.Description | String | Details related to the test being run. | 
| SafeBreach.ActiveTest.SuccessCriteria | String | success criterion for the test. | 
| SafeBreach.ActiveTest.OriginalScenarioId | String | Original scenario ID of the running test | 
| SafeBreach.ActiveTest.ActionsCount | String | number of actions | 
| SafeBreach.ActiveTest.EdgesCount | String | number of edges. | 
| SafeBreach.ActiveTest.CreatedAt | String | details related to when test is created. | 
| SafeBreach.ActiveTest.UpdatedAt | String | details related to when test is last updated/changed | 
| SafeBreach.ActiveTest.StepsCount | String | number of steps in simulator. | 
| SafeBreach.ActiveTest.ScenarioId | String | scenario_id of the test. | 
| SafeBreach.ActiveTest.OriginalScenarioId | String | scenario_id for reference. | 
| SafeBreach.ActiveTest.RanBy | String | User who ran the scenario. | 
| SafeBreach.ActiveTest.RanFrom | String | Where the test ran from. | 
| SafeBreach.ActiveTest.TestId | String | test id of the test. | 
| SafeBreach.ActiveTest.Priority | String | priority of tests. | 
| SafeBreach.ActiveTest.RetrySimulations | String | Should simulations be retried | 
| SafeBreach.ActiveTest.PauseDuration | String | is the test paused and if so till when | 
| SafeBreach.ActiveTest.PausedDate | String | when the test is paused | 
| SafeBreach.ActiveTest.ExpectedSimulationsAmount | String | number of simulations expected | 
| SafeBreach.ActiveTest.DispatchedSimulationsAmount | String | the number of simulations dispatched | 
| SafeBreach.ActiveTest.SkippedSimulationsAmount | String | The number of simulations skipped | 
| SafeBreach.ActiveTest.FailedSimulationsAmount | String | The number of simulations failed | 

### safebreach-get-available-simulator-details

***
This command to get all available simulators. if details is set to true then it retrieves simulator details like name, hostname, internal and external ips, types of targets and attacker configurations this simulator is associated with etc. if its set to false then it retrieves just name, id, simulation users, proxies etc. if deleted is set to true then it retrieves the data which has been deleted.

#### Base Command

`safebreach-get-available-simulator-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | if hostname to be included for search. | Optional | 
| external_ip | if external IP details to be included for search. | Optional | 
| internal_ip | if Internal IP are to be included for search. | Optional | 
| os | operating system name to filter with, Eg: LINUX,WINDOWS etc, incase nothing is selected then this will be set as empty which means all are retrieved. Possible values are: , LINUX, MAC, WINDOWS. | Optional | 
| is_enabled | if to search only enabled ones. Possible values are: true, false. | Optional | 
| is_connected | status of connection of simulators to search. Possible values are: true, false. | Optional | 
| is_critical | whether to search only for critical simulators or not. Possible values are: true, false. | Optional | 
| additional_details | Whether to show additional details or not. Possible values are: true, false. | Optional | 
| status | if simulator status are to be included for search. Possible values are: APPROVED, PENDING, ALL. Default is ALL. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Simulator.IsEnabled | String | Whether the simulator is enabled or not. | 
| SafeBreach.Simulator.SimulatorId | String | The Id of given simulator. | 
| SafeBreach.Simulator.Name | String | name for given simulator. | 
| SafeBreach.Simulator.AccountId | String | Account Id of account Hosting given simulator. | 
| SafeBreach.Simulator.IsCritical | String | Whether the simulator is critical. | 
| SafeBreach.Simulator.IsExfiltration | String | If Simulator is exfiltration target. | 
| SafeBreach.Simulator.IsInfiltration | String | If simulator is infiltration target. | 
| SafeBreach.Simulator.IsMailTarget | String | If simulator is mail target. | 
| SafeBreach.Simulator.IsMailAttacker | String | If simulator is mail attacker. | 
| SafeBreach.Simulator.IsPreExecutor | String | Whether the simulator is pre executor. | 
| SafeBreach.Simulator.IsAwsAttacker | String | if the given simulator is aws attacker. | 
| SafeBreach.Simulator.IsAzureAttacker | String | If the given simulator is azure attacker. | 
| SafeBreach.Simulator.ExternalIp | String | external ip of given simulator. | 
| SafeBreach.Simulator.InternalIp | String | internal ip of given simulator. | 
| SafeBreach.Simulator.IsWebApplicationAttacker | String | Whether the simulator is Web application attacker. | 
| SafeBreach.Simulator.PreferredInterface | String | Preferred simulator interface. | 
| SafeBreach.Simulator.PreferredIp | String | Preferred Ip of simulator. | 
| SafeBreach.Simulator.Hostname | String | Hostname of given simulator. | 
| SafeBreach.Simulator.ConnectionType | String | connection_type of given simulator. | 
| SafeBreach.Simulator.SimulatorStatus | String | status of the simulator. | 
| SafeBreach.Simulator.ConnectionStatus | String | connection status of simulator. | 
| SafeBreach.Simulator.SimulatorFrameworkVersion | String | Framework version of simulator. | 
| SafeBreach.Simulator.OperatingSystemType | String | operating system type of given simulator. | 
| SafeBreach.Simulator.OperatingSystem | String | Operating system of given simulator. | 
| SafeBreach.Simulator.ExecutionHostname | String | Execution Hostname of the given simulator. | 
| SafeBreach.Simulator.Deployments | String | deployments simulator is part of. | 
| SafeBreach.Simulator.CreatedAt | String | Creation datetime of simulator. | 
| SafeBreach.Simulator.UpdatedAt | String | Update datetime of given simulator. | 
| SafeBreach.Simulator.DeletedAt | String | deletion datetime of given simulator. | 
| SafeBreach.Simulator.Assets | String | Assets of given simulator. | 
| SafeBreach.Simulator.SimulationUsers | String | simulator users list. | 
| SafeBreach.Simulator.Proxies | String | Proxies of simulator. | 
| SafeBreach.Simulator.AdvancedActions | String | Advanced simulator details. | 

### safebreach-get-tests

***
This command gets tests with given modifiers.

#### Base Command

`safebreach-get-tests`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Test.ScenarioId | String | scenario ID of the test. | 
| SafeBreach.Test.SimulationName | String | Name of the simulation. | 
| SafeBreach.Test.SecurityActionPerControl | String | Security Actions of the simulation. | 
| SafeBreach.Test.TestId | String | Test id of the test. | 
| SafeBreach.Test.Status | String | status of the test. | 
| SafeBreach.Test.PlannedSimulationsAmount | String | Planned simulations count of the test. | 
| SafeBreach.Test.SimulatorExecutions | String | simulator executions of the test. | 
| SafeBreach.Test.AttackExecutions | String | list of attacks that are part of the simulation. | 
| SafeBreach.Test.RanBy | String | user who started the simulation. | 
| SafeBreach.Test.SimulatorCount | String | simulators count per account. | 
| SafeBreach.Test.EndTime | String | End Time of the test. | 
| SafeBreach.Test.StartTime | String | start time of the test. | 
| SafeBreach.Test.finalStatus.stopped | String | stopped count of attacks. | 
| SafeBreach.Test.finalStatus.missed | String | missed count of attacks. | 
| SafeBreach.Test.finalStatus.logged | String | logged count of attacks. | 
| SafeBreach.Test.finalStatus.detected | String | detected count of attacks. | 
| SafeBreach.Test.finalStatus.prevented | String | prevented count of attacks. | 

### safebreach-get-tests-with-scenario-id

***
This command gets tests with given scenario ID as part of it.

#### Base Command

`safebreach-get-tests-with-scenario-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scenario_id | Scenario Id for test which has to be filtered. this can be found on UI, if unsure about this then please run safebreach-get-tests instead of this with same parameters as inputs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Test.ScenarioId | String | scenario ID of the test. | 
| SafeBreach.Test.SimulationName | String | Name of the simulation. | 
| SafeBreach.Test.SecurityActionPerControl | String | Security Actions of the simulation. | 
| SafeBreach.Test.TestId | String | Test id of the test. | 
| SafeBreach.Test.Status | String | status of the test. | 
| SafeBreach.Test.PlannedSimulationsAmount | String | Planned simulations count of the test. | 
| SafeBreach.Test.SimulatorExecutions | String | simulator executions of the test. | 
| SafeBreach.Test.AttackExecutions | String | list of attacks that are part of the simulation. | 
| SafeBreach.Test.RanBy | String | user who started the simulation. | 
| SafeBreach.Test.SimulatorCount | String | simulators count per account. | 
| SafeBreach.Test.EndTime | String | End Time of the test. | 
| SafeBreach.Test.StartTime | String | start time of the test. | 
| SafeBreach.Test.finalStatus.stopped | String | stopped count of attacks. | 
| SafeBreach.Test.finalStatus.missed | String | missed count of attacks. | 
| SafeBreach.Test.finalStatus.logged | String | logged count of attacks. | 
| SafeBreach.Test.finalStatus.detected | String | detected count of attacks. | 
| SafeBreach.Test.finalStatus.prevented | String | prevented count of attacks. | 

### safebreach-get-all-users

***
This command gives all users who are not deleted.

#### Base Command

`safebreach-get-all-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.UserData.Id | Number | The ID of User retrieved. this can be used to further link this user with                      user_id field of safebreach-update-user or safebreach-delete-user commands | 
| SafeBreach.UserData.Name | String | The name of User retrieved. | 
| SafeBreach.UserData.Email | String | The email of User retrieved. this can be used for updating user or                      deleting user for input email of commands safebreach-update-user or safebreach-delete-user  | 

### safebreach-get-custom-scenarios

***
This command  retrieves scenarios which are saved by user as custom scenarios. they generally have configurations and everything set up and will be ready to run as tests

#### Base Command

`safebreach-get-custom-scenarios`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_details | Details of custom scenarios (My scenarios). Possible values are: false, true. Default is true. Possible values are: false, true. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.CustomScenario.Id | String | the Id of scenario. | 
| SafeBreach.CustomScenario.Name | String | the name of the scenario. | 
| SafeBreach.CustomScenario.Description | String | the description of the scenario. | 
| SafeBreach.CustomScenario.SuccessCriteria | String | success criteria the scenario. | 
| SafeBreach.CustomScenario.OriginalScenarioId | String | original scenario id of scenario. | 
| SafeBreach.CustomScenario.ActionsList | String | actions list of the scenario. | 
| SafeBreach.CustomScenario.EdgesCount | String | edges_count for the scenario. | 
| SafeBreach.CustomScenario.StepsOrder | String | the order of steps of the scenario. | 
| SafeBreach.CustomScenario.CreatedAt | String | the creation datetime of the scenario. | 
| SafeBreach.CustomScenario.UpdatedAt | String | the last updated time the scenario. | 

### safebreach-list-deployments

***
This command gets all deployments present for this instance.

#### Base Command

`safebreach-list-deployments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Deployment.Id | Number | The ID of deployment | 
| SafeBreach.Deployment.AccountId | String | The accountId of user who created the deployment. | 
| SafeBreach.Deployment.Name | String | The name of deployment.                        this will be the name shown in deployment name field of table in deployments page in safebreach UI | 
| SafeBreach.Deployment.CreatedAt | String | The creation date and time of deployment. | 
| SafeBreach.Deployment.UpdatedAt | String | The last updated date and time of deployment. | 
| SafeBreach.Deployment.Description | String | This is description field of deployments table of safebreach UI | 
| SafeBreach.Deployment.Simulators | String | The simulators that are part of deployment. | 

### safebreach-get-indicators

***
This command fetches SafeBreach Insights from which indicators are extracted,  creating new indicators or updating existing indicators.

#### Base Command

`safebreach-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| test_id | Test ID of the insight. | Required | 
| limit | The maximum number of indicators to  generate. The default is 1000. | Optional | 
| insightCategory | Multi-select option for the category of the insights to get remediation data  for:Network Access, Network Inspection, Endpoint, Email, Web, Data Leak. | Optional | 
| insightDataType | Multi-select option for the remediation data type to get:  Hash, Domain, URI, Command, Port, Protocol, Registry. | Optional | 
| behavioralReputation | Select option for the category of behavioral reputation. | Optional | 
| nonBehavioralReputation | Select option for the category of non-behavioral reputation. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Indicator.Value | String | The value of the indicator | 
| SafeBreach.Indicator.Type | String | The type of the indicator | 
| SafeBreach.Indicator.rawJSON.dataType | String | The data type of the indicator | 
| SafeBreach.Indicator.rawJSON.insightTime | String | The time of the insight | 
| SafeBreach.Indicator.rawJSON.value | String | The data type value of the indicator | 
| SafeBreach.Indicator.fields.description | String | The description of the indicator | 
| SafeBreach.Indicator.fields.safebreachseverity | String | The severity of the indicator | 
| SafeBreach.Indicator.fields.safebreachseverityscore | String | The severity score of the indicator | 
| SafeBreach.Indicator.fields.safebreachisbehavioral | Boolean | The behavioral of the indicator | 
| SafeBreach.Indicator.fields.safebreachattackids | Unknown | The attack ids of the indicator | 
| SafeBreach.Indicator.fields.port | String | The port of the indicator | 
| SafeBreach.Indicator.fields.tags | String | The tags of the indicator | 
| SafeBreach.Indicator.Score | Number | The score of the indicator | 

### safebreach-get-simulator-download-links

***
This command gets a list of links for download (item per operating system) for the latest available version.

#### Base Command

`safebreach-get-simulator-download-links`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.InstallationLinks.md5 | String | The MD5 generated from the contents of the file | 
| SafeBreach.InstallationLinks.Os | String | The operating system for which the update is intended | 
| SafeBreach.InstallationLinks.sha1 | String | The sha1 generated from the contents of the file. | 
| SafeBreach.InstallationLinks.sha256 | String | The sha256 generated from the contents of the file. | 
| SafeBreach.InstallationLinks.sha512 | String | The sha512 generated from the contents of the file. | 
| SafeBreach.InstallationLinks.sha512 | String | The sha512 generated from the contents of the file. | 
| SafeBreach.InstallationLinks.Url | String | The URL from which update can be downloaded. | 
| SafeBreach.InstallationLinks.Version | String | This indicates the simulator version. | 

### safebreach-get-prebuilt-scenarios

***
This command gets scenarios which are built by safebreach. They will be available by default even in new instance of your safebreach instance. They can be modified and saved as custom scenarios or used as it is.

#### Base Command

`safebreach-get-prebuilt-scenarios`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.PrebuiltScenario.Id | String | the Id of scenario. | 
| SafeBreach.PrebuiltScenario.Name | String | the name of the scenario. | 
| SafeBreach.PrebuiltScenario.Description | String | the description of the scenario. | 
| SafeBreach.PrebuiltScenario.CreatedBy | String | user id of user, who created the scenario. | 
| SafeBreach.PrebuiltScenario.CreatedAt | String | creation datetime of scenario. | 
| SafeBreach.PrebuiltScenario.UpdatedAt | String | the update datetime of the scenario. | 
| SafeBreach.PrebuiltScenario.Recommended | String | the recommendation status of the scenario. | 
| SafeBreach.PrebuiltScenario.TagsList | String | the tags related to the scenario. | 
| SafeBreach.PrebuiltScenario.Categories | String | the category ids of the scenario. | 
| SafeBreach.PrebuiltScenario.StepsOrder | String | the order of steps involved in the scenario. | 
| SafeBreach.PrebuiltScenario.Order | String | the order of execution related to the scenario. | 
| SafeBreach.PrebuiltScenario.MinApiVer | String | the minimum version of API required for scenario to be executed | 

### safebreach-get-scheduled-scenarios

***
This command retrieves schedules from safebreach which user has set and they will display it to user. By default Name is not shown, to retrieve and see it, please run 'safebreach-get-custom-scenarios' command to find name of scenario to which the schedule is associated with.

#### Base Command

`safebreach-get-scheduled-scenarios`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Schedules.Id | String | the Id of the schedule. | 
| SafeBreach.Schedules.IsEnabled | Boolean | if simulation is enabled. | 
| SafeBreach.Schedules.UserSchedule | String | the user readable form of the schedule. | 
| SafeBreach.Schedules.RunDate | String | the run date of the schedule. | 
| SafeBreach.Schedules.CronTimezone | String | the time zone of the schedule. | 
| SafeBreach.Schedules.Description | String | the description of the schedule. | 
| SafeBreach.Schedules.ScenarioId | String | the matrix ID of the schedule. | 
| SafeBreach.Schedules.CreatedAt | String | the creation datetime of the schedule. | 
| SafeBreach.Schedules.UpdatedAt | String | the updated datetime of the schedule. | 
| SafeBreach.Schedules.DeletedAt | String | the deletion time of the schedule. | 

### safebreach-get-services-status

***
This command retrieves status of services from safebreach and shows them as table for user, incase they are down then from when they are down or when it was last up will also be shown here.

#### Base Command

`safebreach-get-services-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.ServiceStatus.Name | String | the name of the service. | 
| SafeBreach.ServiceStatus.Version | String | version of the service. | 
| SafeBreach.ServiceStatus.connection status | String | connection status of service. | 
| SafeBreach.ServiceStatus.Error | String | error status of service. | 

### safebreach-get-simulations

***
This command is used to get simulations and their data related to a given test, this can be used as predecessor command to rerun-simulations command for easier queueing of simulations. This command does not have any limiters with pagination implemented so there might be huge data retrieved.

#### Base Command

`safebreach-get-simulations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| test_id | This is ID of the test whose simulations will be retrieved. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Simulation.SimulationId | String | the id of the simulation. | 
| SafeBreach.Simulation.AttackerNodeName | String | Name of attacker node of simulation. | 
| SafeBreach.Simulation.TargetNodeName | String | name of target of simulation. | 
| SafeBreach.Simulation.DestNodeName | String | name of destination of simulation. | 
| SafeBreach.Simulation.AttackName | String | name of attack | 
| SafeBreach.Simulation.AttacksInvolved | String | attack types involved in of simulation. | 
| SafeBreach.Simulation.ResultDetails | String | result of simulation. | 
| SafeBreach.Simulation.SecurityAction | String | security status as per the simulation. | 
| SafeBreach.Simulation.AttackDescription | String | attack details. | 

### safebreach-get-available-simulator-count

***
This command gives all details related to account, we are using this to find assigned simulator quota.

#### Base Command

`safebreach-get-available-simulator-count`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.AccountDetails.Id | Number | The account ID which is being used by integration. | 
| SafeBreach.AccountDetails.Name | String | The Account Name of account being queried. | 
| SafeBreach.AccountDetails.ContactName | String | Contact name for given account. | 
| SafeBreach.AccountDetails.ContactEmail | String | Email of the contact person. | 
| SafeBreach.AccountDetails.UserQuota | String | User Quota for the given account, maximum users which are allowed for the account. | 
| SafeBreach.AccountDetails.SimulatorsQuota | Number | The simulator quota for the given account. The maximum number of simulators which are available for the account. | 
| SafeBreach.AccountDetails.RegistrationDate | Number | The registration date of given account. | 
| SafeBreach.AccountDetails.ActivationDate | String | The Activation date of given account. | 
| SafeBreach.AccountDetails.ExpirationDate | String | Account expiration date. | 

### safebreach-get-simulator-with-id

***
This command gives simulator with given id

#### Base Command

`safebreach-get-simulator-with-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulator_id | simulator id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Simulator.IsEnabled | String | Whether the simulator is enabled or not. | 
| SafeBreach.Simulator.SimulatorId | String | The Id of given simulator. | 
| SafeBreach.Simulator.Name | String | name for given simulator. | 
| SafeBreach.Simulator.AccountId | String | Account Id of account Hosting given simulator. | 
| SafeBreach.Simulator.IsCritical | String | Whether the simulator is critical. | 
| SafeBreach.Simulator.IsExfiltration | String | If Simulator is exfiltration target. | 
| SafeBreach.Simulator.IsInfiltration | String | If simulator is infiltration target. | 
| SafeBreach.Simulator.IsMailTarget | String | If simulator is mail target. | 
| SafeBreach.Simulator.IsMailAttacker | String | If simulator is mail attacker. | 
| SafeBreach.Simulator.IsPreExecutor | String | Whether the simulator is pre executor. | 
| SafeBreach.Simulator.IsAwsAttacker | String | if the given simulator is aws attacker. | 
| SafeBreach.Simulator.IsAzureAttacker | String | If the given simulator is azure attacker. | 
| SafeBreach.Simulator.ExternalIp | String | external ip of given simulator. | 
| SafeBreach.Simulator.InternalIp | String | internal ip of given simulator. | 
| SafeBreach.Simulator.IsWebApplicationAttacker | String | Whether the simulator is Web application attacker. | 
| SafeBreach.Simulator.PreferredInterface | String | Preferred simulator interface. | 
| SafeBreach.Simulator.PreferredIp | String | Preferred Ip of simulator. | 
| SafeBreach.Simulator.Hostname | String | Hostname of given simulator. | 
| SafeBreach.Simulator.ConnectionType | String | connection_type of given simulator. | 
| SafeBreach.Simulator.SimulatorStatus | String | status of the simulator. | 
| SafeBreach.Simulator.ConnectionStatus | String | connection status of simulator. | 
| SafeBreach.Simulator.SimulatorFrameworkVersion | String | Framework version of simulator. | 
| SafeBreach.Simulator.OperatingSystemType | String | operating system type of given simulator. | 
| SafeBreach.Simulator.OperatingSystem | String | Operating system of given simulator. | 
| SafeBreach.Simulator.ExecutionHostname | String | Execution Hostname of the given simulator. | 
| SafeBreach.Simulator.Deployments | String | deployments simulator is part of. | 
| SafeBreach.Simulator.CreatedAt | String | Creation datetime of simulator. | 
| SafeBreach.Simulator.UpdatedAt | String | Update datetime of given simulator. | 
| SafeBreach.Simulator.DeletedAt | String | deletion datetime of given simulator. | 
| SafeBreach.Simulator.Assets | String | Assets of given simulator. | 
| SafeBreach.Simulator.SimulationUsers | String | simulator users list. | 
| SafeBreach.Simulator.Proxies | String | Proxies of simulator. | 
| SafeBreach.Simulator.AdvancedActions | String | Advanced simulator details. | 

### safebreach-get-simulators-versions-list

***
This command fetches the list of SafeBreach simulators

#### Base Command

`safebreach-get-simulators-versions-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Simulator.Id | String | Simulator Id | 
| SafeBreach.Simulator.Lastupdatedate | String | Simulator last updated data | 
| SafeBreach.Simulator.Lastupdatestatus | String | Simulator last updated status | 
| SafeBreach.Simulator.Currentstatus | String | Simulator current status | 
| SafeBreach.Simulator.Availableversions | Unknown | Simulator available versions | 

### safebreach-get-user-with-matching-name-or-email

***
This command gives all users which match the inputs given, Since email is a unique field we only get one user if            email matches but if name is given as input then care should be taken to see name matches exactly.            else there is a chance that multiple users are retrieved, please not that either name or email are to            be populated and if neither of them are given as input then it results in error

#### Base Command

`safebreach-get-user-with-matching-name-or-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the user. Partial match is supported. | Optional | 
| email | Email of the user. Exact match required. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.UserData.Id | Number | The ID of User retrieved. this can be used to further link this user with user_id field of                       safebreach-update-user or safebreach-delete-user commands | 
| SafeBreach.UserData.Name | String | The name of User retrieved. | 
| SafeBreach.UserData.Email | String | The email of User retrieved. this can be used for updating user or deleting user                       for input email of commands safebreach-update-user or safebreach-delete-user | 

### safebreach-get-verification-token

***
This command retrieves existing verification token needed for verification of the simulators.

#### Base Command

`safebreach-get-verification-token`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.VerificationToken.Token | String | the value of new verification token. | 

### safebreach-pause/resume-simulations-tests

***
This command gets simulations/tests which are in running or queued state and pauses/resumes them based on input selected. The state selected will be applied for all running/queued state tasks whether they are simulations/tests.

#### Base Command

`safebreach-pause/resume-simulations-tests`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulation_or_test_state | State of tests/simulators to set to:<br/>1. pause will set all simulations/tests which are in queue/running to paused stated and resume all will be the state of button in running simulations page. <br/>2. resume will queue all simulations/tests and will set them to running/queued depending on priority. <br/>Note that this doe not affect the schedules and scheduled tasks unless they are running or active at the moment of execution of the command. Possible values are: resume, pause. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.TestStatus.Status | String | the status of the simulations/tests. | 

### safebreach-rerun-simulation

***
this commands puts given simulation ids into queue for running.

#### Base Command

`safebreach-rerun-simulation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulation_ids | ids of simulation we want to queue,                          please give ids of simulations as comma separated numbers. | Required | 
| test_name | test name for the given test. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Simulation.Id | String | the Id of simulation. | 
| SafeBreach.Simulation.Name | String | the name of the simulation. | 
| SafeBreach.Simulation.Description | String | the description of the simulation. | 
| SafeBreach.Simulation.SuccessCriteria | String | success criteria the simulation. | 
| SafeBreach.Simulation.OriginalScenarioId | String | original simulation id of simulation. | 
| SafeBreach.Simulation.ActionsList | String | actions list of the simulation. | 
| SafeBreach.Simulation.StepsOrder | String | the order of steps of the simulation. | 
| SafeBreach.Simulation.Createdat | String | the creation datetime of the simulation. | 
| SafeBreach.Simulation.Updatedat | String | the last updated time the simulation. | 

### safebreach-rerun-test

***
This command puts given test data in queue for execution.

#### Base Command

`safebreach-rerun-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| test_id | test id for the given test,             this is be test id field from get-all-tests-summary command. | Required | 
| test_name | test name for the given test. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Test.Id | String | the Id of test. | 
| SafeBreach.Test.Name | String | the name of the test. | 
| SafeBreach.Test.Description | String | the description of the test. | 
| SafeBreach.Test.SuccessCriteria | String | success criteria the test. | 
| SafeBreach.Test.OriginalScenarioId | String | original scenario id of test. | 
| SafeBreach.Test.ActionsList | String | actions list of the test. | 
| SafeBreach.Test.EdgesCount | String | edges_count for the test. | 
| SafeBreach.Test.StepsOrder | String | the order of steps of the test. | 
| SafeBreach.Test.CreatedAt | String | the creation datetime of the test. | 
| SafeBreach.Test.UpdatedAt | String | the last updated time the test. | 
| SafeBreach.Test.ScenarioId | String | the test id of the test. | 
| SafeBreach.Test.RanBy | String | the user id of the user who ran the test. | 
| SafeBreach.Test.RanFrom | String | where the user ran the test from. | 
| SafeBreach.Test.EnableFeedbackLoop | String | feedback loop status of the test. | 
| SafeBreach.Test.TestId | String | test_id of the test. | 
| SafeBreach.Test.Priority | String | priority of the test. | 
| SafeBreach.Test.RetrySimulations | String | retry status of the test. | 

### safebreach-rotate-verification-token

***
This command rotates generated verification token meaning it creates a new token which will be used for verification of simulator and adding the simulator.

#### Base Command

`safebreach-rotate-verification-token`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.Token.NewToken | String | New token which has been generated due to the API call | 

### safebreach-update-deployment

***
This command updates a deployment with given data. The deployment_id field of this command can be retrieved from 'safebreach-list-deployments' command. If the user wants to search with deployment ID then they can search it 

#### Base Command

`safebreach-update-deployment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deployment_id | ID of the deployment to update. Can be searched with list-deployments command. | Required | 
| updated_simulators_for_deployment | Comma separated ID of all simulators to be part of the deployment Simulators can be  retrieved by calling get-all-available-simulator-details command. | Optional | 
| updated_deployment_name | Deployment name. | Optional | 
| updated_deployment_description | Deployment description. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.UpdatedDeployment.Id | Number | The ID of deployment whose values have been updated.                          ID cant be changed so this wont be updated. | 
| SafeBreach.UpdatedDeployment.AccountId | String | The accountId of user who created the deployment. | 
| SafeBreach.UpdatedDeployment.Name | String | The name of deployment which has been updated to the name given in updated_deployment_name.                        this will be the name shown in deployment name field of table in deployments page in safebreach UI | 
| SafeBreach.UpdatedDeployment.CreatedAt | String | The creation date and time of deployment whose data has been updated. | 
| SafeBreach.UpdatedDeployment.UpdatedAt | String | The last updated date and time of deployment whose data has been updated.                      This will generally be closer to the update deployment command run time for reference | 
| SafeBreach.UpdatedDeployment.Description | String | The updated description of deployment which is provided in updated_deployment_description                      field of input . This will now be the description which is shown in description field of deployments                      table of safebreach UI | 
| SafeBreach.UpdatedDeployment.Simulators | String | The simulators that are part of deployment. unless any simulators are given as input this                           field won't be updated this field doesn't reflect changes if simulators given as input are deleted | 

### safebreach-update-simulator

***
This command updates simulator with given id. the given inputs for update fields will be updated to the selected filed values will be updated to given value.

#### Base Command

`safebreach-update-simulator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulator_id | Simulator ID. | Required | 
| connection_url | The given value will be set as connection string, meaning this can be used to connect to this URL. | Optional | 
| cloud_proxy_url | the given value will be set as cloud proxy url. | Optional | 
| name | The given value will be set as name of simulator. This will be the name of simulator once the command runs. | Optional | 
| preferred_interface | the given value will be set as preferred interface. | Optional | 
| preferred_ip | the given value will be set as Preferred IP to connect to the simulator. | Optional | 
| tunnel | the given value will be set as tunnel. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.UpdatedSimulator.IsEnabled | String | Whether the simulator is enabled or not. | 
| SafeBreach.UpdatedSimulator.SimulatorId | String | The Id of given simulator. | 
| SafeBreach.UpdatedSimulator.Name | String | name for given simulator. | 
| SafeBreach.UpdatedSimulator.AccountId | String | Account Id of account Hosting given simulator. | 
| SafeBreach.UpdatedSimulator.IsCritical | String | Whether the simulator is critical. | 
| SafeBreach.UpdatedSimulator.IsExfiltration | String | If Simulator is exfiltration target. | 
| SafeBreach.UpdatedSimulator.IsInfiltration | String | If simulator is infiltration target. | 
| SafeBreach.UpdatedSimulator.IsMailTarget | String | If simulator is mail target. | 
| SafeBreach.UpdatedSimulator.IsMailAttacker | String | If simulator is mail attacker. | 
| SafeBreach.UpdatedSimulator.IsPreExecutor | String | Whether the simulator is pre executor. | 
| SafeBreach.UpdatedSimulator.IsAwsAttacker | String | if the given simulator is aws attacker. | 
| SafeBreach.UpdatedSimulator.IsAzureAttacker | String | If the given simulator is azure attacker. | 
| SafeBreach.UpdatedSimulator.ExternalIp | String | external ip of given simulator. | 
| SafeBreach.UpdatedSimulator.InternalIp | String | internal ip of given simulator. | 
| SafeBreach.UpdatedSimulator.IsWebApplicationAttacker | String | Whether the simulator is Web application attacker. | 
| SafeBreach.UpdatedSimulator.PreferredInterface | String | Preferred simulator interface. | 
| SafeBreach.UpdatedSimulator.PreferredIp | String | Preferred Ip of simulator. | 
| SafeBreach.UpdatedSimulator.Hostname | String | Hostname of given simulator. | 
| SafeBreach.UpdatedSimulator.ConnectionType | String | connection_type of given simulator. | 
| SafeBreach.UpdatedSimulator.SimulatorStatus | String | status of the simulator. | 
| SafeBreach.UpdatedSimulator.ConnectionStatus | String | connection status of simulator. | 
| SafeBreach.UpdatedSimulator.SimulatorFrameworkVersion | String | Framework version of simulator. | 
| SafeBreach.UpdatedSimulator.OperatingSystemType | String | operating system type of given simulator. | 
| SafeBreach.UpdatedSimulator.OperatingSystem | String | Operating system of given simulator. | 
| SafeBreach.UpdatedSimulator.ExecutionHostname | String | Execution Hostname of the given simulator. | 
| SafeBreach.UpdatedSimulator.Deployments | String | deployments simulator is part of. | 
| SafeBreach.UpdatedSimulator.CreatedAt | String | Creation datetime of simulator. | 
| SafeBreach.UpdatedSimulator.UpdatedAt | String | Update datetime of given simulator. | 
| SafeBreach.UpdatedSimulator.DeletedAt | String | deletion datetime of given simulator. | 
| SafeBreach.UpdatedSimulator.Assets | String | Assets of given simulator. | 
| SafeBreach.UpdatedSimulator.SimulationUsers | String | simulator users list. | 
| SafeBreach.UpdatedSimulator.Proxies | String | Proxies of simulator. | 
| SafeBreach.UpdatedSimulator.AdvancedActions | String | Advanced simulator details. | 

### safebreach-upgrade-simulator

***
This command updates the simulator using the Simulator ID and available version.

#### Base Command

`safebreach-upgrade-simulator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulator_id | Simulator ID. | Required | 
| simulator_version | The version should be in the format of the safebreach-get-simulators-versions-list  command and that 'latest' can be used. The default is the latest. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.UpdatedSimulator.Nodeid | String | Simulator ID | 
| SafeBreach.UpdatedSimulator.Status | String | Simulator status | 

### safebreach-update-user

***
This command updates a user with given data.

#### Base Command

`safebreach-update-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | user ID of user from safebreach to search. | Required | 
| name | Update the user name to given value of this field. | Optional | 
| user_description | Update the user Description to given value in this field. | Optional | 
| is_active |  Update the user Status based on the input, if this is set to false then user will be deactivated. unless this field is left empty, whatever is present here will be updated to user details. user will be selected based on user_id field mentioned above. Possible values are: true, false, . | Optional | 
| password | Password of user to be updated with. this will be used for changing password for user. unless this field is left empty, whatever is present here will be updated to user details. user will be selected based on user_id field mentioned above. | Optional | 
| user_role |  Role of the user to be changed to. unless you want to change the user role and permissions, dont select anything in this field, user will be selected based on user_id field mentioned above. Possible values are: viewer, administrator, contentDeveloper, operator. | Optional | 
| deployments | Comma separated ID of all deployments the user should be part of. unless this field is left empty, whatever is present here will be updated to user details.incase there are old deployments assigned to user then please include them too, else they will be replaced with new values.User will be selected based on user_id field mentioned above. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SafeBreach.UpdatedUserData.Id | Number | The ID of User whose data has been updated. | 
| SafeBreach.UpdatedUserData.Name | String | The name of User after running the update command according to safebreach records. | 
| SafeBreach.UpdatedUserData.Email | String | the email of the user whose data has been updated by the command. | 
| SafeBreach.UpdatedUserData.Createdat | String | the time at which the user who has been selected has been created | 
| SafeBreach.UpdatedUserData.Updatedat | String | The last updated time of User selected for update.                       this will be the execution time for the command or close to it. | 
| SafeBreach.UpdatedUserData.Deletedat | String | The Deletion time of User selected to update. Generally this is empty unless                      user chosen to update is a deleted user | 
| SafeBreach.UpdatedUserData.Roles | String | The roles of User updated. these will change if role has been updated during                      updating user details else they will be same as pre update. | 
| SafeBreach.UpdatedUserData.Description | String | The description of User after updating user, if description field has been given any                      new value during update then its updated else this will be left unchanged from previous value. | 
| SafeBreach.UpdatedUserData.Role | String | The roles and permissions related to user who has been selected for update.unless this field                      has been given a value , this will not be updated and will stay the same as previous value. | 
| SafeBreach.UpdatedUserData.Deployments | String | The deployments related to user, this will be comma separated values of deployment IDs | 
