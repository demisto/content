SafeBreach automatically executes thousands of breach methods from its extensive and growing Hacker’s Playbook™ to validate security control effectiveness. Simulations are automatically correlated with network, endpoint, and SIEM solutions providing data-driven SafeBreach Insights for holistic remediation to harden enterprise defenses.
This integration was integrated and tested with version 2024Q1.4 of Safebreach.

## Configure Safebreach on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Safebreach.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | This is base URL for your instance. | True |
    | API Key | This is API key for your instance, this can be created in safebreach user                       administration&gt;APIkeys and then it must be saved as there is no way to view this again | True |
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
| approved_simulator_details.is_enabled | String | Whether the simulator is enabled or not. | 
| approved_simulator_details.simulator_id | String | The Id of given simulator. | 
| approved_simulator_details.name | String | name for given simulator. | 
| approved_simulator_details.account_id | String | Account Id of account Hosting given simulator. | 
| approved_simulator_details.is_critical | String | Whether the simulator is critical. | 
| approved_simulator_details.is_exfiltration | String | If Simulator is exfiltration target. | 
| approved_simulator_details.is_infiltration | String | If simulator is infiltration target. | 
| approved_simulator_details.is_mail_target | String | If simulator is mail target. | 
| approved_simulator_details.is_mail_attacker | String | If simulator is mail attacker. | 
| approved_simulator_details.is_pre_executor | String | Whether the simulator is pre executor. | 
| approved_simulator_details.is_aws_attacker | String | if the given simulator is aws attacker. | 
| approved_simulator_details.is_azure_attacker | String | If the given simulator is azure attacker. | 
| approved_simulator_details.external_ip | String | external ip of given simulator. | 
| approved_simulator_details.internal_ip | String | internal ip of given simulator. | 
| approved_simulator_details.is_web_application_attacker | String | Whether the simulator is Web application attacker. | 
| approved_simulator_details.preferred_interface | String | Preferred simulator interface. | 
| approved_simulator_details.preferred_ip | String | Preferred Ip of simulator. | 
| approved_simulator_details.hostname | String | Hostname of given simulator. | 
| approved_simulator_details.connection_type | String | connection_type of given simulator. | 
| approved_simulator_details.simulator_status | String | status of the simulator. | 
| approved_simulator_details.connection_status | String | connection status of simulator. | 
| approved_simulator_details.simulator_framework_version | String | Framework version of simulator. | 
| approved_simulator_details.operating_system_type | String | operating system type of given simulator. | 
| approved_simulator_details.operating_system | String | Operating system of given simulator. | 
| approved_simulator_details.execution_hostname | String | Execution Hostname of the given simulator. | 
| approved_simulator_details.deployments | String | deployments simulator is part of. | 
| approved_simulator_details.created_at | String | Creation datetime of simulator. | 
| approved_simulator_details.updated_at | String | Update datetime of given simulator. | 
| approved_simulator_details.deleted_at | String | deletion datetime of given simulator. | 
| approved_simulator_details.assets | String | Assets of given simulator. | 
| approved_simulator_details.simulation_users | String | simulator users list. | 
| approved_simulator_details.proxies | String | Proxies of simulator. | 
| approved_simulator_details.advanced_actions | String | Advanced simulator details. | 

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
| generated_api_key.name | String | The Name of API Key generated through this command,                           This will match the input name of the command. | 
| generated_api_key.description | String | The Description of API Key created.                           this will be same as input description given for the command. | 
| generated_api_key.created_by | String | The id of user who generated this API key. | 
| generated_api_key.created_bt | String | The creation date and time of API key. | 
| generated_api_key.key | String | The value of API key generated. store this for further use as this will only be shown once | 

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
| created_deployment_data.id | Number | The ID of deployment created. this Id can be used to update ,delete deployment as                      deployment_id field of the deployment. | 
| created_deployment_data.account_id | String | This field shows account ID of user who has created the account. | 
| created_deployment_data.name | String | The name of deployment created. this will be name which will be shown on deployments page                      of safebreach and name that is given as input to the command. | 
| created_deployment_data.created_at | String | The creation date and time of deployment , this will be closer to                      command execution time if the deployment creation is successful. | 
| created_deployment_data.description | String | The description of the deployment created will be shown in description                           part of the table in safebreach. | 
| created_deployment_data.simulators | String | The simulators that are part of deployment. | 

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
| created_user_data.id | Number | The ID of User created. | 
| created_user_data.name | String | The name of User created. | 
| created_user_data.email | String | The email of User created. | 
| created_user_data.createdAt | String | The creation time of User. | 
| created_user_data.roles | String | The roles and permissions of User created. | 
| created_user_data.description | String | The description of User if any is given at creation time, it will be populated here. | 
| created_user_data.role | String | The role assigned to user during creation. | 
| created_user_data.deployments | String | The deployments user is part of. | 

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
| deleted_api_key.name | Number | The Name of API Key deleted. | 
| deleted_api_key.description | String | Description of API Key deleted. | 
| deleted_api_key.created_by | String | The id of user who generated this API key. | 
| deleted_api_key.created_at | String | The creation time and date of API key. | 
| deleted_api_key.deleted_at | String | The deletion time and date of API key. The deletion date and time are generally                      close to the command execution time and date. | 

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
| deleted_deployment_data.id | Number | The ID of deployment which has been deleted. | 
| deleted_deployment_data.account_id | String | The account Id of user who deleted the deployment. | 
| deleted_deployment_data.name | String | The name of deployment before the deployment was deleted. | 
| deleted_deployment_data.created_at | String | The creation date and time of deployment which has been deleted. | 
| deleted_deployment_data.description | String | The description of deployment before it was deleted. | 
| deleted_deployment_data.simulators | String | The simulators that are part of deployment before it was deleted. | 

### safebreach-delete-integration-issues

***
This command deletes connector-related errors and warnings for the specified connector_id (retrieved using the get-all-integration-issues command).

#### Base Command

`safebreach-delete-integration-issues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| integration_id | The ID of Integration to have its errors/warnings deleted. Both errors and warnings will be deleted. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| errors_cleared.error | Number | Error count after deletion of errors for the given Integration. | 
| errors_cleared.result | String | error deletion status whether true or false. | 

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
| deleted_scheduled_scenario.id | String | the Id of the scheduled scenario. | 
| deleted_scheduled_scenario.is_enabled | Boolean | if scheduled scenario is enabled. | 
| deleted_scheduled_scenario.user_schedule | String | the user readable form of the scheduled scenario. | 
| deleted_scheduled_scenario.run_date | String | the run date of the scheduled scenario. | 
| deleted_scheduled_scenario.cron_timezone | String | the time zone of the scheduled scenario. | 
| deleted_scheduled_scenario.description | String | the description of the scheduled scenario. | 
| deleted_scheduled_scenario.scenario_id | String | the test ID of the scheduled scenario. | 
| deleted_scheduled_scenario.created_at | String | the creation datetime of the scheduled scenario. | 
| deleted_scheduled_scenario.updated_at | String | the updated datetime of the scheduled scenario. | 
| deleted_scheduled_scenario.deleted_at | String | the deletion time of the scheduled scenario. | 

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
| deleted_simulator_details.is_enabled | String | Whether the simulator is enabled or not. | 
| deleted_simulator_details.simulator_id | String | The Id of given simulator. | 
| deleted_simulator_details.name | String | name for given simulator. | 
| deleted_simulator_details.account_id | String | Account Id of account Hosting given simulator. | 
| deleted_simulator_details.is_critical | String | Whether the simulator is critical. | 
| deleted_simulator_details.is_exfiltration | String | If Simulator is exfiltration target. | 
| deleted_simulator_details.is_infiltration | String | If simulator is infiltration target. | 
| deleted_simulator_details.is_mail_target | String | If simulator is mail target. | 
| deleted_simulator_details.is_mail_attacker | String | If simulator is mail attacker. | 
| deleted_simulator_details.is_pre_executor | String | Whether the simulator is pre executor. | 
| deleted_simulator_details.is_aws_attacker | String | if the given simulator is aws attacker. | 
| deleted_simulator_details.is_azure_attacker | String | If the given simulator is azure attacker. | 
| deleted_simulator_details.external_ip | String | external ip of given simulator. | 
| deleted_simulator_details.internal_ip | String | internal ip of given simulator. | 
| deleted_simulator_details.is_web_application_attacker | String | Whether the simulator is Web application attacker. | 
| deleted_simulator_details.preferred_interface | String | Preferred simulator interface. | 
| deleted_simulator_details.preferred_ip | String | Preferred Ip of simulator. | 
| deleted_simulator_details.hostname | String | Hostname of given simulator. | 
| deleted_simulator_details.connection_type | String | connection_type of given simulator. | 
| deleted_simulator_details.simulator_status | String | status of the simulator. | 
| deleted_simulator_details.connection_status | String | connection status of simulator. | 
| deleted_simulator_details.simulator_framework_version | String | Framework version of simulator. | 
| deleted_simulator_details.operating_system_type | String | operating system type of given simulator. | 
| deleted_simulator_details.operating_system | String | Operating system of given simulator. | 
| deleted_simulator_details.execution_hostname | String | Execution Hostname of the given simulator. | 
| deleted_simulator_details.deployments | String | deployments simulator is part of. | 
| deleted_simulator_details.created_at | String | Creation datetime of simulator. | 
| deleted_simulator_details.updated_at | String | Update datetime of given simulator. | 
| deleted_simulator_details.deleted_at | String | deletion datetime of given simulator. | 
| deleted_simulator_details.assets | String | Assets of given simulator. | 
| deleted_simulator_details.simulation_users | String | simulator users list. | 
| deleted_simulator_details.proxies | String | Proxies of simulator. | 
| deleted_simulator_details.advanced_actions | String | Advanced simulator details. | 

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
| deleted_test_results.scenario_id | String | scenario ID of the test. | 
| deleted_test_results.simulation_name | String | Name of the simulation. | 
| deleted_test_results.security_action_per_control | String | Security Actions of the simulation. | 
| deleted_test_results.test_id | String | Test id of the test. | 
| deleted_test_results.status | String | status of the test. | 
| deleted_test_results.planned_simulations_amount | String | Planned simulations count of the test. | 
| deleted_test_results.simulator_executions | String | simulator executions of the test. | 
| deleted_test_results.attack_executions | String | list of attacks that are part of the simulation. | 
| deleted_test_results.ran_by | String | user who started the simulation. | 
| deleted_test_results.simulator_count | String | simulators count per account. | 
| deleted_test_results.end_time | String | End Time of the test. | 
| deleted_test_results.start_time | String | start time of the test. | 
| deleted_test_results.finalStatus.stopped | String | stopped count of attacks. | 
| deleted_test_results.finalStatus.missed | String | missed count of attacks. | 
| deleted_test_results.finalStatus.logged | String | logged count of attacks. | 
| deleted_test_results.finalStatus.detected | String | detected count of attacks. | 
| deleted_test_results.finalStatus.prevented | String | prevented count of attacks. | 

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
| deleted_user_data.id | Number | The ID of User whose data has been deleted. | 
| deleted_user_data.name | String | The name of User deleted. | 
| deleted_user_data.email | String | The email of User deleted. | 
| deleted_user_data.createdAt | String | the time at which the user who has been selected has been created | 
| deleted_user_data.updatedAt | String | last updated time. | 
| deleted_user_data.deletedAt | String | Deletion time of user. | 
| deleted_user_data.roles | String | The roles of User before they were deleted. | 
| deleted_user_data.description | String | The description of User who has been deleted. | 
| deleted_user_data.role | String | The roles and permissions of User who has been deleted. | 
| deleted_user_data.deployments | String | The deployments related to user before he was deleted. | 

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
| integration_errors.integration_id | Number | The ID of Integration. A general notation that has been followed here is                      as follows, if the  id has _default at the end then its a default connector else its a custom connector | 
| integration_errors.integration_name | String | Name of the integration | 
| integration_errors.action | String | The action of Integration error. This describes where exactly did the error occur,                        if its search,then it implies error/warning happened when connector was trying that process | 
| integration_errors.success_state | String | status of integration error. This implies whether the connector was able to                       successfully perform the operation or if it failed partway.                       So false implies it failed partway and true implies it was successfully completed | 
| integration_errors.error_description | String | This is the exact error description shown on safebreach integration error/warning page.                        This description can be used for understanding of what exactly happened for the integration to fail. | 
| integration_errors.timestamp | String | Time at which error/warning occurred. This can be used to pinpoint error which occurred                      across integrations if time of origin was remembered | 

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
| active_simulations.test id | String | this is test ID of the simulation. | 
| active_simulations.simulation_id | String | the simulation id of the simulation. | 
| active_simulations.attack_id | String | the attack ID of the simulation. | 

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
| active_tests.id | Number | Id of Actively running test. | 
| active_tests.name | String | Name of the test being run. | 
| active_tests.description | String | Details related to the test being run. | 
| active_tests.success_criteria | String | success criterion for the test. | 
| active_tests.original_scenario_id | String | Original scenario ID of the running test | 
| active_tests.actions_count | String | number of actions | 
| active_tests.edges_count | String | number of edges. | 
| active_tests.created_at | String | details related to when test is created. | 
| active_tests.updated_at | String | details related to when test is last updated/changed | 
| active_tests.steps_count | String | number of steps in simulator. | 
| active_tests.scenario_id | String | scenario_id of the test. | 
| active_tests.original_scenario_id | String | scenario_id for reference. | 
| active_tests.ran_by | String | User who ran the scenario. | 
| active_tests.ran_from | String | Where the test ran from. | 
| active_tests.test_id | String | test id of the test. | 
| active_tests.priority | String | priority of tests. | 
| active_tests.retry_simulations | String | Should simulations be retried | 
| active_tests.pause_duration | String | is the test paused and if so till when | 
| active_tests.paused_date | String | when the test is paused | 
| active_tests.expected_simulations_amount | String | number of simulations expected | 
| active_tests.dispatched_simulations_amount | String | the number of simulations dispatched | 
| active_tests.skipped_simulations_amount | String | The number of simulations skipped | 
| active_tests.failed_simulations_amount | String | The number of simulations failed | 

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
| simulator_details.is_enabled | String | Whether the simulator is enabled or not. | 
| simulator_details.simulator_id | String | The Id of given simulator. | 
| simulator_details.name | String | name for given simulator. | 
| simulator_details.account_id | String | Account Id of account Hosting given simulator. | 
| simulator_details.is_critical | String | Whether the simulator is critical. | 
| simulator_details.is_exfiltration | String | If Simulator is exfiltration target. | 
| simulator_details.is_infiltration | String | If simulator is infiltration target. | 
| simulator_details.is_mail_target | String | If simulator is mail target. | 
| simulator_details.is_mail_attacker | String | If simulator is mail attacker. | 
| simulator_details.is_pre_executor | String | Whether the simulator is pre executor. | 
| simulator_details.is_aws_attacker | String | if the given simulator is aws attacker. | 
| simulator_details.is_azure_attacker | String | If the given simulator is azure attacker. | 
| simulator_details.external_ip | String | external ip of given simulator. | 
| simulator_details.internal_ip | String | internal ip of given simulator. | 
| simulator_details.is_web_application_attacker | String | Whether the simulator is Web application attacker. | 
| simulator_details.preferred_interface | String | Preferred simulator interface. | 
| simulator_details.preferred_ip | String | Preferred Ip of simulator. | 
| simulator_details.hostname | String | Hostname of given simulator. | 
| simulator_details.connection_type | String | connection_type of given simulator. | 
| simulator_details.simulator_status | String | status of the simulator. | 
| simulator_details.connection_status | String | connection status of simulator. | 
| simulator_details.simulator_framework_version | String | Framework version of simulator. | 
| simulator_details.operating_system_type | String | operating system type of given simulator. | 
| simulator_details.operating_system | String | Operating system of given simulator. | 
| simulator_details.execution_hostname | String | Execution Hostname of the given simulator. | 
| simulator_details.deployments | String | deployments simulator is part of. | 
| simulator_details.created_at | String | Creation datetime of simulator. | 
| simulator_details.updated_at | String | Update datetime of given simulator. | 
| simulator_details.deleted_at | String | deletion datetime of given simulator. | 
| simulator_details.assets | String | Assets of given simulator. | 
| simulator_details.simulation_users | String | simulator users list. | 
| simulator_details.proxies | String | Proxies of simulator. | 
| simulator_details.advanced_actions | String | Advanced simulator details. | 

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
| test_results.scenario_id | String | scenario ID of the test. | 
| test_results.simulation_name | String | Name of the simulation. | 
| test_results.security_action_per_control | String | Security Actions of the simulation. | 
| test_results.test_id | String | Test id of the test. | 
| test_results.status | String | status of the test. | 
| test_results.planned_simulations_amount | String | Planned simulations count of the test. | 
| test_results.simulator_executions | String | simulator executions of the test. | 
| test_results.attack_executions | String | list of attacks that are part of the simulation. | 
| test_results.ran_by | String | user who started the simulation. | 
| test_results.simulator_count | String | simulators count per account. | 
| test_results.end_time | String | End Time of the test. | 
| test_results.start_time | String | start time of the test. | 
| test_results.finalStatus.stopped | String | stopped count of attacks. | 
| test_results.finalStatus.missed | String | missed count of attacks. | 
| test_results.finalStatus.logged | String | logged count of attacks. | 
| test_results.finalStatus.detected | String | detected count of attacks. | 
| test_results.finalStatus.prevented | String | prevented count of attacks. | 

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
| test_results.scenario_id | String | scenario ID of the test. | 
| test_results.simulation_name | String | Name of the simulation. | 
| test_results.security_action_per_control | String | Security Actions of the simulation. | 
| test_results.test_id | String | Test id of the test. | 
| test_results.status | String | status of the test. | 
| test_results.planned_simulations_amount | String | Planned simulations count of the test. | 
| test_results.simulator_executions | String | simulator executions of the test. | 
| test_results.attack_executions | String | list of attacks that are part of the simulation. | 
| test_results.ran_by | String | user who started the simulation. | 
| test_results.simulator_count | String | simulators count per account. | 
| test_results.end_time | String | End Time of the test. | 
| test_results.start_time | String | start time of the test. | 
| test_results.finalStatus.stopped | String | stopped count of attacks. | 
| test_results.finalStatus.missed | String | missed count of attacks. | 
| test_results.finalStatus.logged | String | logged count of attacks. | 
| test_results.finalStatus.detected | String | detected count of attacks. | 
| test_results.finalStatus.prevented | String | prevented count of attacks. | 

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
| user_data.id | Number | The ID of User retrieved. this can be used to further link this user with                      user_id field of safebreach-update-user or safebreach-delete-user commands | 
| user_data.name | String | The name of User retrieved. | 
| user_data.email | String | The email of User retrieved. this can be used for updating user or                      deleting user for input email of commands safebreach-update-user or safebreach-delete-user  | 

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
| custom_scenarios.id | String | the Id of scenario. | 
| custom_scenarios.name | String | the name of the scenario. | 
| custom_scenarios.description | String | the description of the scenario. | 
| custom_scenarios.success_criteria | String | success criteria the scenario. | 
| custom_scenarios.original_scenario_id | String | original scenario id of scenario. | 
| custom_scenarios.actions_list | String | actions list of the scenario. | 
| custom_scenarios.edges_count | String | edges_count for the scenario. | 
| custom_scenarios.steps_order | String | the order of steps of the scenario. | 
| custom_scenarios.created_at | String | the creation datetime of the scenario. | 
| custom_scenarios.updated_at | String | the last updated time the scenario. | 

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
| deployment_data.id | Number | The ID of deployment | 
| deployment_data.account_id | String | The accountId of user who created the deployment. | 
| deployment_data.name | String | The name of deployment.                        this will be the name shown in deployment name field of table in deployments page in safebreach UI | 
| deployment_data.created_at | String | The creation date and time of deployment. | 
| deployment_data.updated_at | String | The last updated date and time of deployment. | 
| deployment_data.description | String | This is description field of deployments table of safebreach UI | 
| deployment_data.simulators | String | The simulators that are part of deployment. | 

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
| indicator_details.value | String | The value of the indicator | 
| indicator_details.type | String | The type of the indicator | 
| indicator_details.rawJSON.dataType | String | The data type of the indicator | 
| indicator_details.rawJSON.insightTime | String | The time of the insight | 
| indicator_details.rawJSON.value | String | The data type value of the indicator | 
| indicator_details.fields.description | String | The description of the indicator | 
| indicator_details.fields.safebreachseverity | String | The severity of the indicator | 
| indicator_details.fields.safebreachseverityscore | String | The severity score of the indicator | 
| indicator_details.fields.safebreachisbehavioral | Boolean | The behavioral of the indicator | 
| indicator_details.fields.safebreachattackids | Unknown | The attack ids of the indicator | 
| indicator_details.fields.port | String | The port of the indicator | 
| indicator_details.fields.tags | String | The tags of the indicator | 
| indicator_details.score | Number | The score of the indicator | 

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
| installation_links.md5 | String | The MD5 generated from the contents of the file | 
| installation_links.os | String | The operating system for which the update is intended | 
| installation_links.sha1 | String | The sha1 generated from the contents of the file. | 
| installation_links.sha256 | String | The sha256 generated from the contents of the file. | 
| installation_links.sha512 | String | The sha512 generated from the contents of the file. | 
| installation_links.sha512 | String | The sha512 generated from the contents of the file. | 
| installation_links.url | String | The URL from which update can be downloaded. | 
| installation_links.version | String | This indicates the simulator version. | 

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
| prebuilt_scenarios.id | String | the Id of scenario. | 
| prebuilt_scenarios.name | String | the name of the scenario. | 
| prebuilt_scenarios.description | String | the description of the scenario. | 
| prebuilt_scenarios.created_by | String | user id of user, who created the scenario. | 
| prebuilt_scenarios.created_at | String | creation datetime of scenario. | 
| prebuilt_scenarios.updated_at | String | the update datetime of the scenario. | 
| prebuilt_scenarios.recommended | String | the recommendation status of the scenario. | 
| prebuilt_scenarios.tags_list | String | the tags related to the scenario. | 
| prebuilt_scenarios.categories | String | the category ids of the scenario. | 
| prebuilt_scenarios.steps_order | String | the order of steps involved in the scenario. | 
| prebuilt_scenarios.order | String | the order of execution related to the scenario. | 
| prebuilt_scenarios.min_api_ver | String | the minimum version of API required for scenario to be executed | 

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
| schedules.id | String | the Id of the schedule. | 
| schedules.is_enabled | Boolean | if simulation is enabled. | 
| schedules.user_schedule | String | the user readable form of the schedule. | 
| schedules.run_date | String | the run date of the schedule. | 
| schedules.cron_timezone | String | the time zone of the schedule. | 
| schedules.description | String | the description of the schedule. | 
| schedules.scenario_id | String | the matrix ID of the schedule. | 
| schedules.created_at | String | the creation datetime of the schedule. | 
| schedules.updated_at | String | the updated datetime of the schedule. | 
| schedules.deleted_at | String | the deletion time of the schedule. | 

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
| services_status.name | String | the name of the service. | 
| services_status.version | String | version of the service. | 
| services_status.connection status | String | connection status of service. | 
| services_status.error | String | error status of service. | 

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
| simulation_details.simulation_id | String | the id of the simulation. | 
| simulation_details.attacker_node_name | String | Name of attacker node of simulation. | 
| simulation_details.target_node_name | String | name of target of simulation. | 
| simulation_details.dest_node_name | String | name of destination of simulation. | 
| simulation_details.attack_name | String | name of attack | 
| simulation_details.attacks_involved | String | attack types involved in of simulation. | 
| simulation_details.result_details | String | result of simulation. | 
| simulation_details.security_action | String | security status as per the simulation. | 
| simulation_details.attack_description | String | attack details. | 

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
| account_details.id | Number | The account ID which is being used by integration. | 
| account_details.name | String | The Account Name of account being queried. | 
| account_details.contact_name | String | Contact name for given account. | 
| account_details.contact_email | String | Email of the contact person. | 
| account_details.user_quota | String | User Quota for the given account, maximum users which are allowed for the account. | 
| account_details.simulators_quota | Number | The simulator quota for the given account. The maximum number of simulators which are available for the account. | 
| account_details.registration_date | Number | The registration date of given account. | 
| account_details.activation_date | String | The Activation date of given account. | 
| account_details.expiration_date | String | Account expiration date. | 

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
| simulator_details_with_id.is_enabled | String | Whether the simulator is enabled or not. | 
| simulator_details_with_id.simulator_id | String | The Id of given simulator. | 
| simulator_details_with_id.name | String | name for given simulator. | 
| simulator_details_with_id.account_id | String | Account Id of account Hosting given simulator. | 
| simulator_details_with_id.is_critical | String | Whether the simulator is critical. | 
| simulator_details_with_id.is_exfiltration | String | If Simulator is exfiltration target. | 
| simulator_details_with_id.is_infiltration | String | If simulator is infiltration target. | 
| simulator_details_with_id.is_mail_target | String | If simulator is mail target. | 
| simulator_details_with_id.is_mail_attacker | String | If simulator is mail attacker. | 
| simulator_details_with_id.is_pre_executor | String | Whether the simulator is pre executor. | 
| simulator_details_with_id.is_aws_attacker | String | if the given simulator is aws attacker. | 
| simulator_details_with_id.is_azure_attacker | String | If the given simulator is azure attacker. | 
| simulator_details_with_id.external_ip | String | external ip of given simulator. | 
| simulator_details_with_id.internal_ip | String | internal ip of given simulator. | 
| simulator_details_with_id.is_web_application_attacker | String | Whether the simulator is Web application attacker. | 
| simulator_details_with_id.preferred_interface | String | Preferred simulator interface. | 
| simulator_details_with_id.preferred_ip | String | Preferred Ip of simulator. | 
| simulator_details_with_id.hostname | String | Hostname of given simulator. | 
| simulator_details_with_id.connection_type | String | connection_type of given simulator. | 
| simulator_details_with_id.simulator_status | String | status of the simulator. | 
| simulator_details_with_id.connection_status | String | connection status of simulator. | 
| simulator_details_with_id.simulator_framework_version | String | Framework version of simulator. | 
| simulator_details_with_id.operating_system_type | String | operating system type of given simulator. | 
| simulator_details_with_id.operating_system | String | Operating system of given simulator. | 
| simulator_details_with_id.execution_hostname | String | Execution Hostname of the given simulator. | 
| simulator_details_with_id.deployments | String | deployments simulator is part of. | 
| simulator_details_with_id.created_at | String | Creation datetime of simulator. | 
| simulator_details_with_id.updated_at | String | Update datetime of given simulator. | 
| simulator_details_with_id.deleted_at | String | deletion datetime of given simulator. | 
| simulator_details_with_id.assets | String | Assets of given simulator. | 
| simulator_details_with_id.simulation_users | String | simulator users list. | 
| simulator_details_with_id.proxies | String | Proxies of simulator. | 
| simulator_details_with_id.advanced_actions | String | Advanced simulator details. | 

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
| simulator_details.id | String | Simulator Id | 
| simulator_details.lastUpdateDate | String | Simulator last updated data | 
| simulator_details.lastUpdateStatus | String | Simulator last updated status | 
| simulator_details.currentStatus | String | Simulator current status | 
| simulator_details.availableVersions | Unknown | Simulator available versions | 

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
| filtered_users.id | Number | The ID of User retrieved. this can be used to further link this user with user_id field of                       safebreach-update-user or safebreach-delete-user commands | 
| filtered_users.name | String | The name of User retrieved. | 
| filtered_users.email | String | The email of User retrieved. this can be used for updating user or deleting user                       for input email of commands safebreach-update-user or safebreach-delete-user | 

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
| verification_token.token | String | the value of new verification token. | 

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
| simulations_tests_status.status | String | the status of the simulations/tests. | 

### safebreach-rerun-simulation

***
this commands puts given simulation ids into queue for running.

#### Base Command

`safebreach-rerun-simulation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| simulation_ids | ids of simulation we want to queue,                          please give ids of simulations as comma separated numbers. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| changed_data.id | String | the Id of simulation. | 
| changed_data.name | String | the name of the simulation. | 
| changed_data.description | String | the description of the simulation. | 
| changed_data.success_criteria | String | success criteria the simulation. | 
| changed_data.original_scenario_id | String | original simulation id of simulation. | 
| changed_data.actions_list | String | actions list of the simulation. | 
| changed_data.steps_order | String | the order of steps of the simulation. | 
| changed_data.createdAt | String | the creation datetime of the simulation. | 
| changed_data.updatedAt | String | the last updated time the simulation. | 

### safebreach-rerun-test

***
this commands puts given test data in queue for execution.

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
| changed_data.id | String | the Id of test. | 
| changed_data.name | String | the name of the test. | 
| changed_data.description | String | the description of the test. | 
| changed_data.success_criteria | String | success criteria the test. | 
| changed_data.original_scenario_id | String | original scenario id of test. | 
| changed_data.actions_list | String | actions list of the test. | 
| changed_data.edges_count | String | edges_count for the test. | 
| changed_data.steps_order | String | the order of steps of the test. | 
| changed_data.created_at | String | the creation datetime of the test. | 
| changed_data.updated_at | String | the last updated time the test. | 
| changed_data.scenario_id | String | the test id of the test. | 
| changed_data.ran_by | String | the user id of the user who ran the test. | 
| changed_data.ran_from | String | where the user ran the test from. | 
| changed_data.enable_feedback_loop | String | feedback loop status of the test. | 
| changed_data.test_id | String | test_id of the test. | 
| changed_data.priority | String | priority of the test. | 
| changed_data.retry_simulations | String | retry status of the test. | 

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
| token.new_token | String | new Token which has been generated due to the api call | 

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
| updated_deployment_data.id | Number | The ID of deployment whose values have been updated.                          ID cant be changed so this wont be updated. | 
| updated_deployment_data.account_id | String | The accountId of user who created the deployment. | 
| updated_deployment_data.name | String | The name of deployment which has been updated to the name given in updated_deployment_name.                        this will be the name shown in deployment name field of table in deployments page in safebreach UI | 
| updated_deployment_data.created_at | String | The creation date and time of deployment whose data has been updated. | 
| updated_deployment_data.updated_at | String | The last updated date and time of deployment whose data has been updated.                      This will generally be closer to the update deployment command run time for reference | 
| updated_deployment_data.description | String | The updated description of deployment which is provided in updated_deployment_description                      field of input . This will now be the description which is shown in description field of deployments                      table of safebreach UI | 
| updated_deployment_data.simulators | String | The simulators that are part of deployment. unless any simulators are given as input this                           field won't be updated this field doesn't reflect changes if simulators given as input are deleted | 

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
| updated_simulator_details.is_enabled | String | Whether the simulator is enabled or not. | 
| updated_simulator_details.simulator_id | String | The Id of given simulator. | 
| updated_simulator_details.name | String | name for given simulator. | 
| updated_simulator_details.account_id | String | Account Id of account Hosting given simulator. | 
| updated_simulator_details.is_critical | String | Whether the simulator is critical. | 
| updated_simulator_details.is_exfiltration | String | If Simulator is exfiltration target. | 
| updated_simulator_details.is_infiltration | String | If simulator is infiltration target. | 
| updated_simulator_details.is_mail_target | String | If simulator is mail target. | 
| updated_simulator_details.is_mail_attacker | String | If simulator is mail attacker. | 
| updated_simulator_details.is_pre_executor | String | Whether the simulator is pre executor. | 
| updated_simulator_details.is_aws_attacker | String | if the given simulator is aws attacker. | 
| updated_simulator_details.is_azure_attacker | String | If the given simulator is azure attacker. | 
| updated_simulator_details.external_ip | String | external ip of given simulator. | 
| updated_simulator_details.internal_ip | String | internal ip of given simulator. | 
| updated_simulator_details.is_web_application_attacker | String | Whether the simulator is Web application attacker. | 
| updated_simulator_details.preferred_interface | String | Preferred simulator interface. | 
| updated_simulator_details.preferred_ip | String | Preferred Ip of simulator. | 
| updated_simulator_details.hostname | String | Hostname of given simulator. | 
| updated_simulator_details.connection_type | String | connection_type of given simulator. | 
| updated_simulator_details.simulator_status | String | status of the simulator. | 
| updated_simulator_details.connection_status | String | connection status of simulator. | 
| updated_simulator_details.simulator_framework_version | String | Framework version of simulator. | 
| updated_simulator_details.operating_system_type | String | operating system type of given simulator. | 
| updated_simulator_details.operating_system | String | Operating system of given simulator. | 
| updated_simulator_details.execution_hostname | String | Execution Hostname of the given simulator. | 
| updated_simulator_details.deployments | String | deployments simulator is part of. | 
| updated_simulator_details.created_at | String | Creation datetime of simulator. | 
| updated_simulator_details.updated_at | String | Update datetime of given simulator. | 
| updated_simulator_details.deleted_at | String | deletion datetime of given simulator. | 
| updated_simulator_details.assets | String | Assets of given simulator. | 
| updated_simulator_details.simulation_users | String | simulator users list. | 
| updated_simulator_details.proxies | String | Proxies of simulator. | 
| updated_simulator_details.advanced_actions | String | Advanced simulator details. | 

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
| updated_simulator_details.nodeId | String | Simulator ID | 
| updated_simulator_details.status | String | Simulator status | 

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
| updated_user_data.id | Number | The ID of User whose data has been updated. | 
| updated_user_data.name | String | The name of User after running the update command according to safebreach records. | 
| updated_user_data.email | String | the email of the user whose data has been updated by the command. | 
| updated_user_data.createdAt | String | the time at which the user who has been selected has been created | 
| updated_user_data.updatedAt | String | The last updated time of User selected for update.                       this will be the execution time for the command or close to it. | 
| updated_user_data.deletedAt | String | The Deletion time of User selected to update. Generally this is empty unless                      user chosen to update is a deleted user | 
| updated_user_data.roles | String | The roles of User updated. these will change if role has been updated during                      updating user details else they will be same as pre update. | 
| updated_user_data.description | String | The description of User after updating user, if description field has been given any                      new value during update then its updated else this will be left unchanged from previous value. | 
| updated_user_data.role | String | The roles and permissions related to user who has been selected for update.unless this field                      has been given a value , this will not be updated and will stay the same as previous value. | 
| updated_user_data.deployments | String | The deployments related to user, this will be comma separated values of deployment IDs | 
