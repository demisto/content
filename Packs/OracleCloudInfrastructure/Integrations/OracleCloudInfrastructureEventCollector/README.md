This integration fetches audit log events from an Oracle Cloud Infrastructure resources.
Audit log events can be used for security audits, to track usage of and changes to Oracle Cloud Infrastructure resources, and to help ensure compliance with standards or regulations.

## Required Permissions

[Required Permissions for collecting audit logs](https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/audit_logs.htm#audit_logs__reqd-perm-auditlogs)
[Required IAM policy for collecting audit logs](https://docs.oracle.com/en-us/iaas/Content/Audit/Tasks/viewinglogevents.htm)
[Oracle Cloud Infrastructure Audit API Endpoints (available Regions)](https://docs.oracle.com/en-us/iaas/api/#/en/audit/20190901)

## Configure Oracle Cloud Infrastructure Event Collector in Cortex

#### OCI Related Parameters

Oracle Cloud Infrastructure SDKs and CLI require basic configuration information, which is achieved by using configuration parameters either with a configuration file or a runtime defined configuration dictionary. This integration uses the runtime defined configuration dictionary.
More about OCI configuration [here](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm).

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Tenancy OCID |  | True |
| User OCID |  | True |
| API Key Fingerprint |  | True |
| API Private Key |  | True |
| API Private Key Type | The default value is PKCS\#8. For more information about the difference between the 2 types follow the link https://stackoverflow.com/questions/48958304/pkcs1-and-pkcs8-format-for-rsa-private-key | False |
| Region | Must be one the available regions for Oracle Cloud Infrastructure. For more information see the integration's description. | True |
| Compartment OCID | The default value is the Tenancy OCID parameter. In case a Compartment ID is given, it will override the default value. To get the value see the link https://docs.oracle.com/en-us/iaas/Content/GSG/Tasks/contactingsupport_topic-Locating_Oracle_Cloud_Infrastructure_IDs.htm\#Finding_the_OCID_of_a_Compartment | False |
| Fetch Events |  | False |
| Events Fetch Interval |  | False |
| First fetch time | This parameter is relevant for 'Audit' and 'CloudGuard Problems' events only. | False |
| Maximum number of events to fetch per type. |  | False |
| Event types to fetch | The type of the events to fetch. Default value is 'Audit'. | True |
| Search log query | Query corresponding to the search operation. | False |
| CloudGuard Problems query | Filters for CloudGuard Problems as key=value pairs separated by ";" \(for example: riskLevel=CRITICAL;lifecycleState=ACTIVE\). Each pair is passed as a ListProblems query parameter. Leave empty to fetch all Problems. CloudGuard Problems are fetched from the configured Region, which must be the Cloud Guard reporting region. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute the following command from the CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

#### oracle-cloud-infrastructure-get-events

***
Manual command to fetch and display events.

#### Base Command

`oracle-cloud-infrastructure-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to true in order to create events, otherwise the command will only display them. Default is false. | True |
