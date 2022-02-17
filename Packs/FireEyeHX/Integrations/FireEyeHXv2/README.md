FireEye Endpoint Security is an integrated solution that detects what others miss and protects endpoint against known and unknown threats. This  integration provides access to information about endpoints, acquisitions, alerts, indicators, and containment. Customers can extract critical data and effectively operate security operations automated playbook
This integration was integrated and tested with version 6.1.0 of FireEyeHX v2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-fireeye-endpoint-security-(hx)-v2).

## Configure FireEye Endpoint Security (HX) v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FireEye Endpoint Security (HX) v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.168.0.1:3000) | True |
    | User Name | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |
    | Incident type | False |
    | Fetch limit | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 3 days) | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fireeye-hx-get-host-information
***
Get information on a host associated with an agent.


#### Base Command

`fireeye-hx-get-host-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentId | The agent ID. If the agent ID is not specified, the host Name must be specified. | Optional | 
| hostName | The host name. If the host name is not specified, the agent ID must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | Unknown | FireEye HX Agent ID. | 
| FireEyeHX.Hosts.agent_version | Unknown | The agent version. | 
| FireEyeHX.Hosts.excluded_from_containment | Unknown | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Unknown | Boolean value to indicate for containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Unknown | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | Unknown | The containment state of the host. Possible values normal|contain|contain_fail|containing|contained|uncontain|uncontaining|wtfc|wtfu | 
| FireEyeHX.Hosts.stats.alerting_conditions | Unknown | The number of conditions that have alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Unknown | Total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Unknown | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Unknown | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | Unknown | The host name. | 
| FireEyeHX.Hosts.domain | Unknown | Domain name. | 
| FireEyeHX.Hosts.timezone | Unknown | Host time zone. | 
| FireEyeHX.Hosts.primary_ip_address | Unknown | The host IP address. | 
| FireEyeHX.Hosts.last_poll_timestamp | Unknown | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | Unknown | Timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | Unknown | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | Unknown | Time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | Unknown | Specific operating system | 
| FireEyeHX.Hosts.os.bitness | Unknown | OS Bitness. | 
| FireEyeHX.Hosts.os.platform | Unknown | Family of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | Unknown | The host MAC address. | 

### fireeye-hx-get-all-hosts-information
***
Get information on all hosts.


#### Base Command

`fireeye-hx-get-all-hosts-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response, The default is 0. | Optional | 
| limit | Limit the number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | Unknown | FireEye HX Agent ID. | 
| FireEyeHX.Hosts.agent_version | Unknown | The agent version. | 
| FireEyeHX.Hosts.excluded_from_containment | Unknown | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Unknown | Boolean value to indicate for containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Unknown | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | Unknown | The containment state of the host. Possible values normal|contain|contain_fail|containing|contained|uncontain|uncontaining|wtfc|wtfu | 
| FireEyeHX.Hosts.stats.alerting_conditions | Unknown | The number of conditions that have alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Unknown | Total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Unknown | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Unknown | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | Unknown | The host name. | 
| FireEyeHX.Hosts.domain | Unknown | Domain name. | 
| FireEyeHX.Hosts.timezone | Unknown | Host time zone. | 
| FireEyeHX.Hosts.primary_ip_address | Unknown | The host IP address. | 
| FireEyeHX.Hosts.last_poll_timestamp | Unknown | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | Unknown | Timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | Unknown | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | Unknown | Time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | Unknown | Specific operating system | 
| FireEyeHX.Hosts.os.bitness | Unknown | OS Bitness. | 
| FireEyeHX.Hosts.os.platform | Unknown | Family of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | Unknown | The host MAC address. | 

### fireeye-hx-host-containment
***
Apply containment for a specific host, so that it no longer has access to other systems, If the user does not have the necessary permissions, the command will not approve the request, The permissions necessary to approve the request are api_admin role.


#### Base Command

`fireeye-hx-host-containment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostName | The host name to be contained. If the hostName is not specified, the agentId must be specified. | Optional | 
| agentId | The agent id running on the host to be contained. If the agentId is not specified, the hostName must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | Unknown | FireEye HX Agent ID. | 
| FireEyeHX.Hosts.agent_version | Unknown | The agent version. | 
| FireEyeHX.Hosts.excluded_from_containment | Unknown | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Unknown | Boolean value to indicate for containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Unknown | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | Unknown | The containment state of the host. Possible values normal|contain|contain_fail|containing|contained|uncontain|uncontaining|wtfc|wtfu | 
| FireEyeHX.Hosts.stats.alerting_conditions | Unknown | The number of conditions that have alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Unknown | Total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Unknown | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Unknown | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | Unknown | The host name. | 
| FireEyeHX.Hosts.domain | Unknown | Domain name. | 
| FireEyeHX.Hosts.timezone | Unknown | Host time zone. | 
| FireEyeHX.Hosts.primary_ip_address | Unknown | The host IP address. | 
| FireEyeHX.Hosts.last_poll_timestamp | Unknown | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | Unknown | Timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | Unknown | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | Unknown | Time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | Unknown | Specific operating system | 
| FireEyeHX.Hosts.os.bitness | Unknown | OS Bitness. | 
| FireEyeHX.Hosts.os.platform | Unknown | Family of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | Unknown | The host MAC address. | 

### fireeye-hx-cancel-containment
***
Release a specific host from containment.


#### Base Command

`fireeye-hx-cancel-containment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostName | The host name to be contained. If the hostName is not specified, the agentId must be specified. | Optional | 
| agentId | The agent id running on the host to be contained. If the agentId is not specified, the hostName must be specified. | Optional | 


#### Context Output

There is no context output for this command.
### fireeye-hx-initiate-data-acquisition
***
Initiate a data acquisition process to gather artifacts from the system disk and memory.


#### Base Command

`fireeye-hx-initiate-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script | Acquisition script in JSON format. | Optional | 
| scriptName | The script name. If the Acquisition script is specified, the script name must be specified as well. | Optional | 
| defaultSystemScript | Use default script. Select the host system. Possible values are: osx, win, linux. | Optional | 
| agentId | The agent ID. If the host name is not specified, the agent ID must be specified. | Optional | 
| hostName | The host name. If the agent ID is not specified, the host name must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | string | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Data.state | string | The acquisition state | 
| FireEyeHX.Acquisitions.Data.md5 | string | File md5 | 
| FireEyeHX.Acquisitions.Data.host._id | string | Agent ID | 
| FireEyeHX.Acquisitions.Data.host.hostname | string | Hostname | 
| FireEyeHX.Acquisitions.Data.instance | string | FIreEye HX instance | 
| FireEyeHX.Acquisitions.Data.finish_time | date | Time when the acquisition finished | 

### fireeye-hx-get-host-set-information
***
Get a list of all host sets known to your HX Series appliance.


#### Base Command

`fireeye-hx-get-host-set-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostSetID | ID of a specific host set to get. | Optional | 
| offset | Specifies which record to start with in the response. The offset value must be an unsigned 32-bit integer. The default is 0. | Optional | 
| limit | Specifies how many records are returned. The limit value must be an unsigned 32-bit integer. The default is 50. | Optional | 
| search | Searches the names of all host sets connected to the specified HX appliance. | Optional | 
| sort | Sorts the results by the specified field in ascending or descending order. The default is sorting by name in ascending order. Sortable fields are _id (host set ID) and name (host set name). | Optional | 
| name | Specifies the name of host set to look for. | Optional | 
| type | Specifies the type of host sets to search for. Possible values are: venn, static. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets._id | number | host set id | 
| FireEyeHX.HostSets._revision | string | Revision number | 
| FireEyeHX.HostSets.name | string | Host set name | 
| FireEyeHX.HostSets.type | string | Host set type \(static/dynamic/hidden\) | 
| FireEyeHX.HostSets.url | string | Host set FireEye url | 

### fireeye-hx-list-policy
***
Get a list of all policy.


#### Base Command

`fireeye-hx-list-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response, The default is 0. | Optional | 
| limit | Limit the number of results. | Optional | 
| policyName | The name of the policy. | Optional | 
| policyId | Unique policy ID. | Optional | 
| enabled | The policy is enabled ("true") or disabled ("false"). Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Policy._id | Unknown |  | 
| FireEyeHX.Policy.name | Unknown |  | 
| FireEyeHX.Policy.description | Unknown |  | 
| FireEyeHX.Policy.policy_type_id | Unknown |  | 
| FireEyeHX.Policy.priority | Unknown |  | 
| FireEyeHX.Policy.enabled | Unknown |  | 
| FireEyeHX.Policy.default | Unknown |  | 
| FireEyeHX.Policy.migrated | Unknown |  | 
| FireEyeHX.Policy.created_by | Unknown |  | 
| FireEyeHX.Policy.created_at | Unknown |  | 
| FireEyeHX.Policy.updated_at | Unknown |  | 
| FireEyeHX.Policy.categories | Unknown |  | 
| FireEyeHX.Policy.display_created_at | Unknown |  | 
| FireEyeHX.Policy.display_updated_at | Unknown |  | 

### fireeye-hx-list-host-set-policy
***
Get a list of all policies for all host sets.


#### Base Command

`fireeye-hx-list-host-set-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response, The default is 0. | Optional | 
| limit | Limit the number of results. | Optional | 
| hostSetId | . | Optional | 
| policyId | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets.Policy.policy_id | Unknown |  | 
| FireEyeHX.HostSets.Policy.persit_id | Unknown |  | 

### fireeye-hx-list-containment
***
Fetches all containment states across known hosts.


#### Base Command

`fireeye-hx-list-containment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response, The default is 0. | Optional | 
| limit | Limit the number of results. | Optional | 
| state_update_time | must be from type of -&gt; String: date-time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | Unknown |   | 
| FireEyeHX.Hosts.last_sysinfo | Unknown |   | 
| FireEyeHX.Hosts.requested_by_actor | Unknown |   | 
| FireEyeHX.Hosts.requested_on | Unknown |   | 
| FireEyeHX.Hosts.contained_by_actor | Unknown |   | 
| FireEyeHX.Hosts.contained_on | Unknown |   | 
| FireEyeHX.Hosts.queued | Unknown |   | 
| FireEyeHX.Hosts.excluded | Unknown |   | 
| FireEyeHX.Hosts.missing_software | Unknown |   | 
| FireEyeHX.Hosts.reported_clone | Unknown |   | 
| FireEyeHX.Hosts.state | Unknown |   | 
| FireEyeHX.Hosts.state_update_time | Unknown |   | 
| FireEyeHX.Hosts.url | Unknown |   | 

### fireeye-hx-search-list
***
Fetches all enterprise searches.


#### Base Command

`fireeye-hx-search-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Specifies which record to start with in the response, The default is 0. | Optional | 
| limit | Specifies how many records are returned, The default is 50. | Optional | 
| state | Filter by search state, you can choose between STOPPED or RUNNING. Possible values are: RUNNING, STOPPED. | Optional | 
| sort | Sorts the results by the specified field, The default is sorting by _id. Possible values are: _id, state, host_set._id, update_time, create_time, update_actor._id, update_actor.username, create_actor._id, create_actor.username. | Optional | 
| hostSetId | Filter searches by host set ID - &lt;Integer&gt;. | Optional | 
| searchId | Gets a single enterprise search record, If you enter this argument there is no need another arguments. | Optional | 
| actorUsername | Filter searches by username that created searches - &lt;String&gt;. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search._id | Unknown | Unique search ID | 
| FireEyeHX.Search.state | Unknown | The state of the search whether it stopped or running | 
| FireEyeHX.Search.scripts | Unknown | A list of reference objects for the scripts utilized in this search | 
| FireEyeHX.Search.update_time | Unknown | Time the search was updated last | 
| FireEyeHX.Search.create_time | Unknown | Time the search was created | 
| FireEyeHX.Search.scripts.platform | Unknown | Platform this script is used for | 
| FireEyeHX.Search.update_actor | Unknown | Actor who last updated the search | 
| FireEyeHX.Search.create_actor | Unknown | Actor who created the search | 
| FireEyeHX.Search.error | Unknown | Collection of errors per agents for the search | 
| FireEyeHX.Search._revision | Unknown | ETag that can be used for concurrency checking | 
| FireEyeHX.Search.input_type | Unknown | The input method that was used to start the search | 
| FireEyeHX.Search.url | Unknown | URI to retrieve data for this record | 
| FireEyeHX.Search.host_set | Unknown |  | 
| FireEyeHX.Search.stats | Unknown |  | 
| FireEyeHX.Search.stats.hosts | Unknown | Number of hosts running this operation | 
| FireEyeHX.Search.stats.skipped_hosts | Unknown | Number of hosts that were skipped | 
| FireEyeHX.Search.stats.search_state | Unknown | Number of search in different states | 
| FireEyeHX.Search.stats.search_issues | Unknown | Issues encountered for searches | 
| FireEyeHX.Search.settings.query_terms.terms | Unknown |  | 
| FireEyeHX.Search.stats.hosts.settings.query_terms.exhaustive_terms | Unknown |  | 
| FireEyeHX.Search.stats.settings.search_type | Unknown | The type of search. | 
| FireEyeHX.Search.stats.settings.exhaustive | Unknown | Whether a search is exhaustive or not | 
| FireEyeHX.Search.stats.settings.mode | Unknown | Whether a search is HOST type or GRID type | 
| FireEyeHX.Search.stats.settings.displayname | Unknown | Name of the search | 

### fireeye-hx-search-stop
***
Stops a specific running search.


#### Base Command

`fireeye-hx-search-stop`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchId | Unique search ID - Required. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search._id | Unknown | Unique search ID | 
| FireEyeHX.Search.state | Unknown | The state of the search whether it stopped or running | 
| FireEyeHX.Search.scripts | Unknown | A list of reference objects for the scripts utilized in this search | 
| FireEyeHX.Search.update_time | Unknown | Time the search was updated last | 
| FireEyeHX.Search.create_time | Unknown | Time the search was created | 
| FireEyeHX.Search.scripts.platform | Unknown | Platform this script is used for | 
| FireEyeHX.Search.update_actor | Unknown | Actor who last updated the search | 
| FireEyeHX.Search.create_actor | Unknown | Actor who created the search | 
| FireEyeHX.Search.error | Unknown | Collection of errors per agents for the search | 
| FireEyeHX.Search._revision | Unknown | ETag that can be used for concurrency checking | 
| FireEyeHX.Search.input_type | Unknown | The input method that was used to start the search | 
| FireEyeHX.Search.url | Unknown | URI to retrieve data for this record | 
| FireEyeHX.Search.host_set | Unknown |  | 
| FireEyeHX.Search.stats | Unknown |  | 
| FireEyeHX.Search.stats.hosts | Unknown | Number of hosts running this operation | 
| FireEyeHX.Search.stats.skipped_hosts | Unknown | Number of hosts that were skipped | 
| FireEyeHX.Search.stats.search_state | Unknown | Number of search in different states | 
| FireEyeHX.Search.stats.search_issues | Unknown | Issues encountered for searches | 
| FireEyeHX.Search.settings.query_terms.terms | Unknown |  | 
| FireEyeHX.Search.stats.hosts.settings.query_terms.exhaustive_terms | Unknown |  | 
| FireEyeHX.Search.stats.settings.search_type | Unknown | The type of search. | 
| FireEyeHX.Search.stats.settings.exhaustive | Unknown | Whether a search is exhaustive or not | 
| FireEyeHX.Search.stats.settings.mode | Unknown | Whether a search is HOST type or GRID type | 
| FireEyeHX.Search.stats.settings.displayname | Unknown | Name of the search | 

### fireeye-hx-search-result-get
***
Fetches the result for a specific enterprise search.


#### Base Command

`fireeye-hx-search-result-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchId | . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search.host._id | Unknown | Unique agent ID | 
| FireEyeHX.Search.host.url | Unknown | URI to retrieve data for this record | 
| FireEyeHX.Search.host.hostname | Unknown | Name of the host | 
| FireEyeHX.Search.results._id | Unknown | Unique ID | 
| FireEyeHX.Search.results.type | Unknown | Type of the search result data | 
| FireEyeHX.Search.results.data | Unknown | Object containing data relating to the search result for the host | 

### fireeye-hx-search
***
Search endpoints to check all hosts or a subset of hosts for a specific file or indicator.


#### Base Command

`fireeye-hx-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchId | searchId. | Optional | 
| agentsIds | IDs of agents to be searched. | Optional | 
| hostsNames | Names of hosts to be searched. | Optional | 
| hostSet | Id of host set to be searched. | Optional | 
| hostSetName | Name of host set to be searched. | Optional | 
| limit | Limit results count (once limit is reached, the search is stopped). | Optional | 
| exhaustive | Should search be exhaustive or quick. Possible values are: yes, no. Default is True. | Optional | 
| ipAddress | A valid IPv4 address to search for. | Optional | 
| ipAddressOperator | Which operator to apply to the given IP address. Possible values are: equals, not equals. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 
| fileMD5Hash | A 32-character MD5 hash value to search for. | Optional | 
| fileMD5HashOperator | Which operator to apply to the given MD5 hash. Possible values are: equals, not equals. | Optional | 
| fileFullPath | Full path of file to search. | Optional | 
| fileFullPathOperator | Which operator to apply to the given file path. Possible values are: equals, not equals, contains, not contains. | Optional | 
| dnsHostname | DNS value to search for. | Optional | 
| dnsHostnameOperator | Which operator to apply to the given DNS. Possible values are: equals, not equals, contains, not contains. | Optional | 
| stopSearch | Method in which search should be stopped after finding &lt;limit&gt; number of results. Possible values are: stopAndDelete, stop. | Optional | 
| fieldSearchName | searchable fields - if this argument selected, the 'fieldSearchOperator' and 'fieldSearchValue'  arguments are required. Possible values are: Application Name, Browser Name, Browser Version, Cookie Flags, Cookie Name, Cookie Value, Driver Device Name, Driver Module Name, Executable Exported Dll Name, Executable Exported Function Name, Executable Imported Function Name, Executable Imported Module Name, Executable Injected, Executable PE Type, Executable Resource Name, File Attributes, File Certificate Issuer, File Certificate Subject, File Download Mime Type, File Download Referrer, File Download Type, File Name, File SHA1 Hash, File SHA256 Hash, File Signature Exists, File Signature Verified, File Stream Name, File Text Written, Group Name, HTTP Header, Host Set, Hostname, Local IP Address, Local Port, Parent Process Name, Parent Process Path, Port, Port Protocol, Port State, Process Arguments, Process Name, Quarantine Event Sender Address, Quarantine Event Sender Name, Registry Key Full Path, Registry Key Value Name, Registry Key Value Text, Remote IP Address, Remote Port, Service DLL, Service Mode, Service Name, Service Status, Service Type, Size in bytes, Syslog Event ID, Syslog Event Message, Syslog Facility. | Optional | 
| fieldSearchOperator | Which operator to apply to the given search field. Possible values are: equals, not equals, contains, not contains, less than, greater than. | Optional | 
| fieldSearchValue | One or more values that match the selected search type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search.results.Timestamp - Modified | string | Time when the entry was last modified | 
| FireEyeHX.Search.results.File Text Written | string | The file text content | 
| FireEyeHX.Search.results.File Name | string | Name of the file | 
| FireEyeHX.Search.results.File Full Path | string | The full path of the file | 
| FireEyeHX.Search.results.File Bytes Written | string | Number of bytes written to the file | 
| FireEyeHX.Search.results.Size in bytes | string | Size of the file in bytes | 
| FireEyeHX.Search.results.Browser Version | string | Version of the browser | 
| FireEyeHX.Search.results.Browser Name | string | Name of the browser | 
| FireEyeHX.Search.results.Cookie Name | string | Name of the cookie | 
| FireEyeHX.Search.results.DNS Hostname | string | Name of the DNS host | 
| FireEyeHX.Search.results.URL | string | The event URL | 
| FireEyeHX.Search.results.Username | string | The event username | 
| FireEyeHX.Search.results.File MD5 Hash | string | MD5 hash of the file | 
| FireEyeHX.Search.host._id | string | ID of the host | 
| FireEyeHX.Search.host.hostname | string | Name of host | 
| FireEyeHX.Search.host.url | string | Inner FireEye host url | 
| FireEyeHX.Search.results.data | string | ID of performed search | 
| FireEyeHX.Search.results.Timestamp - Accessed | string | Last accessed time | 
| FireEyeHX.Search.results.Port | number | Port | 
| FireEyeHX.Search.results.Process ID | string | ID of the process | 
| FireEyeHX.Search.results.Local IP Address | string | Local IP Address | 
| FireEyeHX.Search.results.Local IP Address | string | Local IP Address | 
| FireEyeHX.Search.results.Local Port | number | Local Port | 
| FireEyeHX.Search.results.Username | string | Username | 
| FireEyeHX.Search.results.Remote Port | number | Remote Port | 
| FireEyeHX.Search.results.IP Address | string | IP Address | 
| FireEyeHX.Search.results.Process Name | string | Process Name | 
| FireEyeHX.Search.results.Timestamp - Event | string | Timestamp - Event | 
| FireEyeHX.Search.results.type | string | The type of the event | 
| FireEyeHX.Search.results.id | string | ID of the result | 

### fireeye-hx-get-alert
***
Get details of a specific alert.


#### Base Command

`fireeye-hx-get-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | The alert ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Alerts._id | Unknown | FireEye alert ID. | 
| FireEyeHX.Alerts.agent._id | Unknown | FireEye agent ID. | 
| FireEyeHX.Alerts.agent.containment_state | Unknown | Host containment state. | 
| FireEyeHX.Alerts.condition._id | Unknown | The condition unique ID. | 
| FireEyeHX.Alerts.event_at | Unknown | Time when the event occoured. | 
| FireEyeHX.Alerts.matched_at | Unknown | Time when the event was matched. | 
| FireEyeHX.Alerts.reported_at | Unknown | Time when the event was reported. | 
| FireEyeHX.Alerts.source | Unknown | Source of alert. | 
| FireEyeHX.Alerts.matched_source_alerts._id | Unknown | Source alert ID. | 
| FireEyeHX.Alerts.matched_source_alerts.appliance_id | Unknown | Appliance ID | 
| FireEyeHX.Alerts.matched_source_alerts.meta | Unknown | Source alert meta. | 
| FireEyeHX.Alerts.matched_source_alerts.indicator_id | Unknown | Indicator ID. | 
| FireEyeHX.Alerts.resolution | Unknown | Alert resulotion. | 
| FireEyeHX.Alerts.event_type | Unknown | Event type. | 

### fireeye-hx-suppress-alert
***
Suppress alert by ID.


#### Base Command

`fireeye-hx-suppress-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | The alert id. The alert id is listed in the output of 'get-alerts' command. | Required | 


#### Context Output

There is no context output for this command.
### fireeye-hx-get-indicators
***
Get a list of indicators.


#### Base Command

`fireeye-hx-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The indicator category. | Optional | 
| searchTerm | The searchTerm can be any name, category, signature, source, or condition value. | Optional | 
| shareMode | Determines who can see the indicator. You must belong to the correct authorization group . Possible values are: any, restricted, unrestricted, visible. | Optional | 
| sort | Sorts the results by the specified field in ascending  order. Possible values are: category, activeSince, createdBy, alerted. | Optional | 
| createdBy | Person who created the indicator. | Optional | 
| alerted | Whether the indicator resulted in alerts. Possible values are: yes, no. | Optional | 
| limit | Limit the number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators._id | Unknown | FireEye unique indicator ID. | 
| FireEyeHX.Indicators.name | Unknown | The indicator name as displayed in the UI. | 
| FireEyeHX.Indicators.description | Unknown | Indicator description. | 
| FireEyeHX.Indicators.category.name | Unknown | Catagory name. | 
| FireEyeHX.Indicators.created_by | Unknown | The "Created By" field as displayed in UI | 
| FireEyeHX.Indicators.active_since | Unknown | Date indicator became active. | 
| FireEyeHX.Indicators.stats.source_alerts | Unknown | Total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.alerted_agents | Unknown | Total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.platforms | Unknown | List of families of operating systems. | 
| FireEyeHX.Indicators.uri_name | String | URI formatted name of the indicator. | 
| FireEyeHX.Indicators.category.uri_name | String | URI name of the category. | 

### fireeye-hx-get-indicator
***
Get a specific indicator details.


#### Base Command

`fireeye-hx-get-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | Indicator category. Please use the `uri_category` value. | Required | 
| name | Indicator name. Please use the `uri_name` value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators._id | Unknown | FireEye unique indicator ID. | 
| FireEyeHX.Indicators.name | Unknown | The indicator name as displayed in the UI. | 
| FireEyeHX.Indicators.description | Unknown | Indicator description. | 
| FireEyeHX.Indicators.category.name | Unknown | Catagory name. | 
| FireEyeHX.Indicators.created_by | Unknown | The "Created By" field as displayed in UI | 
| FireEyeHX.Indicators.active_since | Unknown | Date indicator became active. | 
| FireEyeHX.Indicators.stats.source_alerts | Unknown | Total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.alerted_agents | Unknown | Total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.platforms | Unknown | List of families of operating systems. | 
| FireEyeHX.Conditions._id | Unknown | FireEye unique condition ID. | 
| FireEyeHX.Conditions.event_type | Unknown | Event type. | 
| FireEyeHX.Conditions.enabled | Unknown | Indicates whether the condition is enabled. | 

### fireeye-hx-append-conditions
***
Add conditions to an indicator. Conditions can be MD5, hash values, domain names and IP addresses.


#### Base Command

`fireeye-hx-append-conditions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The indicator category. Please use the `uri_category` value. | Required | 
| name | The name of the indicator. Please use the `uri_name` value. | Required | 
| condition | A list of conditions to add. The list can include a list of IPv4 addresses, MD5 files, and domain names. For example: example.netexample.orgexample.lol. | Required | 


#### Context Output

There is no context output for this command.
### fireeye-hx-search-delete
***
Delete the search, by ID.


#### Base Command

`fireeye-hx-search-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchId | The search ID. | Required | 


#### Context Output

There is no context output for this command.
### fireeye-hx-delete-file-acquisition
***
Delete the file acquisition, by ID.


#### Base Command

`fireeye-hx-delete-file-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisitionId | The acquisition ID. | Required | 


#### Context Output

There is no context output for this command.
### fireeye-hx-approve-containment
***
Approve pending containment requests made by other components or users, The permissions necessary are api_admin role.


#### Base Command

`fireeye-hx-approve-containment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentId | The Agent ID - this argument is required. | Required | 


#### Context Output

There is no context output for this command.
### fireeye-hx-assign-host-set-policy
***
Insert a new host set policy on your Endpoint Security server.


#### Base Command

`fireeye-hx-assign-host-set-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostSetId | The Host Set ID - this argument is required. | Required | 
| policyId | The Policy ID - this argument is required. | Required | 


#### Context Output

There is no context output for this command.
### fireeye-hx-get-data-acquisition
***
Gather artifacts from the system disk and memory for the given acquisition id. (The data is fetched as mans file)


#### Base Command

`fireeye-hx-get-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisitionId | The acquisition unique ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | string | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Data.state | string | The acquisition state. | 
| FireEyeHX.Acquisitions.Data.md5 | string | File md5. | 
| FireEyeHX.Acquisitions.Data.host._id | string | Agent ID | 
| FireEyeHX.Acquisitions.Data.finish_time | string | Time when the acquisition finished | 
| FireEyeHX.Acquisitions.Data.host.hostname | string | Hostname | 
| FireEyeHX.Acquisitions.Data.instance | date | FIreEye HX instance | 

### fireeye-hx-data-acquisition
***
Start a data acquisition process to gather artifacts from the system disk and memory. (The data is fetched as mans file)


#### Base Command

`fireeye-hx-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script | Acquisition script in JSON format. | Optional | 
| scriptName | The script name. If the Acquisition script is specified, the script name must be specified as well. | Optional | 
| defaultSystemScript | Use default script. Select the host system. Possible values are: osx, win, linux. | Optional | 
| agentId | The agent ID. If the host name is not specified, the agent ID must be specified. | Optional | 
| hostName | The host name. If the agent ID is not specified, the host name must be specified. | Optional | 
| acquisition_id | This argument is deprecated. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | Unknown | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Data.state | Unknown | The acquisition state. | 
| FireEyeHX.Acquisitions.Data.md5 | Unknown | File md5. | 
| FireEyeHX.Acquisitions.Data.finish_time | Unknown | Time when the acquisition was finished. | 
| FireEyeHX.Acquisitions.Data.host._id | unknown | Agent ID | 

### fireeye-hx-get-alerts
***
Get a list of alerts, use the different arguments to filter the results returned.


#### Base Command

`fireeye-hx-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hasShareMode | Identifies which alerts result from indicators with the specified share mode. Possible values are: any, restricted, unrestricted. | Optional | 
| resolution | Sorts the results by the specified field. Possible values are: active_threat, alert, block, partial_block. | Optional | 
| agentId | Filter by the agent ID. | Optional | 
| conditionId | Filter by condition ID. | Optional | 
| eventAt | Filter event occurred time. ISO-8601 timestamp.. | Optional | 
| alertId | Filter by alert ID. | Optional | 
| matchedAt | Filter by match detection time. ISO-8601 timestamp. | Optional | 
| minId | Filter that returns only records with an AlertId field value great than the minId value. | Optional | 
| reportedAt | Filter by reported time. ISO-8601 timestamp. | Optional | 
| IOCsource | Source of alert- indicator of compromise. Possible values are: yes. | Optional | 
| EXDsource | Source of alert - exploit detection. Possible values are: yes. | Optional | 
| MALsource | Source of alert - malware alert. Possible values are: yes. | Optional | 
| limit | Limit the results returned. | Optional | 
| sort | Sorts the results by the specified field in ascending order. Possible values are: agentId, conditionId, eventAt, alertId, matchedAt, id, reportedAt. | Optional | 
| sortOrder | The sort order for the results. Possible values are: ascending, descending. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Alerts._id | Unknown | FireEye alert ID. | 
| FireEyeHX.Alerts.agent._id | Unknown | FireEye agent ID. | 
| FireEyeHX.Alerts.agent.containment_state | Unknown | Host containment state. | 
| FireEyeHX.Alerts.condition._id | Unknown | The condition unique ID. | 
| FireEyeHX.Alerts.event_at | Unknown | Time when the event occoured. | 
| FireEyeHX.Alerts.matched_at | Unknown | Time when the event was matched. | 
| FireEyeHX.Alerts.reported_at | Unknown | Time when the event was reported. | 
| FireEyeHX.Alerts.source | Unknown | Source of alert. | 
| FireEyeHX.Alerts.matched_source_alerts._id | Unknown | Source alert ID. | 
| FireEyeHX.Alerts.matched_source_alerts.appliance_id | Unknown | Appliance ID | 
| FireEyeHX.Alerts.matched_source_alerts.meta | Unknown | Source alert meta. | 
| FireEyeHX.Alerts.matched_source_alerts.indicator_id | Unknown | Indicator ID. | 
| FireEyeHX.Alerts.resolution | Unknown | Alert resulotion. | 
| FireEyeHX.Alerts.event_type | Unknown | Event type. | 

### fireeye-hx-file-acquisition
***
Aquire a specific file as a password protected zip file. The password for unlocking the zip file is 'unzip-me'.


#### Base Command

`fireeye-hx-file-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisition_id | acquisition ID, This argument is deprecated. | Optional | 
| fileName | The file name. | Required | 
| filePath | The file path. | Required | 
| acquireUsing | Whether to aqcuire the file using the API or RAW. By default, raw file will be acquired. Use API option when file is encrypted. Possible values are: API, RAW. | Optional | 
| agentId | The agent ID associated with the host that holds the file. If the hostName is not specified, the agentId must be specified. | Optional | 
| hostName | The host that holds the file. If the agentId is not specified, hostName must be specified. | Optional | 
| polling | Whether to use Cortex XSOAR's built-in polling to retrieve the result when it's ready. Possible values are: true, false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. Default is 60. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Files._id | Unknown | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Files.state | Unknown | The acquisition state. | 
| FireEyeHX.Acquisitions.Files.md5 | Unknown | File md5. | 
| FireEyeHX.Acquisitions.Files.req_filename | Unknown | The file name. | 
| FireEyeHX.Acquisitions.Files.req_path | Unknown | The file path. | 
| FireEyeHX.Acquisitions.Files.host._id | Unknown | FireEye HX agent ID. | 

### fireeye-hx-create-indicator
***
Create new indicator


#### Base Command

`fireeye-hx-create-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The indicator category. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators.active_since | date | Date indicator became active. | 
| FireEyeHX.Indicators.meta | string | Meta data for new indicator | 
| FireEyeHX.Indicators.display_name | string | The indicator display name | 
| FireEyeHX.Indicators.name | string | The indicator name as displayed in the UI. | 
| FireEyeHX.Indicators.created_by | string | The "Created By" field as displayed in UI | 
| FireEyeHX.Indicators.url | string | The data URL | 
| FireEyeHX.Indicators.create_text | Unknown | The indicator create text | 
| FireEyeHX.Indicators.platforms | string | List of families of operating systems. | 
| FireEyeHX.Indicators.create_actor._id | number | The ID of the actor | 
| FireEyeHX.Indicators.create_actor.username | string | Actor user name | 
| FireEyeHX.Indicators.signature | string | Signature of indicator  | 
| FireEyeHX.Indicators._revision | string | Indicator revision | 
| FireEyeHX.Indicators._id | string | FireEye unique indicator ID. | 
| FireEyeHX.Indicator.description | string | Indicator description | 
| FireEyeHX.Indicators.category._id | number | Category ID | 
| FireEyeHX.Indicators.category.name | string | Category name | 
| FireEyeHX.Indicators.category.share_mode | string | Category share mode | 
| FireEyeHX.Indicators.category.uri_name | string | Category uri name | 
| FireEyeHX.Indicators.category.url | string | Category URL | 
| FireEyeHX.Indicators.uri_name | string | The indicator uri name | 
| FireEyeHX.Indicators.stats.active_conditions | number | Indicator active conditions | 
| FireEyeHX.Indicators.stats.alerted_agents | number | Total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.source_alerts | number | Total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.update_actor._id | number | Update actor ID | 
| FireEyeHX.Indicators.update_actor.username | string | Update actor name | 

### fireeye-hx-delete-host-set-policy
***
Delete a Host Set Policy.


#### Base Command

`fireeye-hx-delete-host-set-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostSetId | The Host Set Id. | Required | 
| policyId | The Policy Id. | Required | 


#### Context Output

There is no context output for this command.
