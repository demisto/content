This Integration is used to to fetch-incidents via “Active alerts”, get alert details via “Alert details”, and get the “Agent list”.
This integration was integrated and tested with version xx of ThousandEyes 

## Configure ThousandEyes  on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ThousandEyes .
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Base API URL | True |
    | Password | True |
    | Fetch incidents | False |
    | Incidents Fetch Interval | False |
    | Incident type | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False |
    | Minimum Severity to filter out the fetched alerts (only applicable for incidents) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### thousandeyes-get-alerts
***
Fetches all the alerts.


#### Base Command

`thousandeyes-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| aid | AID to fetch Active Alerts from. | Optional | 
| from_date | Explicit start date to fetch Alerts from. | Optional | 
| to_date | Explicit end date to fetch Alerts to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThousandEyes.Alerts.AlertID | unknown | unique ID of the alert; each alert occurrence is assigned a new unique ID | 
| ThousandEyes.Alerts.Active | unknown | 0 for inactive, 1 for active, 2 for disabled. Alert is disabled if either alert rule itself has been deleted or the test it is applied to has been disabled, deleted, disabled alerting, or disassociated the alert rule from the test | 
| ThousandEyes.Alerts.Agents | unknown | array of monitors where the alert has at some point been active since the point that the alert was triggered. Not shown on BGP alerts. | 
| ThousandEyes.Alerts.AID | unknown | Unique identifier of the Group AID | 
| ThousandEyes.Alerts.DateStart | unknown | the date/time where an alert rule was triggered, expressed in UTC | 
| ThousandEyes.Alerts.ApiLinks | unknown | list of hyperlinks to other areas of the API | 
| ThousandEyes.Alerts.PermaLink | unknown | hyperlink to alerts list, with row expanded | 
| ThousandEyes.Alerts.RuleExpression | unknown | string expression of alert rule | 
| ThousandEyes.Alerts.RuleID | unknown | unique ID of the alert rule | 
| ThousandEyes.Alerts.RuleName | unknown | name of the alert rule | 
| ThousandEyes.Alerts.TestID | unknown | unique ID of the test | 
| ThousandEyes.Alerts.TestName | unknown | name of the test | 
| ThousandEyes.Alerts.ViolationCount | unknown | number of sources currently meeting the alert criteria | 
| ThousandEyes.Alerts.Type | unknown | type of alert being triggered | 
| ThousandEyes.Alerts.Severity | unknown | field with one of the following values: INFO, MAJOR, MINOR, CRITICAL for all alert types | 


#### Command Example
``` ```

#### Human Readable Output



### thousandeyes-get-alert
***
Fetches a given alert.


#### Base Command

`thousandeyes-get-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to fetch. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### thousandeyes-get-agents
***
Fetches all agents.


#### Base Command

`thousandeyes-get-agents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThousandEyes.Agents.AgentID | unknown | unique ID of agent | 
| ThousandEyes.Agents.AgentName | unknown | display name of the agent | 
| ThousandEyes.Agents.AgentType | unknown | Cloud, Enterprise or Enterprise Cluster, shows the type of agent | 
| ThousandEyes.Agents.CountryID | unknown | ISO-3166-1 alpha-2 country code of the agent | 
| ThousandEyes.Agents.Enabled | unknown | 1 for enabled, 0 for disabled \(Enterprise Agents only\) | 
| ThousandEyes.Agents.KeepBrowserCache | unknown | 1 for enabled, 0 for disabled \(Enterprise Agents and Enterprise Clusters only\) | 
| ThousandEyes.Agents.VerifySslCertificates | unknown | 1 for enabled, 0 for disabled \(Enterprise Agents and Enterprise Clusters only\) | 
| ThousandEyes.Agents.IpAdresses | unknown | array of ipAddress entries | 
| ThousandEyes.Agents.LastSeen | unknown | yyyy-MM-dd hh:mm:ss, expressed in UTC \(Enterprise Agents only\) | 
| ThousandEyes.Agents.Location | unknown | location of the agent | 
| ThousandEyes.Agents.Network | unknown | name of the autonomous system in which the Agent is found \(Enterprise Agents only\) | 
| ThousandEyes.Agents.Prefix | unknown | Network prefix, expressed in CIDR format \(Enterprise Agents only\) | 
| ThousandEyes.Agents.PublicIpAddresses | unknown | array of ipAddress entries | 
| ThousandEyes.Agents.TargetForTests | unknown | target IP address or domain name representing test destination when agent is acting as a test target in an agent-to-agent test \(Enterprise Agents only\) | 
| ThousandEyes.Agents.AgentState | unknown | Online, Offline or Disabled \(standalone Enterprise Agents only\) | 
| ThousandEyes.Agents.Utilization | unknown | shows overall utilization percentage \(online Enterprise Agents and Enterprise Clusters only\) | 
| ThousandEyes.Agents.IPv6Policy | unknown | IP version policy, can be FORCE_IPV4, PREFER_IPV6 or FORCE_IPV6 \(Enterprise Agents and Enterprise Clusters only\) | 
| ThousandEyes.Agents.Hostname | unknown | fully qualified domain name of the agent \(Enterprise Agents only\) | 
| ThousandEyes.Agents.CreatedDate | unknown | yyyy-MM-dd hh:mm:ss, expressed in UTC. For Enterprise Clusters, this equals to the createdDate value of the initial cluster member before the conversion to cluster was performed \(Enterprise Agents and Enterprise Clusters only\) | 
| ThousandEyes.Agents.ErrorDetails | unknown | if an enterprise agent or a cluster member presents at least one error, the errors will be shown as an array of entries in the errorDetails field \(Enterprise Agents and Enterprise Cluster members only\) | 


#### Command Example
``` ```

#### Human Readable Output



### thousandeyes-get-agent
***
Fetches a given agent.


#### Base Command

`thousandeyes-get-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent ID to fetch. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### thousandeyes-test-fetch
***
Testing fetch incidents


#### Base Command

`thousandeyes-test-fetch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


