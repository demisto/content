This Integration is used to fetch-incidents via “Active alerts”, get alert details via “Alert details”, and get the “Agent list”.
It was integrated and tested with API v6 of ThousandEyes.

## Configure ThousandEyes  in Cortex


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

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| ThousandEyes.Alerts.AlertID | Integer | unique ID of the alert; each alert occurrence is assigned a new unique ID | 
| ThousandEyes.Alerts.Active | Integer | 0 for inactive, 1 for active, 2 for disabled. Alert is disabled if either alert rule itself has been deleted or the test it is applied to has been disabled, deleted, disabled alerting, or disassociated the alert rule from the test | 
| ThousandEyes.Alerts.Agents | Unknown | array of monitors where the alert has at some point been active since the point that the alert was triggered. Not shown on BGP alerts. | 
| ThousandEyes.Alerts.AID | Integer | Unique identifier of the Group AID | 
| ThousandEyes.Alerts.DateStart | Unknown | the date/time where an alert rule was triggered, expressed in UTC | 
| ThousandEyes.Alerts.ApiLinks | Unknown | list of hyperlinks to other areas of the API | 
| ThousandEyes.Alerts.PermaLink | String | hyperlink to alerts list, with row expanded | 
| ThousandEyes.Alerts.RuleExpression | String | string expression of alert rule | 
| ThousandEyes.Alerts.RuleID | Integer | unique ID of the alert rule | 
| ThousandEyes.Alerts.RuleName | String | name of the alert rule | 
| ThousandEyes.Alerts.TestID | Integer | unique ID of the test | 
| ThousandEyes.Alerts.TestName | String | name of the test | 
| ThousandEyes.Alerts.ViolationCount | Integer | number of sources currently meeting the alert criteria | 
| ThousandEyes.Alerts.Type | Integer | type of alert being triggered | 
| ThousandEyes.Alerts.Severity | Integer | field with one of the following values: INFO, MAJOR, MINOR, CRITICAL for all alert types | 


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
| ThousandEyes.Agents.AgentID | Integer | unique ID of agent | 
| ThousandEyes.Agents.AgentName | String | display name of the agent | 
| ThousandEyes.Agents.AgentType | String | Cloud, Enterprise or Enterprise Cluster, shows the type of agent | 
| ThousandEyes.Agents.CountryID | String | ISO-3166-1 alpha-2 country code of the agent | 
| ThousandEyes.Agents.Enabled | Boolean | 1 for enabled, 0 for disabled \(Enterprise Agents only\) | 
| ThousandEyes.Agents.KeepBrowserCache | Boolean | 1 for enabled, 0 for disabled \(Enterprise Agents and Enterprise Clusters only\) | 
| ThousandEyes.Agents.VerifySslCertificates | Boolean | 1 for enabled, 0 for disabled \(Enterprise Agents and Enterprise Clusters only\) | 
| ThousandEyes.Agents.IpAdresses | Unknown | array of ipAddress entries | 
| ThousandEyes.Agents.LastSeen | Unknown | yyyy-MM-dd hh:mm:ss, expressed in UTC \(Enterprise Agents only\) | 
| ThousandEyes.Agents.Location | String | location of the agent | 
| ThousandEyes.Agents.Network | String | name of the autonomous system in which the Agent is found \(Enterprise Agents only\) | 
| ThousandEyes.Agents.Prefix | String | Network prefix, expressed in CIDR format \(Enterprise Agents only\) | 
| ThousandEyes.Agents.PublicIpAddresses | Unknown | array of ipAddress entries | 
| ThousandEyes.Agents.TargetForTests | String | target IP address or domain name representing test destination when agent is acting as a test target in an agent-to-agent test \(Enterprise Agents only\) | 
| ThousandEyes.Agents.AgentState | String | Online, Offline or Disabled \(standalone Enterprise Agents only\) | 
| ThousandEyes.Agents.Utilization | Integer | shows overall utilization percentage \(online Enterprise Agents and Enterprise Clusters only\) | 
| ThousandEyes.Agents.IPv6Policy | String | IP version policy, can be FORCE_IPV4, PREFER_IPV6 or FORCE_IPV6 \(Enterprise Agents and Enterprise Clusters only\) | 
| ThousandEyes.Agents.Hostname | String | fully qualified domain name of the agent \(Enterprise Agents only\) | 
| ThousandEyes.Agents.CreatedDate | Unknown | yyyy-MM-dd hh:mm:ss, expressed in UTC. For Enterprise Clusters, this equals to the createdDate value of the initial cluster member before the conversion to cluster was performed \(Enterprise Agents and Enterprise Clusters only\) | 
| ThousandEyes.Agents.ErrorDetails | Unknown | if an enterprise agent or a cluster member presents at least one error, the errors will be shown as an array of entries in the errorDetails field \(Enterprise Agents and Enterprise Cluster members only\) | 


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