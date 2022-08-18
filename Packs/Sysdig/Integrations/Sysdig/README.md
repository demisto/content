Security for containers, Kubernetes, and cloud.
## Configure Sysdig on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Sysdig.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., https://us2.app.sysdig.com) | True |
    | Sysdig Monitor API Key | True |
    | Sysdig Secure API Key | True |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sysdig-get-alerts
***
Returns existing alerts


#### Base Command

`sysdig-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### sysdig-get-metrics
***
Returns current metrics


#### Base Command

`sysdig-get-metrics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### sysdig-get-users
***
Lists sysdig users


#### Base Command

`sysdig-get-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### sysdig-list-hosts
***
Lists container hosts


#### Base Command

`sysdig-list-hosts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| duration | Duration in seconds. Default is 86400. | Optional | 
| count | Number of hosts to return. Default is 100. | Optional | 
| print_json | Set to 'yes' to return raw json results. Possible values are: yes, no. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HostCount.Count | number | Count of hosts | 
| HostCount.DateAdded | date | Date added | 
| HostCount.Host | string | Hostname | 

### sysdig-get-events
***
List container events


#### Base Command

`sysdig-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventName | Name of container event. Possible values are: All, Container out of memory, Container died, Container Killed, Back Off Container Start or Image Pull, Container Unhealthy, Free Disk Space Failed, FailedScheduling, Killing Container, Pod Deleted, Scaling Replica Set, Pod Created, Container Image Pull, Create or Start Failed, Pod Create Failed, Updated load balancer with new hosts, Error updating load balancer with new hosts, Node Ready, Node Registered, Starting Kubelet, Removing Node, Deleting Node, Node not Ready, Node Rebooted. Default is All. | Optional | 
| limit | Max number of results to return. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Events.EventDescription | string | Event description | 
| Events.EventName | string | Event name | 
| Events.CreatedOn | date | Date created | 
| Events.EventType | string | Event type | 
| Events.EventId | string | Event Id | 
| Events.EventSource | string | Event source | 
| Events.Timestamp | date | Timestamp | 
| Events.EventSeverity | string | Event severity | 
| Events.EventScope | string | Event scope | 
| Events.EventVersion | string | Event version | 

### sysdig-list-policies
***
List sysdig policies


#### Base Command

`sysdig-list-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Policies.Description | string | Description | 
| Policies.Name | string | Name of policy | 

### sysdig-list-vulnerabilities
***
List container vulnerabilities


#### Base Command

`sysdig-list-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Max number of vulnerabilities to return. Default is 100. | Optional | 
| workloadType | Type of workload to query for vulnerabilities. Possible values are: all, daemonset, deployment, statefulset, pod, replicaset. Default is all. | Optional | 
| csv | Return csv output. Possible values are: yes, no. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContainerVulns.policyEvaluationsResult | unknown | Policy Evaluations Result | 
| ContainerVulns.exploitCount | unknown | Count of exploits | 
| ContainerVulns.storedAt | string | Time stored | 
| ContainerVulns.imageId | string | Image Id | 
| ContainerVulns.resultId | string | Result Id | 
| ContainerVulns.runningVulnsBySev | unknown | Running vulnerabilities by severity | 
| ContainerVulns.vulnsBySev | unknown | Vulnerabilities by severity | 

### sysdig-list-vulns-by-container
***
List individual vulnerabilities by container or pod


#### Base Command

`sysdig-list-vulns-by-container`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resultId | ID of container image to query (results from sysdig-list-policies). | Required | 
| limit | Number of results to return. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContainerVulns.vuln_cvssScore | string | CVSS score | 
| ContainerVulns.package_name | string | Name of vulnerable package | 
| ContainerVulns.vuln_cvssVersion | string | CVSS version | 
| ContainerVulns.vuln_exploitable | boolean | Is the vulnerability exploitable? | 
| ContainerVulns.vuln_name | string | Name of vulnerability | 
| ContainerVulns.package_type | string | Package type | 
| ContainerVulns.package_id | string | Package Id | 
| ContainerVulns.vuln_disclosureDate | date | Vulnerability disclosure date | 
| ContainerVulns.id | string | Id | 
| ContainerVulns.package_version | string | Package version | 
| ContainerVulns.fixedInVersion | string | Fixed version | 
