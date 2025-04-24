Use the Digital Defense Frontline VM to identify and evaluate the security and business risks of network devices and applications deployed as premise, cloud, or hybrid network-based implementations.
This integration was integrated and tested with version 6.2.4 of Digital Defense FrontlineVM
## Configure Digital Defense FrontlineVM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| frontlineURL | Frontline VM URL | True |
| insecure | Trust any certificate \(not secure\) | False |
| apiToken | API Token to access Frontline VM | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| incidentSeverity | Minimum vulnerability severity for fetching incidents | False |
| incidentFrequency | Rate at which to check vulnerability events when fetching incidents | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### frontline-get-assets
***
Retrieves the asset's information from Frontline VM.


#### Base Command

`frontline-get-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address for which to return assets. | Optional | 
| label_name | The label name for which to return assets. | Optional | 
| max_days_since_scan | The number of days (retroactive) since the last scan. | Optional | 
| hostname | The hostname for which to return assets. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FrontlineVM.Hosts | unknown | The host data from Frontline.Cloud. | 
| FrontlineVM.Hosts.ID | unknown | The ID number of the host. | 
| FrontlineVM.Hosts.Hostname | unknown | The hostname of the asset. | 
| FrontlineVM.Hosts.IP | unknown | The IP address of the host. | 
| FrontlineVM.Hosts.DNSHostname | unknown | The DNS hostname of the host. | 
| FrontlineVM.Hosts.MAC | unknown | The MAC address of the host. | 
| FrontlineVM.Hosts.OS | unknown | The operating system of the host. | 
| FrontlineVM.Hosts.OSType | unknown | The operating system type of the host. | 
| FrontlineVM.Hosts.CriticalVulnCount | unknown | The severity count of critical vulnerabilities. | 


#### Command Example
``` ```

#### Human Readable Output



### frontline-get-vulns
***
Retrieves vulnerability information from Frontline VM.


#### Base Command

`frontline-get-vulns`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| min_severity | The minimum severity level for which to return vulnerabilities. This argument overrides the "severity" argument when used together. Can be: "critical","high","medium","low","trivial", or "info". | Optional | 
| severity | Returns all vulnerabilities from Frontline with the specified severity level. Can be: "critical","high","medium","low","trivial", or "info". | Optional | 
| max_days_since_created | Retrieves vulnerabilities found prior to the specified date (in days). | Optional | 
| min_days_since_created | Retrieves vulnerabilities found after the specified date (in days). | Optional | 
| host_id | Retrieves vulnerabilities from a specific host based on the Host ID. | Optional | 
| ip_address | The IP address of the host for which to retrieve the vulnerability data. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FrontlineVM.Vulns | unknown | Retrieved vulnerability data pulled from Frontline.Cloud. | 
| FrontlineVM.Stat | unknown | The statistical overview of vulnerabilities pulled. | 
| FrontlineVM.Vulns.vuln-id | unknown | The ID of the vulnerability. | 
| FrontlineVM.Vulns.hostname | unknown | The hostname of the asset. | 
| FrontlineVM.Vulns.ip-address | unknown | The IP address of the asset. | 
| FrontlineVM.Vulns.vuln-title | unknown | The title of the vulnerability. | 
| FrontlineVM.Vulns.date-created | unknown | The date the vulnerability was created. | 
| FrontlineVM.Vulns.ddi-severity | unknown | The severity level of the vulnerability. | 
| FrontlineVM.Vulns.vuln-info | unknown | Information related to the vulnerability. | 


#### Command Example
``` ```

#### Human Readable Output



### frontline-scan-asset
***
Performs a scan on the specified asset.


#### Base Command

`frontline-scan-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address of the asset to scan. | Optional | 
| scan_policy | The policy of the scan (case sensitive). | Optional | 
| ip_range_start | The IP address start range of the asset to scan. | Optional | 
| ip_range_end | The IP address end range of the asset to scan. | Optional | 
| scan_name | The name of this scan to run in FrontlineVM. Default value will be "Cortex XSOAR Scan [&lt;asset_ip_address&gt;]" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FrontlineVM.Scan.ID | unknown | The ID number of the scan. | 
| FrontlineVM.Scan.Name | unknown | The name of the scan. | 
| FrontlineVM.Scan.Policy | unknown | The policy name of the scan. | 
| FrontlineVM.Scan.IP | unknown | The IP address of the scan \(can be a single IP address or a range of IP addresses\). | 


#### Command Example
``` ```

#### Human Readable Output

