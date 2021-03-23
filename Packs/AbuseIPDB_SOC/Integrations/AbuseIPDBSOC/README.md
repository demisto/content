Central repository to report and identify IP addresses that have been associated with malicious activity online. Check the Detailed Information section for more information on how to configure the integration.
This integration was integrated and tested with version xx of AbuseIPDB_SOC
## Configure AbuseIPDB_SOC on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AbuseIPDB_SOC.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | AbuseIP server URL |  | True |
    | API Key (v2) |  | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Minimum score threshold |  | False |
    | Maximum reports age (in days) |  | False |
    | Disregard quota errors |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Checks the specified IP address against the AbuseIP database.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to check (CSV supported). | Optional | 
| days | The time range to return reports (in days). Default is 30. Default is 30. | Optional | 
| verbose | The length of the report. "true" returns the full report, "false" does not return reported categories. Default is "true". Possible values are: true, false. Default is true. | Optional | 
| threshold | The minimum score from AbuseIPDB to consider whether the IP address is malicious (must be greater than 20). Default is 80. Default is 80. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The address of the IP. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Detections | String | The Detections that led to the verdict. | 
| AbuseIPDB.IP.Address | String | The IP address fetched from AbuseIPDB. | 
| AbuseIPDB.IP.AbuseConfidenceScore | String | The confidence score fetched from AbuseIPDB. | 
| AbuseIPDB.IP.TotalReports | Number | The number of times the address has been reported. | 
| AbuseIPDB.IP.Geo.Country | String | The country associated with the IP Address. | 
| AbuseIPDB.IP.Reports | String | The reports summary \(for "verbose" reports\). | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| AbuseIPDB.IP.Malicious.Vendor | String | The vendor that determined this IP address to be malicious. | 
| AbuseIPDB.IP.Malicious.Detections | String | The Detections that led to the verdict. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| AbuseIPDB.IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 


#### Command Example
``` ```

#### Human Readable Output



### abuseipdb-check-cidr-block
***
Queries a block of IP addresses to check against the database.


#### Base Command

`abuseipdb-check-cidr-block`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network | IPv4 Address Block in CIDR notation. | Required | 
| days | The time range to return reports (in days). Default is 30. Default is 30. | Optional | 
| limit | The maximum number of IPs to check. Default is 40. Default is 40. | Optional | 
| threshold | The minimum score from AbuseIPDB to consider whether the IP address is malicious (must be greater than 20). Default is 80. Default is 80. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Detections | String | The Detections that led to the verdict. | 
| AbuseIPDB.IP.Address | String | The IP address fetched from AbuseIPDB. | 
| AbuseIPDB.IP.AbuseConfidenceScore | Unknown | The confidence score fetched from AbuseIPDB. | 
| AbuseIPDB.IP.TotalReports | Unknown | The number of times this address has been reported. | 
| AbuseIPDB.IP.Geo.Country | Unknown | The country associated with this IP Address. | 
| AbuseIPDB.IP.Reports | Unknown | Reports summary \(for "verbose" reports\). | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| AbuseIPDB.IP.Malicious.Vendor | String | The vendor used to calculate the score. | 
| AbuseIPDB.IP.Malicious.Detections | String | The Detections that led to the verdict. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 


#### Command Example
``` ```

#### Human Readable Output



### abuseipdb-report-ip
***
Reports an IP address to AbuseIPDB.


#### Base Command

`abuseipdb-report-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to report. | Required | 
| categories | A CSV list of category IDs. For more information, see https://www.abuseipdb.com/categories. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### abuseipdb-get-blacklist
***
Returns a list of the most reported IP addresses.


#### Base Command

`abuseipdb-get-blacklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| days | The time range to return reports (in days). Default is 30. Default is 30. | Optional | 
| limit | The maximum number of IPs to retrieve. Default is 50. . Default is 50. | Optional | 
| saveToContext | Whether to save a list of blacklisted IPs in the Context Data in Demisto. Default is false. Possible values are: true, false. Default is false. | Optional | 
| confidence | The Minimum confidence required for the retrieved IPs. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbuseIPDB.Blacklist | Unknown | A list of blacklisted IP addresses. | 


#### Command Example
``` ```

#### Human Readable Output



### abuseipdb-get-categories
***
Returns a list of report categories from AbuseIPDB.


#### Base Command

`abuseipdb-get-categories`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AbuseIPDB.Categories | string | The list of AbuseIPDB categories. | 


#### Command Example
``` ```

#### Human Readable Output


