This integration uses Farsight Security’s DNSDB solution to interactively lookup rich, historical DNS information – either as playbook tasks or through API calls in the War Room – to access rdata and rrset records.

**To set up Farsight Security DNSDB to work with Cortex XSOAR:**
----------------------------------------------------------------

User will need DNSDB’s API key and service URL for connecting to the Cortex XSOAR server.

## Configure Farsight DNSDB in Cortex


| **Parameter** | **Required** |
| --- | --- |
| DNSDB Service URL | True |
| API Key | True |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dnsdb-rdata

***
Lookup rdata records

#### Base Command

`dnsdb-rdata`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | query type. Possible values are: name, ip, raw. | Required | 
| value | query value. | Required | 
| limit | Limit the number of returned records. Default is 100. | Optional | 
| time_first_before | Filter results for entries seen for first time before (seconds). | Optional | 
| time_last_before | Filter results for entries seen last time before (seconds). | Optional | 
| time_first_after | filter results for entries seen first time after (seconds). | Optional | 
| time_last_after | filter results for entries seen last time after (seconds). | Optional | 
| rrtype | query rrtype. | Optional | 

#### Context Output

There is no context output for this command.
### dnsdb-rrset

***
Lookup rrser records

#### Base Command

`dnsdb-rrset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owner | Owner name to query. | Required | 
| rrtype | rrtype value to query. | Optional | 
| bailiwick | Bailiwick value to query. | Optional | 
| limit | Limit the number of returned records. Default is 100. | Optional | 
| time_first_before | Filter results for entries seen for first time before (seconds). | Optional | 
| time_first_after | Filter results for entries seen for first time after (seconds). | Optional | 
| time_last_before | Filter results for entries seen for last time before (seconds). | Optional | 
| time_last_after | Filter results for entries seen for last time after (seconds). | Optional | 

#### Context Output

There is no context output for this command.