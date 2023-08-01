This is the Hello World integration for getting started.
## Configure TestDan on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for TestDan.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    | Server URL (e.g. https://soar.monstersofhack.com) |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Maximum number of incidents per fetch |  | False |
    | API Key |  | True |
    | Score threshold for IP reputation command | Set this to determine the HelloWorld score that will determine if an IP is malicious \(0-100\) | False |
    | Score threshold for domain reputation command | Set this to determine the HelloWorld score that will determine if a domain is malicious \(0-100\) | False |
    | Fetch alerts with status (ACTIVE, CLOSED) |  | False |
    | Fetch alerts with type | Comma-separated list of types of alerts to fetch. Types might change over time. Some examples are 'Bug' and 'Vulnerability' | False |
    | Minimum severity of alerts to fetch |  | True |
    | First fetch time |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### helloworld-say-hello

***
Hello command - prints hello to anyone.

#### Base Command

`helloworld-say-hello`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of whom you want to say hello to. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| hello | String | Should be Hello \*\*something\*\* here. | 

### helloworld-search-alerts

***
Search HelloWorld Alerts.

#### Base Command

`helloworld-search-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | Filter by alert severity. Comma-separated value (Low,Medium,High,Critical). | Optional | 
| status | Filter by alert status. Possible values are: ACTIVE, CLOSED. | Optional | 
| alert_type | Filter by alert type. | Optional | 
| max_results | Maximum results to return. | Optional | 
| start_time | Filter by start time. <br/>Examples:<br/>  "3 days ago"<br/>  "1 month"<br/>  "2019-10-10T12:22:00"<br/>  "2019-10-10". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Alert.alert_id | String | Alert ID. | 
| HelloWorld.Alert.alert_status | String | Alert status. Can be 'ACTIVE' or 'CLOSED'. | 
| HelloWorld.Alert.alert_type | String | Alert type. For example 'Bug' or 'Vulnerability'. | 
| HelloWorld.Alert.created | Date | Alert created time. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| HelloWorld.Alert.name | String | Alert name. | 
| HelloWorld.Alert.severity | String | Alert severity. Can be 'Low', 'Medium', 'High' or 'Critical'. | 

### helloworld-get-alert

***
Retrieve alert extra data by ID.

#### Base Command

`helloworld-get-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Alert.alert_id | String | Alert ID. | 
| HelloWorld.Alert.created | Date | Alert created time. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| HelloWorld.Alert.description | String | Alert description. | 
| HelloWorld.Alert.device_id | String | ID of the device involved in the alert. | 
| HelloWorld.Alert.device_ip | String | IP Address of the device involved in the alert. | 
| HelloWorld.Alert.location | String | Location of the device involved in the alert. | 
| HelloWorld.Alert.user | String | User involved in the alert. | 

### helloworld-update-alert-status

***
Update the status for an alert.

#### Base Command

`helloworld-update-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to update. | Required | 
| status | New status of the alert. Possible values are: ACTIVE, CLOSED. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Alert.alert_id | String | Alert ID. | 
| HelloWorld.Alert.updated | Date | Alert update time. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| HelloWorld.Alert.alert_status | String | Alert status. Can be 'ACTIVE' or 'CLOSED'. | 

### ip

***
Return IP information and reputation

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 
| threshold | If the IP has reputation above the threshold then the IP defined as malicious. If threshold not set, then threshold from instance configuration is used. Default is 65. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| HelloWorld.IP.asn | String | The autonomous system name for the IP address. | 
| HelloWorld.IP.asn_cidr | String | The ASN CIDR. | 
| HelloWorld.IP.asn_country_code | String | The ASN country code. | 
| HelloWorld.IP.asn_date | Date | The date on which the ASN was assigned. | 
| HelloWorld.IP.asn_description | String | The ASN description. | 
| HelloWorld.IP.asn_registry | String | The registry the ASN belongs to. | 
| HelloWorld.IP.entities | String | Entities associated to the IP. | 
| HelloWorld.IP.ip | String | The actual IP address. | 
| HelloWorld.IP.network.cidr | String | Network CIDR for the IP address. | 
| HelloWorld.IP.network.country | Unknown | The country of the IP address. | 
| HelloWorld.IP.network.end_address | String | The last IP address of the CIDR. | 
| HelloWorld.IP.network.events.action | String | The action that happened on the event. | 
| HelloWorld.IP.network.events.actor | Unknown | The actor that performed the action on the event. | 
| HelloWorld.IP.network.events.timestamp | String | The timestamp when the event occurred. | 
| HelloWorld.IP.network.handle | String | The handle of the network. | 
| HelloWorld.IP.network.ip_version | String | The IP address version. | 
| HelloWorld.IP.network.links | String | Links associated to the IP address. | 
| HelloWorld.IP.network.name | String | The name of the network. | 
| HelloWorld.IP.network.notices.description | String | The description of the notice. | 
| HelloWorld.IP.network.notices.links | Unknown | Links associated with the notice. | 
| HelloWorld.IP.network.notices.title | String | Title of the notice. | 
| HelloWorld.IP.network.parent_handle | String | Handle of the parent network. | 
| HelloWorld.IP.network.raw | Unknown | Additional raw data for the network. | 
| HelloWorld.IP.network.remarks | Unknown | Additional remarks for the network. | 
| HelloWorld.IP.network.start_address | String | The first IP address of the CIDR. | 
| HelloWorld.IP.network.status | String | Status of the network. | 
| HelloWorld.IP.network.type | String | The type of the network. | 
| HelloWorld.IP.query | String | IP address that was queried. | 
| HelloWorld.IP.raw | Unknown | Additional raw data for the IP address. | 
| HelloWorld.IP.score | Number | Reputation score from HelloWorld for this IP \(0 to 100, where higher is worse\). | 
| IP.Address | String | IP address. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.ASN | String | The autonomous system name for the IP address. | 
| IP.Relationships.EntityA | string | The source of the relationship. | 
| IP.Relationships.EntityB | string | The destination of the relationship. | 
| IP.Relationships.Relationship | string | The name of the relationship. | 
| IP.Relationships.EntityAType | string | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. | 

### domain

***
Returns Domain information and reputation.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Optional | 
| threshold | If the domain has reputation above the threshold then the domain defined as malicious. If threshold not set, then threshold from instance configuration is used. Default is 65. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.CreationDate | Date | The creation date of the domain. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.ExpirationDate | Date | The expiration date of the domain. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.NameServers | String | Name servers of the domain. | 
| Domain.WHOIS.NameServers | String | A CSV string of name servers, for example 'ns1.bla.com, ns2.bla.com'. | 
| Domain.WHOIS.CreationDate | Date | The creation date of the domain. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.WHOIS.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example 'GoDaddy' | 
| IP.ASN | String | The autonomous system name for the IP address. | 
| HelloWorld.Domain.address | String | Domain admin address. | 
| HelloWorld.Domain.city | String | Domain admin city. | 
| HelloWorld.Domain.country | String | Domain admin country. | 
| HelloWorld.Domain.creation_date | Date | Domain creation date. Format is ISO8601. | 
| HelloWorld.Domain.dnssec | String | DNSSEC status. | 
| HelloWorld.Domain.domain | String | The domain name. | 
| HelloWorld.Domain.domain_name | String | Domain name options. | 
| HelloWorld.Domain.emails | String | Contact emails. | 
| HelloWorld.Domain.expiration_date | Date | Expiration date. Format is ISO8601. | 
| HelloWorld.Domain.name | String | Domain admin name. | 
| HelloWorld.Domain.name_servers | String | Name server. | 
| HelloWorld.Domain.org | String | Domain organization. | 
| HelloWorld.Domain.referral_url | Unknown | Referral URL. | 
| HelloWorld.Domain.registrar | String | Domain registrar. | 
| HelloWorld.Domain.score | Number | Reputation score from HelloWorld for this domain \(0 to 100, where higher is worse\). | 
| HelloWorld.Domain.state | String | Domain admin state. | 
| HelloWorld.Domain.status | String | Domain status. | 
| HelloWorld.Domain.updated_date | Date | Updated date. Format is ISO8601. | 
| HelloWorld.Domain.whois_server | String | WHOIS server. | 
| HelloWorld.Domain.zipcode | Unknown | Domain admin zipcode. | 

### helloworld-scan-start

***
Start scan on an asset.

#### Base Command

`helloworld-scan-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Asset to start the scan against. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Scan.scan_id | string | Unique ID of the scan. | 
| HelloWorld.Scan.status | string | Status of the scan \('RUNNING' or 'COMPLETE'\). | 
| HelloWorld.Scan.hostname | string | The hostname the scan is run against. | 

### helloworld-scan-status

***
Retrieve scan status for one or more scan IDs.

#### Base Command

`helloworld-scan-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | List of Scan IDs. helloworld-scan-start returns "scan_id". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Scan.scan_id | string | Unique ID of the scan. | 
| HelloWorld.Scan.status | string | Status of the scan \('RUNNING' or 'COMPLETE'\). | 

### helloworld-scan-results

***
Retrieve scan status in Context or as a File (default) for a Scan.

#### Base Command

`helloworld-scan-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | Results format (file or JSON). Possible values are: json, file. Default is file. | Required | 
| scan_id | Unique ID of the scan. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Scan.entities.entity-id | String | Scanned entity ID. | 
| HelloWorld.Scan.entities.ip_address | String | Scanned entity IP address. | 
| HelloWorld.Scan.entities.type | String | Scanned entity type. | 
| HelloWorld.Scan.entities.vulnerability_status | String | Scanned entity vulnerability status. | 
| HelloWorld.Scan.entities.vulns | String | Scanned entity CVE. | 
| HelloWorld.Scan.scan_id | String | Unique ID of the scan. | 
| HelloWorld.Scan.status | String | Status of the scan \('RUNNING' or 'COMPLETE'\). | 
| InfoFile.EntryID | Unknown | The EntryID of the report file. | 
| InfoFile.Extension | string | The extension of the report file. | 
| InfoFile.Name | string | The name of the report file. | 
| InfoFile.Info | string | The info of the report file. | 
| InfoFile.Size | number | The size of the report file. | 
| InfoFile.Type | string | The type of the report file. | 
| CVE.ID | string | The ID of the CVE. | 
