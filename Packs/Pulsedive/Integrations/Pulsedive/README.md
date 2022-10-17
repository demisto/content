Use the Pulsedive integration to get OSINT threatintel for incidents.

## Integrate Pulsedive into Cortex XSOAR

Leverage Pulsedive threat intelligence in Cortex XSOAR to enrich any domain, URL, or IP. Retrieve risk scores and factors, investigate contextual data, pivot on any data point, and investigate potential threats.
Register Free: https://pulsedive.com/login
About: https://pulsedive.com/about/
Contact: mailto:support@pulsedive.com

## Configure Pulsedive on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Pulsedive.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Key | True |
    | Trust any certificate (not secure) | False |


4. Click **Test** to validate that the integration can reach Pulsedive.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domains | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor| String | The vendor used to calculate the score. |
| Domain.Name | String | The domain name. |
| Domain.Malicious.Vendor| String | The vendor reporting the domain as malicious. |
| Domain.Malicious.Description| String | A description explaining why the domain was reported as malicious. |
| Domain.Registrant.Name | String | The name of the registrant. |
| Domain.Registrant.Country| String | The country of the registrant. |
| Domain.Organization | String | The organization of the domain. |
| Domain.CreationDate | String | The creation date of the domain. Format is ISO8601 (i.e. '2020-04-30T10:35:00.000Z'). |
| Domain.ExpirationDate| String | The expiration date of the domain. Format is ISO8601 (i.e. '2020-04-30T10:35:00.000Z'). |
| Domain.UpdatedDate | String | The date when the domain was last updated. Format is ISO8601 (i.e.'2020-04-30T10:35:00.000Z'). |
| Domain.NameServers | String | Name servers of the domain. |
| Domain.WHOIS.NameServers | String | A CSV string of name servers, for example 'ns1.bla.com, ns2.bla.com'. |
| Domain.WHOIS.CreationDate | Date | The creation date of the domain. Format is ISO8601 (i.e. '2020-04-30T10:35:00.000Z'). |
| Domain.WHOIS.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 (i.e.'2020-04-30T10:35:00.000Z'). |
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. |
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example 'GoDaddy' |
| IP.ASN | String | The autonomous system name for the IP address. |
| Pulsedive.Domain.address | String | Domain admin address. |
| Pulsedive.Domain.city | String | Domain admin city. |
| Pulsedive.Domain.country | String | Domain admin country. |
| Pulsedive.Domain.creation_date | String | Domain creation date. Format is ISO8601.|
| Pulsedive.Domain.dnssec | String | DNSSEC status. |
| Pulsedive.Domain.domain | String | The domain name. |
| Pulsedive.Domain.domain_name | String | Domain name options. |
| Pulsedive.Domain.emails | String | Contact emails. |
| Pulsedive.Domain.expiration_date | Date | Expiration date. Format is ISO8601. |
| Pulsedive.Domain.name | String | Domain admin name. |
| Pulsedive.Domain.name_servers | String | Name server. |
| Pulsedive.Domain.org | String | Domain organization. |
| Pulsedive.Domain.referral_url | String | Referral URL. |
| Pulsedive.Domain.registrar | String | Domain registrar. |
| Pulsedive.Domain.score | String | Reputation score from HelloWorld for this domain (0 to 100, where higher is worse). |
| Pulsedive.Domain.state | String | Domain admin state. |
| Pulsedive.Domain.status | String | Domain status. |
| Pulsedive.Domain.updated_date | String | Updated date. Format is ISO8601. |
| Pulsedive.Domain.whois_server | String | WHOIS server. |
| Pulsedive.Domain.zipcode | String | Domain admin zipcode. |


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs | Required | 

#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs | Required | 

#### Base Command

`pulsedive-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The value to scan | Required | 
| scan_type | You can choose between passive and active scanning. Default value is 'active' | Optional | 

#### Base Command

`pulsedive-scan-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qid | QID recieved from scan command | Required | 
