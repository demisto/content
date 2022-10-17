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

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested. | String |
| DBotScore.Score| The actual score.| Number
| DBotScore.Type| The indicator type.| String
| DBotScore.Vendor| The vendor used to calculate the score.| String
| Domain.Name| The domain name.| String
| Domain.Malicious.Vendor| The vendor reporting the domain as malicious.| String
| Domain.Malicious.Description| A description explaining why the domain was reported as malicious.| String
| Domain.Registrant.Name| The name of the registrant.| String
| Domain.Registrant.Country| The country of the registrant.| String
| Domain.Organization| The organization of the domain.| String
| Domain.CreationDate| The creation date of the domain. Format is ISO8601 (i.e. '2020-04-30T10:35:00.000Z').| Date
| Domain.ExpirationDate| The expiration date of the domain. Format is ISO8601 (i.e. '2020-04-30T10:35:00.000Z').| Date
| Domain.UpdatedDate| The date when the domain was last updated. Format is ISO8601 (i.e.'2020-04-30T10:35:00.000Z').| Date
| Domain.NameServers| Name servers of the domain.| String
| Domain.WHOIS.NameServers| A CSV string of name servers, for example 'ns1.bla.com, ns2.bla.com'.| String
| Domain.WHOIS.CreationDate| The creation date of the domain. Format is ISO8601 (i.e. '2020-04-30T10:35:00.000Z').| Date
| Domain.WHOIS.UpdatedDate| The date when the domain was last updated. Format is ISO8601 (i.e.'2020-04-30T10:35:00.000Z').| Date
| Domain.WHOIS.ExpirationDate| The expiration date of the domain.| Date
| Domain.WHOIS.Registrar.Name| The name of the registrar, for example 'GoDaddy'| String
| IP.ASN | The autonomous system name for the IP address.| String
| Pulsedive.Domain.address| Domain admin address.| String
| Pulsedive.Domain.city| Domain admin city.| String
| Pulsedive.Domain.country| Domain admin country.| String
| Pulsedive.Domain.creation_date| Domain creation date. Format is ISO8601.| Date
| Pulsedive.Domain.dnssec| DNSSEC status.| String
| Pulsedive.Domain.domain| The domain name.| String
| Pulsedive.Domain.domain_name| Domain name options.| String
| Pulsedive.Domain.emails| Contact emails.| String
| Pulsedive.Domain.expiration_date| Expiration date. Format is ISO8601.| Date
| Pulsedive.Domain.name| Domain admin name.| String
| Pulsedive.Domain.name_servers| Name server.| String
| Pulsedive.Domain.org| Domain organization.| String
| Pulsedive.Domain.referral_url| Referral URL.| Unknown
| Pulsedive.Domain.registrar| Domain registrar.| String
| Pulsedive.Domain.score| Reputation score from HelloWorld for this domain (0 to 100, where        higher is worse).| Number
| Pulsedive.Domain.state| Domain admin state.| String
| Pulsedive.Domain.status| Domain status.| String
| Pulsedive.Domain.updated_date| Updated date. Format is ISO8601.| Date
| Pulsedive.Domain.whois_server| WHOIS server.| String
| Pulsedive.Domain.zipcode| Domain admin zipcode.| Unknown

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
