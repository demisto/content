# Group-IB Threat Intelligence

Pack helps to integrate Group-IB Threat Intelligence and get incidents directly into Cortex XSOAR.
The integration supports multiple collections including compromised accounts, bank cards, breaches, malware, attacks, OSI leaks, vulnerabilities, and threat intelligence. See the [Data Collections Overview](#data-collections-overview) section below for the complete list with descriptions and recommended date ranges.

## Prerequisites

1. **Access Group-IB Threat Intelligence (TI) Web Interface**
   - Open the Group-IB TI platform at [https://tap.group-ib.com](https://tap.group-ib.com)

2. **Generate API Credentials**
   - In the web interface, click your name in the upper right corner
   - Select **Profile** → **Security and Access** tab
   - Click **Personal token** and follow the instructions to generate your API token
   - **Note**: The API token serves as your password for authentication

3. **Network Configuration**
   - **Important**: Contact Group-IB support to add your Cortex XSOAR server's IP address to the allow list
   - If you are using a proxy, provide the public IP address of the proxy server instead
   - Make sure you have added Group-IB [API IPs/URLs](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FInitial%20Steps%2FInitial%20Steps) to you FW/Proxy rules.

## Important Notes

### Limit Parameter

The **Limit (items per request)** parameter specifies the number of records requested per API page. This limit applies to **all collections** configured in the integration instance.

**Important considerations:**

- The limit determines how many records are fetched in a **single API request**. For example, if "Number of requests per collection" is set to 2 and the limit is 500, the integration will make 2 requests per collection, each requesting up to 500 records, resulting in up to 1000 records per collection per fetch cycle.
- Different collections may have different optimal limit values based on their data structure and API recommendations. We strongly recommend consulting the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) for specific limit recommendations for each collection.
- **Best practice**: Create separate integration instances for different collections or groups of collections that share similar optimal limit values. This allows you to optimize performance for each collection type.

### Collection-Specific Filters

The following three filters control data collection behavior for the `compromised/account_group` collection:

- **Include unique type in data**: Filter to include unique data from the compromised/account_group collection
- **Include combolist type in data**: Filter to include combolist data from the compromised/account_group collection
- **Enable filter "Probable Corporate Access"**: Filter to limit data collection to only corporate accounts

**Filter Logic** (applies to unique and combolist filters):

- If **both** `Include unique type in data` and `Include combolist type in data` are **disabled**: No filtering is applied, and both types of data are collected
- If **only** `Include unique type in data` is **enabled**: Only unique records are collected
- If **only** `Include combolist type in data` is **enabled**: Only combolist records are collected
- If **both** `Include unique type in data` and `Include combolist type in data` are **enabled**: Both types of data are collected
- When both unique and combolist filters are **not enabled** (no checkboxes selected): Both unique and combolist data types are collected by default (as stated above). In this state, you can enable `Enable filter "Probable Corporate Access"` to limit the entire feed (both unique and combolist data) to only corporate accounts. You can also combine the corporate access filter with unique or combolist filters, if needed. For example, if you are collecting **only combolist** data (without unique), you can enable `Enable filter "Probable Corporate Access"` to limit the combolist collection to only corporate accounts

**Best Practice**: For optimal organization and performance, consider running **two separate integration instances**:

- **Instance 1**: Enable `Include unique type in data` only
- **Instance 2**: Enable `Include combolist type in data` only
- **Instance 3** (optional): Enable 'Probable Corporate Access' - if you need to focus on your company employees compromises only

These filters have no effect on other collections.

## Data Collections Overview

Once the configuration is complete, the following collections become available in Cortex XSOAR. For detailed information about each collection, its structure, and available fields, please refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).

**Note:** If you're using a POC or partner license, access to data is limited to 30 days. The recommended date ranges below are guidelines and can be adjusted according to your needs.

| Collection | Description | Recommended Date Range |
|------------|-------------|----------------------|
| `compromised/account_group` | The collection contains credentials collected from various phishing resources, botnets, C&C servers, Darkweb, etc., used by hackers. All indicated sources are unique and private. It also includes combolist and corporate accounts. For Public Breaches - please refer to compromised/breached. | 2-4 years |
| `compromised/bank_card_group` | Information about compromised bank cards, sourced from card shops, forums, and public leaks. | 2 years |
| `compromised/mule` | Information on compromised accounts used by threat actors for money laundering and fund transfers. | 90 days |
| `compromised/breached` | Information about publicly leaked databases containing credentials and personal data. **Note:** Hunting rules are on by default here. | 90 days |
| `attacks/ddos` | Data on Distributed Denial of Service (DDoS) attacks, including targeted resources and attack durations. | 5-10 days |
| `attacks/deface` | Records of defacement attacks, highlighting compromised websites and related actors. | 5-10 days |
| `attacks/phishing_group` | Information on phishing attacks, including URLs of phishing websites. **Note:** Do not use IPs for detection - it may cause many false positives. Focus only on URLs. | 3-5 days |
| `attacks/phishing_kit` | Collections of phishing website templates, scripts, and configurations used by attackers. | 30 days |
| `apt/threat` | Reports on nation-state APTs activities, including associated indicators (IOCs), attack techniques, and MITRE ATT&CK mappings. | 2-4 years |
| `apt/threat_actor` | Profiles of nation-state groups detailing their characteristics, targets, motivations, and techniques. | 2-4 years |
| `hi/threat` | Finance motivated cybercriminals reports, including associated indicators (IOCs), attack techniques, and MITRE ATT&CK mappings. | 2-4 years |
| `hi/threat_actor` | Profiles of financially motivated cybercriminals detailing their characteristics, targets, motivations, and techniques. | 2-4 years |
| `malware/cnc` | Information on malware Command-and-Control (C&C) servers used for data exfiltration and command distribution. | 90 days |
| `malware/malware` | Detailed malware descriptions. | 2-4 years |
| `osi/git_repository` | Publicly available code from repositories like GitHub, filtered by your hunting rules. **Note:** Hunting rules are on by default here. | 30 days |
| `osi/public_leak` | Public data leaks from sources like Pastebin, ghostbin, and others, including credentials, database dumps, configuration files, and logs. **Note:** Hunting rules are on by default here. | 15 days |
| `osi/vulnerability` | Information on software vulnerabilities, associated exploits, and available proof-of-concept details. | 90 days |
| `suspicious_ip/tor_node` | Data about known Tor exit nodes used as anonymity relays. | 5 days |
| `suspicious_ip/open_proxy` | Information on publicly available proxy servers, including potentially misconfigured proxies. | 5 days |
| `suspicious_ip/scanner` | IP addresses identified as scanning or probing corporate networks. | 5 days |
| `suspicious_ip/socks_proxy` | IP addresses of infected hosts configured as SOCKS proxies used for anonymized attacks. | 5 days |
| `suspicious_ip/vpn` | Information about public and private VPN servers identified as potentially malicious or suspicious. | 5 days |

## Configure Group-IB Threat Intelligence in Cortex

| **Parameter**                  | **Description** | **Required** |
|--------------------------------| --- | --- |
| GIB TI  URL                    | The FQDN/IP the integration should connect to (default: `https://tap.group-ib.com/api/v2/`). | True |
| Username                       | Enter the email address you use to log into the web interface. The API token serves as your password for authentication. | True |
| Trust any certificate (not secure) | Whether to allow connections without verifying SSL certificates validity. | False |
| Use system proxy settings      | Whether to use XSOAR system proxy settings to connect to the API. | False |
| Colletions to fetch            | Select the collections you want to fetch incidents from. Read more about collections [here](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details). | False |
| Incidents first fetch          | Specify the date range for initial data fetch (default: "3 days"). | False |
| Number of requests per collection | Number of API requests per collection in each fetch iteration (default: 3). If you face some runtime errors, lower the value. | False |
| Limit (items per request) | Number of items requested per API page. This limit applies to all collections in the instance. The limit determines how many records are fetched in a single API request. For example, if "Number of requests per collection" is 2 and limit is 500, the integration will make 2 requests per collection, each requesting up to 500 records, resulting in up to 1000 records per collection per fetch cycle. We recommend following the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) for collection-specific limit recommendations. Best practice: create separate integration instances for different collections or groups of collections with similar optimal limit values. | False |
| Include combolist type in data | Filter to include combolist data from the `compromised/account_group` collection. Works only for `compromised/account_group` collection. Filter logic: If only this filter is enabled, only combolist records are collected. If both combolist and unique filters are enabled, both types are collected. If both are disabled, both types are collected by default. | False |
| Include unique type in data | Filter to include unique data from the `compromised/account_group` collection. Works only for `compromised/account_group` collection. Filter logic: If only this filter is enabled, only unique records are collected. If both combolist and unique filters are enabled, both types are collected. If both are disabled, both types are collected by default. | False |
| Enable filter "Probable Corporate Access" | Filter to limit data collection to only corporate accounts. Works only for `compromised/account_group` collection. When both unique and combolist filters are not enabled, you can enable this to limit the whole feed to corporate accounts only. Can also be combined with unique or combolist filters if needed. | False |
| Hunting Rules | To enable the collection of data using hunting rules, please select this parameter. | False |

## Note

Requests to the following collections come with the Hunting Rules parameter by default - and turing it off or on won't make any changes: `osi/git_repository, osi/public_leak, compromised/breached, compromised/messenger, compromised/discord`

## Additional Resources

For detailed information about collections, their structure, available fields, and recommended date ranges, refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Available Commands

The following commands are available in this integration:

- `gibtia-get-available-collections` - Returns list of available collections
- `gibtia-get-compromised-account-info` - Performs Group-IB event lookup in compromised/account collection
- `gibtia-get-compromised-card-group-info` - Performs Group-IB event lookup in compromised/card collection
- `gibtia-get-compromised-breached-info` - Performs Group-IB event lookup in compromised/breached collection
- `gibtia-get-phishing-group-info` - Performs Group-IB event lookup in attacks/phishing_group collection
- `gibtia-get-osi-git-leak-info` - Performs Group-IB event lookup in osi/git_repository collection
- `gibtia-get-osi-public-leak-info` - Performs Group-IB event lookup in osi/public_leak collection
- `gibtia-get-osi-vulnerability-info` - Performs Group-IB event lookup in osi/vulnerability collection
- `gibtia-get-malware-malware-info` - Performs Group-IB event lookup in malware/malware collection
- `gibtia-get-compromised-mule-info` - Performs Group-IB event lookup in compromised/mule collection
- `gibtia-get-attacks-ddos-info` - Performs Group-IB event lookup in attacks/ddos collection
- `gibtia-get-attacks-deface-info` - Performs Group-IB event lookup in attacks/deface collection
- `gibtia-get-threat-info` - Performs Group-IB event lookup in hi/threat or apt/threat collection
- `gibtia-get-threat-actor-info` - Performs Group-IB event lookup in hi/threat_actor or apt/threat_actor collection
- `gibtia-get-suspicious-ip-tor-node-info` - Performs Group-IB event lookup in suspicious_ip/tor_node collection
- `gibtia-get-suspicious-ip-open-proxy-info` - Performs Group-IB event lookup in suspicious_ip/open_proxy collection
- `gibtia-get-suspicious-ip-socks-proxy-info` - Performs Group-IB event lookup in suspicious_ip/socks_proxy collection
- `gibtia-get-suspicious-ip-vpn-info` - Performs Group-IB event lookup in suspicious_ip/vpn collection
- `gibtia-get-suspicious-ip-scanner-info` - Performs Group-IB event lookup in suspicious_ip/scanner collection
- `gibtia-get-malware-cnc-info` - Performs Group-IB event lookup in malware/cnc collection
- `gibtia-global-search` - Performs global Group-IB search across all collections
- `gibtia-local-search` - Performs Group-IB search in selected collection

### gibtia-get-compromised-account-info

***
Command performs Group-IB event lookup in compromised/account collection with provided ID.

#### Base Command

`gibtia-get-compromised-account-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 253b9a136f0d574149fc43691eaf7ae27aff141a. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.CompromisedAccount.client.ipv4.asn | String | Victim IP address |
| GIBTIA.CompromisedAccount.client.ipv4.countryName | String | Country name |
| GIBTIA.CompromisedAccount.client.ipv4.ip | String | Victim IP address |
| GIBTIA.CompromisedAccount.client.ipv4.region | String | Region name |
| GIBTIA.CompromisedAccount.cnc.domain | String | Event CNC domain |
| GIBTIA.CompromisedAccount.cnc.url | String | CNC URL |
| GIBTIA.CompromisedAccount.cnc.ipv4.ip | String | CNC IP address |
| GIBTIA.CompromisedAccount.dateCompromised | Date | Date of compromise |
| GIBTIA.CompromisedAccount.dateDetected | Date | Date of detection |
| GIBTIA.CompromisedAccount.dropEmail.email | String | Email where compromised data were sent to |
| GIBTIA.CompromisedAccount.dropEmail.domain | String | Email domain |
| GIBTIA.CompromisedAccount.login | String | Compromised login |
| GIBTIA.CompromisedAccount.password | String | Compromised password |
| GIBTIA.CompromisedAccount.malware.name | String | Malware name |
| GIBTIA.CompromisedAccount.malware.id | String | Group-IB malware ID |
| GIBTIA.CompromisedAccount.person.name | String | Card owner name |
| GIBTIA.CompromisedAccount.person.email | String | Card owner e-mail |
| GIBTIA.CompromisedAccount.portalLink | String | Link to GIB incident |
| GIBTIA.CompromisedAccount.threatActor.name | String | Associated threat actor |
| GIBTIA.CompromisedAccount.threatActor.isAPT | Boolean | Is threat actor APT group |
| GIBTIA.CompromisedAccount.threatActor.id | String | Threat actor GIB ID |
| GIBTIA.CompromisedAccount.id | String | Group-IB incident ID |
| GIBTIA.CompromisedAccount.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-compromised-account-info id=253b9a136f0d574149fc43691eaf7ae27aff141a```

#### Human Readable Output

>### Feed from compromised/account with ID 253b9a136f0d574149fc43691eaf7ae27aff141a

>|client ipv4 ip|cnc cnc|cnc domain|cnc ipv4 asn|cnc ipv4 city|cnc ipv4 countryCode|cnc ipv4 countryName|cnc ipv4 ip|cnc ipv4 provider|cnc ipv4 region|cnc url|companyId|dateDetected|domain|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|login|malware id|malware name|malware stixGuid|oldId|password|portalLink|silentInsert|sourceType|stixGuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0.0.0.0 | <<<<<<<<<http://some.com>>>>>>>>> | some.com | AS1111 | City | RU | Country | 11.11.11.11 | some.com | City | <http://some.com> | -1 | 2020-02-22T01:21:03+00:00 | some.com | A2 | 80 | 100 | red | red | 90 | 253b9a136f0d574149fc43691eaf7ae27aff141a | some.com | 411ac9df6c5515922a56e30013e8b8b366eeec80 | PredatorStealer | 2f7650f4-bc72-2068-d1a5-467b688975d8 | 396792583 | @some@ | <https://group-ib.com/cd/accounts?searchValue=id:253b9a136f0d574149fc43691eaf7ae27aff141a> | 0 | Botnet | 8abb3aa9-e351-f837-d61a-856901c3dc9d |

>### URL indicator

>|gibid|severity|value|
>|---|---|---|
>| 253b9a136f0d574149fc43691eaf7ae27aff141a | red | <http://some.com> |

>### Domain indicator

>|gibid|severity|value|
>|---|---|---|
>| 253b9a136f0d574149fc43691eaf7ae27aff141a | red | some.com |

>### IP indicator

>|asn|geocountry|geolocation|gibid|severity|value|
>|---|---|---|---|---|---|
>| AS1111 | Country | City | 253b9a136f0d574149fc43691eaf7ae27aff141a | red | 11.11.11.11 |

### gibtia-get-compromised-breached-info

***
Command performs Group-IB event lookup in compromised/breached collection with provided ID.

#### Base Command

`gibtia-get-compromised-breached-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 6fd344f340f4bdc08548cb36ded62bdf. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.DataBreach.email | String | List of breached emails |
| GIBTIA.DataBreach.leakName | String | Name of the leak |
| GIBTIA.DataBreach.password | String | List of breached passwords |
| GIBTIA.DataBreach.uploadTime | Date | Date of breached data upload |
| GIBTIA.DataBreach.id | String | Group-IB incident ID |
| GIBTIA.DataBreach.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-compromised-breached-info id=277c4112d348c91f6dabe9467f0d18ba```

#### Human Readable Output

>### Feed from compromised/breached with ID 277c4112d348c91f6dabe9467f0d18ba

>|addInfo|email|evaluation|id|leakName|password|uploadTime|
>|---|---|---|---|---|---|---|
>| address: <br/> | some@gmail.com | admiraltyCode: C3<br/>credibility: 50<br/>reliability: 50<br/>severity: green<br/>tlp: amber<br/>ttl: null | 277c4112d348c91f6dabe9467f0d18ba | some.com | AC91C480FDE9D7ACB8AC4B78310EB2TD,<br/>1390DDDFA28AE085D23518A035703112 | 2021-06-12T03:02:00 |

### gibtia-get-compromised-mule-info

***
Command performs Group-IB event lookup in compromised/mule collection with provided ID.

#### Base Command

`gibtia-get-compromised-mule-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 50a3b4abbfca5dcbec9c8b3a110598f61ba93r33. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.CompromisedMule.account | String | Account number \(card/phone\), which was used by threat actor to cash out |
| GIBTIA.CompromisedMule.cnc.ipv4.asn | String | CNC ASN |
| GIBTIA.CompromisedMule.cnc.ipv4.countryName | String | Country name |
| GIBTIA.CompromisedMule.cnc.ipv4.ip | String | Victim IP address |
| GIBTIA.CompromisedMule.cnc.ipv4.region | String | Region name |
| GIBTIA.CompromisedMule.cnc.url | String | CNC URL |
| GIBTIA.CompromisedMule.cnc.domain | String | CNC domain |
| GIBTIA.CompromisedMule.dateAdd | Date | Date of detection |
| GIBTIA.CompromisedMule.malware.name | String | Malware name |
| GIBTIA.CompromisedMule.portalLink | String | Link to GIB incident |
| GIBTIA.CompromisedMule.threatActor.name | String | Associated threat actor |
| GIBTIA.CompromisedMule.threatActor.id | String | Threat actor GIB ID |
| GIBTIA.CompromisedMule.threatActor.isAPT | Boolean | Is threat actor APT group |
| GIBTIA.CompromisedMule.id | String | Group-IB incident ID |
| GIBTIA.CompromisedMule.sourceType | String | Information source |
| GIBTIA.CompromisedMule.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-compromised-mule-info id=50a3b4abbfca5dcbec9c8b3a110598f61ba90a99```

#### Human Readable Output

>### Feed from compromised/mule with ID 50a3b4abbfca5dcbec9c8b3a110598f61ba90a99

>|account|cnc cnc|cnc domain|cnc ipv4 ip|cnc url|dateAdd|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|hash|id|malware id|malware name|malware stixGuid|oldId|organization name|portalLink|sourceType|stixGuid|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1111111111111111 | <<<<<<<<<<http://some.com>>>>>>>>>> | some | 11.11.11.11 | http://some.com | 2020-02-21T13:02:00+00:00 | A2 | 80 | 100 | red | amber | 30 | some | 50a3b4abbfca5dcbec9c8b3a110598f61ba90a99 | 5a2b741f8593f88178623848573abc899f9157d4 | Anubis | 7d837524-7b01-ddc9-a357-46e7136a9852 | 392993084 | Some | <https://group-ib.com/cd/mules?searchValue=id:50a3b4abbfca5dcbec9c8b3a110598f61ba90a99> | Botnet | 2da6b164-9a12-6db5-4346-2a80a4e03255 | Person |

>### URL indicator

>|gibid|severity|value|
>|---|---|---|
>| 50a3b4abbfca5dcbec9c8b3a110598f61ba90a99 | red | <http://some.com> |

>### Domain indicator

>|gibid|severity|value|
>|---|---|---|
>| 50a3b4abbfca5dcbec9c8b3a110598f61ba90a99 | red | some |

>### IP indicator

>|gibid|severity|value|
>|---|---|---|
>| 50a3b4abbfca5dcbec9c8b3a110598f61ba90a99 | red | 11.11.11.11 |

### gibtia-get-osi-git-leak-info

***
Command performs Group-IB event lookup in osi/git_leak collection with provided ID.

#### Base Command

`gibtia-get-osi-git-leak-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: f201c253ac71f7d78db39fa111a2af9d7ee7a3f7. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.GitLeak.dateDetected | Date | Leak detection date |
| GIBTIA.GitLeak.matchesType | String | List of matches type |
| GIBTIA.GitLeak.name | String | GIT filename |
| GIBTIA.GitLeak.repository | String | GIT repository |
| GIBTIA.GitLeak.revisions.file | String | Leaked file link |
| GIBTIA.GitLeak.revisions.fileDiff | String | Leaked file diff |
| GIBTIA.GitLeak.revisions.info.authorName | String | Revision author |
| GIBTIA.GitLeak.revisions.info.authorEmail | String | Author name |
| GIBTIA.GitLeak.revisions.info.dateCreated | Date | Revision creation date |
| GIBTIA.GitLeak.source | String | Source\(github/gitlab/etc.\) |
| GIBTIA.GitLeak.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-osi-git-leak-info id=ead0d8ae9f2347789941ebacde88ad2e3b1ef691```

#### Human Readable Output

>### Feed from osi/git_leak with ID ead0d8ae9f2347789941ebacde88ad2e3b1ef691

>|companyId|dateDetected|dateUpdated|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|file|fileId|id|matchesType|matchesTypeCount card|matchesTypeCount cisco|matchesTypeCount commonKeywords|matchesTypeCount domain|matchesTypeCount dsn|matchesTypeCount email|matchesTypeCount google|matchesTypeCount ip|matchesTypeCount keyword|matchesTypeCount login|matchesTypeCount metasploit|matchesTypeCount nmap|matchesTypeCount pgp|matchesTypeCount sha|matchesTypeCount slackAPI|matchesTypeCount ssh|name|repository|source|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 40,<br>1872,<br>2060,<br>2248,<br>2522,<br>2692 | 2020-03-12T01:12:00+00:00 | 2020-02-11T01:12:00+00:00 | A6 | 100 | 100 | green | amber | 30 | <https://group-ib.com/api/v2/osi/git_leak/ead0d8ae9f2347789941ebacde88ad2e3b1ef691/file/bWFpbi0zOTFkYjVkNWYxN2FiNmNiYmJmN2MzNWQxZjRkMDc2Y2I0YzgzMGYwOTdiMmE5ZWRkZDJkZjdiMDY1MDcwOWE3> | 391db5d5f17ab6cbbbf7c35d1f4d076cb4c830f097b2a9eddd2df7b0650709a7 | ead0d8ae9f2347789941ebacde88ad2e3b1ef691 | commonKeywords,<br>keyword | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | some | some.com | github |

>### revisions table

>|bind|companyId|data|file|fileDiff|fileDiffId|fileId|hash|info|parentFileId|
>|---|---|---|---|---|---|---|---|---|---|
>| {'bindBy': 'cert', 'companyId': [2692], 'data': 'cert', 'type': 'keyword'} | 2692 | commonKeywords: {"password": ["password"]} | <https://group-ib.com/api/v2/osi/git_leak/ead0d8ae9f2347789941ebacde88ad2e3b1ef691/file/cmV2aXNpb24tZmlsZS0zOTFkYjVkNWYxN2FiNmNiYmJmN2MzNWQxZjRkMDc2Y2I0YzgzMGYwOTdiMmE5ZWRkZDJkZjdiMDY1MDcwOWE3> | <https://group-ib.com/api/v2/osi/git_leak/ead0d8ae9f2347789941ebacde88ad2e3b1ef691/file/cmV2aXNpb24tZmlsZURpZmYtMzkxZGI1ZDVmMTdhYjZjYmJiZjdjMzVkMWY0ZDA3NmNiNGM4MzBmMDk3YjJhOWVkZGQyZGY3YjA2NTA3MDlhNw>== | a2187ee179076a22e550e8f7fbc51840e87aba260431ab9cb2d4e0192ad4134c | 391db5d5f17ab6cbbbf7c35d1f4d076cb4c830f097b2a9eddd2df7b0650709a7 | Some | authorEmail: some@gmail.com <br>authorName: some<br>dateCreated: 2020-01-03T11:17:52+00:00<br>timestamp: 1617794272 | ead0d8ae9f2347789941ebacde88ad2e3b1ef691 |

### gibtia-get-osi-public-leak-info

***
Command performs Group-IB event lookup in osi/public_leak collection with provided ID.

#### Base Command

`gibtia-get-osi-public-leak-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: a9a5b5cb9b971a2a037e3a0a30654185ea148095. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.PublicLeak.created | Date | Leak event detection date |
| GIBTIA.PublicLeak.data | String | Leaked data |
| GIBTIA.PublicLeak.hash | String | Leak data hash |
| GIBTIA.PublicLeak.linkList.author | String | Leak entry author |
| GIBTIA.PublicLeak.linkList.dateDetected | Date | Leak detection date |
| GIBTIA.PublicLeak.linkList.datePublished | Date | Leak publish date |
| GIBTIA.PublicLeak.linkList.hash | String | Leak hash |
| GIBTIA.PublicLeak.linkList.link | String | Leak link |
| GIBTIA.PublicLeak.linkList.source | String | Leak source |
| GIBTIA.PublicLeak.matches | String | Matches |
| GIBTIA.PublicLeak.portalLink | String | Group-IB portal link |
| GIBTIA.PublicLeak.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-osi-public-leak-info id=a09f2354e52d5fa0a8697c8df0b4ed99cc956273```

#### Human Readable Output

>### Feed from osi/public_leak with ID a11f2354e52d5fa0a8697c8df0b4ed99cc956211

>|created|data|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|hash|id|language|portalLink|size|updated|useful|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-02-02T13:52:01+03:00 | Big chunk of data | C3 | 50 | 50 | green | amber | 30 | a11f2354e52d5fa0a8697c8df0b4ed99cc956211 | a11f2354e52d5fa0a8697c8df0b4ed99cc956211 | java | <https://group-ib.com/osi/public_leak?searchValue=id:a09f2354e52d5fa0a8697c8df0b4ed99cc956273> | 709 B | 2021-04-01T14:57:01+03:00 | 1 |

>### linkList table

>|dateDetected|datePublished|hash|itemSource|link|size|source|status|
>|---|---|---|---|---|---|---|---|
>| 2021-04-01T14:57:01+03:00 | 2021-04-01T14:50:45+03:00 | 5d9657dbdf59487a6031820add2cacbe54e86814 | api | <https://some.com> | 709 | some.com | 1 |

### gibtia-get-osi-vulnerability-info

***
Command performs Group-IB event lookup in osi/vulnerability collection with provided ID.

#### Base Command

`gibtia-get-osi-vulnerability-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/><br/>e.g.: CVE-2021-27152. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.OSIVulnerability.affectedSoftware.name | String | Affected software name |
| GIBTIA.OSIVulnerability.affectedSoftware.operator | String | Affected software version operator\( ex. le=less or equal\) |
| GIBTIA.OSIVulnerability.affectedSoftware.version | String | Affected software version |
| GIBTIA.OSIVulnerability.bulletinFamily | String | Bulletin family |
| GIBTIA.OSIVulnerability.cvss.score | String | CVSS score |
| GIBTIA.OSIVulnerability.cvss.vector | String | CVSS vector |
| GIBTIA.OSIVulnerability.dateLastSeen | Date | Date last seen |
| GIBTIA.OSIVulnerability.datePublished | Date | Date published |
| GIBTIA.OSIVulnerability.description | String | Vulnerability description |
| GIBTIA.OSIVulnerability.id | String | Vulnerability ID |
| GIBTIA.OSIVulnerability.reporter | String | Vulnerability reporter |
| GIBTIA.OSIVulnerability.title | String | Vulnerability title |
| GIBTIA.OSIVulnerability.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-osi-vulnerability-info id=CVE-2021-27152```

#### Human Readable Output

>### Feed from osi/vulnerability with ID CVE-2021-27152

>|bulletinFamily|cvss score|cvss vector|dateLastSeen|dateModified|datePublished|description|displayOptions isFavourite|displayOptions isHidden|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|exploitCount|extCvss base|extCvss environmental|extCvss exploitability|extCvss impact|extCvss mImpact|extCvss overall|extCvss temporal|extCvss vector|extDescription|href|id|lastseen|modified|portalLink|provider|published|references|reporter|title|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| NVD | 7.5 | AV:N/AC:L/Au:N/C:P/I:P/A:P | 2021-02-11T14:35:24+03:00 | 2021-02-11T00:45:00+03:00 | 2021-02-10T19:15:00+03:00 | Description | false | false | A1 | 100 | 100 | red | green | 30 | 0 | 9.8 | 0.0 | 3.9 | 5.9 | 0.0 | 9.8 | 0.0 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | Big description | <<<<<<<<<https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-27152>>>>>>>>> | CVE-2021-27152 | 2021-02-11T14:35:24+03:00 | 2021-02-11T00:45:00+03:00 | <https://group-ib.com/osi/vulnerabilities?searchValue=id:CVE-2021-27152> | some.com | 2021-02-10T19:15:00+03:00 | <https://pierrekim.github.io/blog/2021-01-12-fiberhome-ont-0day-vulnerabilities.html#httpd-hardcoded-credentials>,<br><https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2021-27152> | some.com | CVE-2021-27152 | cve |

>### softwareMixed table

>|os|osVendor|osVersion|vendor|
>|---|---|---|---|
>| some_firmware | some | some | some |

### gibtia-get-attacks-ddos-info

***
Command performs Group-IB event lookup in attacks/ddos collection with provided ID.

#### Base Command

`gibtia-get-attacks-ddos-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 26a05baa4025edff367b058b13c6b43e820538a5. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.AttacksDDoS.cnc.url | String | CNC URL |
| GIBTIA.AttacksDDoS.cnc.domain | String | CNC domain |
| GIBTIA.AttacksDDoS.cnc.ipv4.asn | String | CNC ASN |
| GIBTIA.AttacksDDoS.cnc.ipv4.countryName | String | CNC IP country name |
| GIBTIA.AttacksDDoS.cnc.ipv4.ip | String | CNC IP address |
| GIBTIA.AttacksDDoS.cnc.ipv4.region | String | CNC region name |
| GIBTIA.AttacksDDoS.target.ipv4.asn | String | DDoS target ASN |
| GIBTIA.AttacksDDoS.target.ipv4.countryName | String | DDoS target country name |
| GIBTIA.AttacksDDoS.target.ipv4.ip | String | DDoS target IP address |
| GIBTIA.AttacksDDoS.target.ipv4.region | String | DDoS target region name |
| GIBTIA.AttacksDDoS.target.category | String | DDoS target category |
| GIBTIA.AttacksDDoS.target.domain | String | DDoS target domain |
| GIBTIA.AttacksDDoS.threatActor.id | String | Associated threat actor ID |
| GIBTIA.AttacksDDoS.threatActor.name | String | Associated threat actor |
| GIBTIA.AttacksDdos.threatActor.isAPT | Boolean | Is threat actor APT |
| GIBTIA.AttacksDDoS.id | String | GIB incident ID |
| GIBTIA.AttacksDDoS.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-attacks-ddos-info id=26a05baa4025edff367b058b13c6b43e820538a5```

#### Human Readable Output

>### Feed from attacks/ddos with ID 26a05baa4025edff367b058b13c6b43e820538a5

>|cnc cnc|cnc domain|cnc ipv4 asn|cnc ipv4 city|cnc ipv4 countryCode|cnc ipv4 countryName|cnc ipv4 ip|cnc ipv4 provider|cnc ipv4 region|companyId|dateBegin|dateEnd|dateReg|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|oldId|portalLink|protocol|source|stixGuid|target domainsCount|target ipv4 asn|target ipv4 city|target ipv4 countryCode|target ipv4 countryName|target ipv4 ip|target ipv4 provider|target ipv4 region|target port|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| some.com | some.com | AS11111 | Some | US | United States | 11.11.11.11 | Some | Some | -1 | 2021-01-16T02:58:53+00:00 | 2021-01-16T02:58:55+00:00 | 2021-01-16 | A2 | 90 | 90 | red | green | 30 | 26a05baa4025edff367b058b13c6b43e820538a5 | 394657345 | <https://group-ib.com/attacks/ddos?searchValue=id:26a05baa4025edff367b058b13c6b43e820538a5> | udp | honeypot_logs:1 | ea05c117-2cca-b3cd-f033-a8e16e5db3c2 | 0 | AS11111 | Some | US | United States | 11.11.11.11 | Some | Some | 55843 | DNS Reflection |

>### Domain indicator

>|gibid|severity|value|
>|---|---|---|
>| 26a05baa4025edff367b058b13c6b43e820538a5 | red | some.com |

>### IP indicator

>|asn|geocountry|geolocation|gibid|severity|value|
>|---|---|---|---|---|---|
>| AS11111 | United States | Some | 26a05baa4025edff367b058b13c6b43e820538a5 | red | 11.11.11.11 |

### gibtia-get-attacks-deface-info

***
Command performs Group-IB event lookup in attacks/deface collection with provided ID.

#### Base Command

`gibtia-get-attacks-deface-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 6009637a1135cd001ef46e21. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.AttacksDeface.date | Date | Date of deface |
| GIBTIA.AttacksDeface.id | String | GIB incident ID |
| GIBTIA.AttacksDeface.targetIp.asn | String | Victim ASN |
| GIBTIA.AttacksDeface.targetIp.countryName | String | Victim country name |
| GIBTIA.AttacksDeface.targetIp.region | String | Victim IP region name |
| GIBTIA.AttacksDeface.threatActor.id | String | Associated threat actor ID |
| GIBTIA.AttacksDeface.threatActor.name | String | Associated threat actor |
| GIBTIA.AttacksDeface.threatActor.isAPT | Boolean | Is threat actor APT |
| GIBTIA.AttacksDeface.url | String | URL of compromised resource |
| GIBTIA.AttacksDeface.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-attacks-deface-info id=6009637a1135cd001ef46e21```

#### Human Readable Output

>### Feed from attacks/deface with ID 6009637a1135cd001ef46e21

>|date|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|mirrorLink|portalLink|providerDomain|siteUrl|source|targetDomain|targetIp countryName|targetIp ip|threatActor id|threatActor isAPT|threatActor name|tsCreate|url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-01-21T02:22:18+00:00 | B2 | 80 | 80 | orange | amber | 30 | 6009637a1135cd001ef46e21 | <https://some.com/id:-6009637a1135cd001ef46e21>: | <https://group-ib.com/attacks/deface?searchValue=id:6009637a1135cd001ef46e21> | some.com | <<<<<<<<<<http://some.com>>>>>>>>>> | some.com | some.com | Indonesia | 11.11.11.11 | d7ff75c35f93dce6f5410bba9a6c206bdff66555 | false | FRK48 | 2021-01-21T11:19:52+00:00 | http://some.com |

>### URL indicator

>|gibid|severity|value|
>|---|---|---|
>| 6009637a1135cd001ef46e21 | orange | <http://some.com> |

>### Domain indicator

>|gibid|severity|value|
>|---|---|---|
>| 6009637a1135cd001ef46e21 | orange | some.com |

>### IP indicator

>|geocountry|gibid|severity|value|
>|---|---|---|---|
>| Indonesia | 6009637a1135cd001ef46e21 | orange | 11.11.11.11 |

### gibtia-get-threat-info

***
Command performs Group-IB event lookup in hi/threat (or in apt/threat if the APT flag is true) collection with provided ID.

#### Base Command

`gibtia-get-threat-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 1b09d389d016121afbffe481a14b30ea995876e4. | Required |
| isAPT | Is threat APT. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.Threat.contacts.account | String | Threat accounts found in this threat action. |
| GIBTIA.Threat.contacts.flag | String | Is account fake or not |
| GIBTIA.Threat.contacts.service | String | Account service |
| GIBTIA.Threat.contacts.type | String | Type of account\(social_network/email/wallet etc.\) |
| GIBTIA.Threat.countries | String | Affected countries |
| GIBTIA.Threat.createdAt | Date | Threat report creation date |
| GIBTIA.Threat.cveList.name | String | List of abused CVE |
| GIBTIA.Threat.dateFirstSeen | Date | Attack first seen date |
| GIBTIA.Threat.dateLastSeen | Date | Attack last seen date |
| GIBTIA.Threat.datePublished | Date | Date published |
| GIBTIA.Threat.description | String | Threat description |
| GIBTIA.Threat.forumsAccounts.url | String | Related forum URL |
| GIBTIA.Threat.forumsAccounts.nickname | String | Related forums account |
| GIBTIA.Threat.forumsAccounts.registeredAt | Date | Related forums account registration date |
| GIBTIA.Threat.forumsAccounts.messageCount | Number | Related forums messages count |
| GIBTIA.Threat.id | String | GIB internal threat ID |
| GIBTIA.Threat.indicators | String | Can be either network or file indicators |
| GIBTIA.Threat.langs | String | Languages actors related |
| GIBTIA.Threat.malwareList.name | String | Related Malware Name |
| GIBTIA.Threat.malwareList.id | String | Related malware GIB internal ID |
| GIBTIA.Threat.mitreMatrix.attackPatternId | String | MITRE attack pattern ID |
| GIBTIA.Threat.mitreMatrix.attackTactic | String | MITRE attack tactic name |
| GIBTIA.Threat.mitreMatrix.attackType | String | MITRE attack type |
| GIBTIA.Threat.mitreMatrix.id | String | MITRE attack id |
| GIBTIA.Threat.regions | String | Regions affected by attack |
| GIBTIA.Threat.reportNumber | String | GIB report number |
| GIBTIA.Threat.sectors | String | Affected sectors |
| GIBTIA.Threat.shortDescription | String | Short description |
| GIBTIA.Threat.title | String | Threat title |
| GIBTIA.Threat.targetedCompany | String | Targeted company name |
| GIBTIA.Threat.ThreatActor.name | String | Threat actor name |
| GIBTIA.Threat.ThreatActor.id | String | Threat actor ID |
| GIBTIA.Threat.ThreatActor.isAPT | Boolean | Is threat actor APT group |
| GIBTIA.Threat.sources | String | Sources links |
| GIBTIA.Threat.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-threat-info id=1b09d389d016121afbffe481a14b30ea995876e4 isAPT=true```

#### Human Readable Output

>### Feed from threat with ID 1b09d389d016121afbffe481a14b30ea995876e4

>|createdAt|dateFirstSeen|dateLastSeen|datePublished|deleted|description|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|id|isPublished|isTailored|langs|oldId|reportNumber|sectors|threatActor country|threatActor id|threatActor isAPT|threatActor name|title|type|updatedAt|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-01-15T16:53:20+03:00 | 2021-01-15 | 2021-01-15 | 2021-01-15 | false | Big description | B1 | 100 | 80 | orange | amber | 1b09d389d016121afbffe481a14b30ea995876e4 | true | false | en,<br>com | 4c01c2d4-5ebb-44d8-9e91-be89231b0eb3 | CP-2501-1653 | financial-services,<br>finance | KP | 5e9f20fdcf5876b5772b3d09b432f4080711ac5f | true | Lazarus | Lazarus launches new attack with cryptocurrency trading platforms | threat | 2021-04-02T14:08:03+03:00 |

>### files table

>|hash|mime|name|size|
>|---|---|---|---|
>| fa5b6b2f074ba6eb58f8b093f0e92cb8ff44b655dc8e9ce93f850e71474e4e11 | image/png | fa5b6b2f074ba6eb58f8b093f0e92cb8ff44b655dc8e9ce93f850e71474e4e11 | 284731 |
>| a6851a6b91759d00afce8e65c0e5087429812b8c49d39631793d8b6bdeb08711 | image/png | a6851a6b91759d00afce8e65c0e5087429812b8c49d39631793d8b6bdeb08711 | 129240 |
>| 644f5b8e38f55b82f811240af7c4abdaf8c8bc18b359f8f169074ba881d93b1d | image/png | 644f5b8e38f55b82f811240af7c4abdaf8c8bc18b359f8f169074ba881d93b1d | 556552 |
>| 623102f6cf9d2e6c978898117b7b5b85035b3d5e67c4ee266879868c9eb24dd2 | image/png | 623102f6cf9d2e6c978898117b7b5b85035b3d5e67c4ee266879868c9eb24dd2 | 209254 |

>### mitreMatrix table

>|attackPatternId|attackTactic|attackType|id|params|
>|---|---|---|---|---|
>| attack-pattern--45242287-2964-4a3e-9373-159fad4d8195 | establish-&-maintain-infrastructure | pre_attack_tactics | PRE-T1105 | data:  |

>### indicatorRelationships table

>|sourceId|targetId|
>|---|---|
>| 9f3a2a244570a38e772a35d7c9171eed92bec6f7 | 12cad1ca535a92a2ed306c0edf3025e7d9776693 |

>### indicators table

>|deleted|id|langs|params|seqUpdate|type|
>|---|---|---|---|---|---|
>| false | 9f3a2a244570a38e772a35d7c9171eed12bec6f7 | en | hashes: {"md4": "", "md5": "8397ea747d2ab50da4f876a36d631272", "md6": "", "ripemd160": "", "sha1": "48a6d5141e25b6c63ad8da20b954b56afe512031", "sha224": "", "sha256": "89b5e248c222ebf2cb3b525d3650259e01cf7d8fff5e1aa15ccd7512b1e63957", "sha384": "", "sha512": "", "whirlpool": ""}<br>name: some.com <br>size: null | 16107188499162 | file |
>| false | 8b96c56cbc980c1e3362060ffa953e65281fb1df | en | domain: some.com <br>ipv4: <br>ipv6: <br>ssl: <br>url: <https://some.com> | 16107188498393 | network |
>| false | 42a9929807fd954918f9bb603135754be7a6e11c | en | hashes: {"md4": "", "md5": "5d43baf1c9e9e3a939e5defd8f3fbd1d", "md6": "", "ripemd120": "", "sha1": "d5ff73c043f3bb75dd749636307500b60a336150", "sha224": "", "sha256": "867c8b49d29ae1f6e4a7cd31b6fe7e278753a1ba03d4be338ed11fd1efc3dd12", "sha384": "", "sha512": "", "whirlpool": ""}<br>name: 5d43baf1c9e9e3a939e5defd8f8fbd1d<br>size: null | 16107188498634 | file |
>| false | 12cad1ca535a92a2ed306c0edf3025e7d9776612 | en | domain: some.com <br>ipv4: <br>ipv6: <br>ssl: <br>url: <https://some.com> | 16107188498908 | network |

### gibtia-get-threat-actor-info

***
Command performs Group-IB event lookup in hi/threat_actor (or in apt/threat_actor if the APT flag is true) collection with provided ID.

#### Base Command

`gibtia-get-threat-actor-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB internal threatActor ID.<br/>e.g.: 0d4496592ac3a0f5511cd62ef29887f48d9cb545. | Required |
| isAPT | Is threat actor APT group. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.ThreatActor.aliases | String | Threat actor aliases |
| GIBTIA.ThreatActor.country | String | Threat actor country |
| GIBTIA.ThreatActor.createdAt | Date | Threat actor record creation time |
| GIBTIA.ThreatActor.description | String | Threat actor description |
| GIBTIA.ThreatActor.goals | String | Threat actor goals sectors\(financial, diplomatic, etc.\) |
| GIBTIA.ThreatActor.id | String | Threat actor id |
| GIBTIA.ThreatActor.isAPT | Boolean | Threat actor is APT |
| GIBTIA.ThreatActor.labels | String | GIB internal threat actor labels\(hacker, nation-state, etc.\) |
| GIBTIA.ThreatActor.langs | String | Threat actor communication language |
| GIBTIA.ThreatActor.name | String | Threat actor name |
| GIBTIA.ThreatActor.roles | String | Threat actor roles |
| GIBTIA.ThreatActor.stat.countries | String | Threat actor countries activity found in |
| GIBTIA.ThreatActor.stat.dateFirstSeen | Date | Date first seen |
| GIBTIA.ThreatActor.stat.dateLastSeen | Date | Date last seen |
| GIBTIA.ThreatActor.stat.regions | String | Threat actor activity regions |
| GIBTIA.ThreatActor.stat.reports.datePublished | Date | Related threat report publishing date |
| GIBTIA.ThreatActor.stat.reports.id | String | Related threat report id |
| GIBTIA.ThreatActor.stat.reports.name.en | String | Related threat report language |
| GIBTIA.ThreatActor.stat.sectors | String | Sectors attacked by threat actor |

#### Command Example

```!gibtia-get-threat-actor-info id=0d4496592ac3a0f5511cd62ef29887f48d9cb545 isAPT=true```

#### Human Readable Output

>### Feed from threat_actor with ID 0d4496592ac3a0f5511cd62ef29887f48d9cb545

>|aliases|country|createdAt|deleted|description|goals|id|isAPT|isPublished|labels|langs|name|roles|spokenOnLangs|stat countries|stat dateFirstSeen|stat dateLastSeen|stat regions|stat sectors|stixGuid|updatedAt|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| SectorC08 | RU | 2018-09-26T16:59:50+03:00 | false | Big description | Information | 0d4496592ac3a0f5511cd62ef29887f48d9cb545 | true | true | spy | en | Gamaredon | agent | com | US | 2013-06-01 | 2021-03-19 | asia | non-profit | 63d0e4d4-9f55-4fa2-87af-b6c91ded80e0 | 2021-04-08T22:09:07+03:00 |

>### stat reports table

>|datePublished|id|name|
>|---|---|---|
>| 2021-02-04 | 59dec5947c5adac898445e3958b1d05e1c260459 | en: Template injection attacks from the Gamaredon group continued: protocol topics |

### gibtia-get-suspicious-ip-tor-node-info

***
Command performs Group-IB event lookup in suspicious_ip/tor_node collection with provided ID.

#### Base Command

`gibtia-get-suspicious-ip-tor-node-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 109.70.100.46. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.SuspiciousIPTorNode.ipv4.asn | String | Tor node ASN |
| GIBTIA.SuspiciousIPTorNode.ipv4.countryName | String | Tor node IP country name |
| GIBTIA.SuspiciousIPTorNode.ipv4.ip | String | Tor node IP address |
| GIBTIA.SuspiciousIPTorNode.ipv4.region | String | Tor node IP region name |
| GIBTIA.SuspiciousIPTorNode.id | String | GIB id |
| GIBTIA.SuspiciousIPTorNode.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-suspicious-ip-tor-node-info id=109.70.100.46```

#### Human Readable Output

>### Feed from suspicious_ip/tor_node with ID 11.11.11.11

>|dateFirstSeen|dateLastSeen|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|ipv4 ip|portalLink|source|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-09-03T14:15:25+00:00 | 2021-04-25T03:15:29+00:00 | A1 | 90 | 90 | green | green | 30 | 11.11.11.11 | 11.11.11.11 | <https://group-ib.com/suspicious/tor?searchValue=id:11.11.11.11> | some.com |

>### IP indicator

>|gibid|severity|value|
>|---|---|---|
>| 11.11.11.11 | green | 11.11.11.11 |

### gibtia-get-suspicious-ip-open-proxy-info

***
Command performs Group-IB event lookup in suspicious_ip/open_proxy collection with provided ID.

#### Base Command

`gibtia-get-suspicious-ip-open-proxy-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: cc6a2856da2806b03839f81aa214f22dbcfd7369. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.SuspiciousIPOpenProxy.ipv4.asn | String | Proxy ASN |
| GIBTIA.SuspiciousIPOpenProxy.ipv4.countryName | String | Proxy IP country name |
| GIBTIA.SuspiciousIPOpenProxy.ipv4.ip | String | Proxy IP address |
| GIBTIA.SuspiciousIPOpenProxy.ipv4.region | String | Proxy IP region name |
| GIBTIA.SuspiciousIPOpenProxy.ipv4.port | Number | Proxy port |
| GIBTIA.SuspiciousIPOpenProxy.ipv4.source | String | Information source |
| GIBTIA.SuspiciousIPOpenProxy.ipv4.anonymous | String | Proxy anonymous level |
| GIBTIA.SuspiciousIPOpenProxy.id | String | GIB event ID |
| GIBTIA.SuspiciousIPOpenProxy.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-suspicious-ip-open-proxy-info id=cc6a2856da2806b03839f81aa214f22dbcfd7369```

#### Human Readable Output

>### Feed from suspicious_ip/open_proxy with ID cc6a2856da2806b03839f81aa214f22dbcfd7369

>|anonymous|dateDetected|dateFirstSeen|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|ipv4 countryCode|ipv4 countryName|ipv4 ip|ipv4 provider|oldId|port|portalLink|source|stixGuid|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 11.11.11.11 | 2021-01-21T11:01:02+00:00 | 2020-03-19T23:01:01+00:00 | C3 | 50 | 50 | green | white | 15 | cc6a2856da2806b03839f81aa214f22dbcfd7369 | Country Code | Country | 11.11.11.11 | Some | 241549215 | 80 | <https://group-ib.com/suspicious/proxies?searchValue=id:cc6a2856da2806b03839f81aa214f22dbcfd7369> | some.com | c30604ac-94d5-b514-f1d1-7230ec13c739 | http |

>### IP indicator

>|geocountry|gibid|gibproxyanonymous|gibproxyport|severity|source|value|
>|---|---|---|---|---|---|---|
>| Country | cc6a2856da2806b03839f81aa214f22dbcfd7369 | 11.11.11.11 | 80 | green | some.com | 11.11.11.11 |

### gibtia-get-suspicious-ip-socks-proxy-info

***
Command performs Group-IB event lookup in suspicious_ip/socks_proxy collection with provided ID.

#### Base Command

`gibtia-get-suspicious-ip-socks-proxy-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: 02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.SuspiciousIPSocksProxy.ipv4.asn | String | Proxy IP ASN |
| GIBTIA.SuspiciousIPSocksProxy.ipv4.countryName | String | Proxy IP country name |
| GIBTIA.SuspiciousIPSocksProxy.ipv4.ip | String | Proxy IP address |
| GIBTIA.SuspiciousIPSocksProxy.ipv4.region | String | Proxy IP region name |
| GIBTIA.SuspiciousIPSocksProxy.id | String | GIB ID |
| GIBTIA.SuspiciousIPSocksProxy.evaluation.severity | String | Event severity |

#### Command Example

```!gibtia-get-suspicious-ip-socks-proxy-info id=02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e```

#### Human Readable Output

>### Feed from suspicious_ip/socks_proxy with ID 02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e

>|dateDetected|dateFirstSeen|dateLastSeen|evaluation admiraltyCode|evaluation credibility|evaluation reliability|evaluation severity|evaluation tlp|evaluation ttl|id|ipv4 asn|ipv4 countryCode|ipv4 countryName|ipv4 ip|ipv4 provider|oldId|portalLink|source|stixGuid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-01-19T07:41:11+00:00 | 2021-01-19T07:41:11+00:00 | 2021-02-23T20:58:51+00:00 | A1 | 100 | 90 | green | amber | 2 | 02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e | AS11111 | Country Code | Country | 11.11.11.11 | Some | 395880626 | <https://group-ib.com/suspicious/socks?searchValue=id:02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e> | awmproxy.com | 78cd5f78-e542-bf2c-fc40-e2a41b36dd97 |

>### IP indicator

>|asn|geocountry|gibid|severity|value|
>|---|---|---|---|---|
>| AS11111 | Country | 02e385600dfc5bf9b3b3656df8e0e20f5fc5c86e | green | 11.11.11.11 |

### gibtia-get-malware-cnc-info

***
Command performs Group-IB event lookup in malware/cnc collection by provided ID.

#### Base Command

`gibtia-get-malware-cnc-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | GIB event id.<br/>e.g.: aeed277396e27e375d030a91533aa232444d0089. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.MalwareCNC.dateDetected | Date | Date CNC detected |
| GIBTIA.MalwareCNC.dateLastSeen | Date | Date CNC last seen |
| GIBTIA.MalwareCNC.url | String | CNC URL |
| GIBTIA.MalwareCNC.domain | String | CNC domain |
| GIBTIA.MalwareCNC.ipv4.asn | String | CNC ASN |
| GIBTIA.MalwareCNC.ipv4.countryName | String | CNC IP country name |
| GIBTIA.MalwareCNC.ipv4.ip | String | CNC IP address |
| GIBTIA.MalwareCNC.ipv4.region | String | CNC region name |
| GIBTIA.MalwareCNC.malwareList.name | String | Associated malware |
| GIBTIA.MalwareCNC.threatActor.id | String | Associated threat actor ID |
| GIBTIA.MalwareCNC.threatActor.name | String | Associated threat actor |
| GIBTIA.MalwareCNC.threatActor.isAPT | Boolean | Is APT or not |
| GIBTIA.MalwareCNC.id | String | GIB event ID |

#### Command Example

```!gibtia-get-malware-cnc-info id=aeed277396e27e375d030a91533aa232444d0089```

#### Human Readable Output

>### Feed from malware/cnc with ID aeed277396e27e375d030a91533aa232444d0089

>|cnc|dateDetected|dateLastSeen|domain|id|oldId|stixGuid|url|
>|---|---|---|---|---|---|---|---|
>| <<<<<<<<<<https://some.com>>>>>>>>>> | 2021-04-25T13:37:23+00:00 | 2021-04-25T13:37:23+00:00 | some.com | aeed277396e27e375d030a91533aa232444d0089 | 211146923 | 417b2644-1105-d65b-4b67-a78e82f59b65 | https://some.com |

>### ipv4 table

>|asn|countryCode|countryName|ip|provider|
>|---|---|---|---|---|
>| AS1111 | US | United States | 11.11.11.11 | Some |

>### malwareList table

>|id|name|stixGuid|
>|---|---|---|
>| e99c294ffe7b79655d6ef1f32add638d8a2d4b24 | JS Sniffer - Poter | 1ac5a303-ef6f-2d6a-ad20-a39196815a1a |

>### URL indicator

>|gibid|value|
>|---|---|
>| aeed277396e27e375d030a91533aa232444d0089 | <https://some.com> |

>### Domain indicator

>|gibid|value|
>|---|---|
>| aeed277396e27e375d030a91533aa232444d0089 | some.com |

>### IP indicator

>|asn|geocountry|gibid|value|
>|---|---|---|---|
>| AS1111 | United States | aeed277396e27e375d030a91533aa232444d0089 | 11.11.11.11 |

### gibtia-get-available-collections

***
Returns list of available collections.

#### Base Command

`gibtia-get-available-collections`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBTIA.OtherInfo.collections | String | List of availiable collections |

#### Command Example

```!gibtia-get-available-collections```

#### Human Readable Output

>### Available collections

>|collections|
>|---|
>| compromised/account,<br/>compromised/card,<br/>bp/phishing,<br/>bp/phishing_kit,<br/>osi/git_leak,<br/>osi/public_leak,<br/>malware/targeted_malware,<br/>compromised/mule,<br/>compromised/imei,<br/>attacks/ddos,<br/>attacks/deface,<br/>attacks/phishing,<br/>attacks/phishing_kit,<br/>apt/threat,<br/>hi/threat,<br/>suspicious_ip/tor_node,<br/>suspicious_ip/open_proxy,<br/>suspicious_ip/socks_proxy,<br/>malware/cnc,<br/>osi/vulnerability,<br/>hi/threat_actor,<br/>apt/threat_actor |

### gibtia-global-search

***
Command performs global Group-IB search

#### Base Command

`gibtia-global-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query you want to search.<br/>e.g.: 8.8.8.8. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| apiPath | String | Name of collection in which found matches |
| count | Number | Count of feeds matching this query |
| GIBLink | String | Link to GIB TI&amp;A interface |

#### Command Example

```!gibtia-global-search query=100.100.100.100```

#### Human Readable Output

>### Search results

>|apiPath|count|GIBLink|
>|---|---|---|
>| compromised/account | 14 |  |
>| attacks/phishing | 1 | [https://group-ib.com/attacks/phishing?searchValue=100.100.100.100&q=100.100.100.100](https://group-ib.com/attacks/phishing?searchValue=100.100.100.100&q=100.100.100.100) |
>| bp/phishing | 1 |  |
>| osi/git_leak | 5 | [https://group-ib.com/osi/git_leaks?searchValue=100.100.100.100&q=100.100.100.100](https://group-ib.com/osi/git_leaks?searchValue=100.100.100.100&q=100.100.100.100) |
>| osi/public_leak | 23 | [https://group-ib.com/osi/public_leak?searchValue=100.100.100.100&q=100.100.100.100](https://group-ib.com/osi/public_leak?searchValue=100.100.100.100&q=100.100.100.100) |

### gibtia-local-search

***
Command performs Group-IB search in selected collection.

#### Base Command

`gibtia-local-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_name | Collection you want to search. Possible values are same as collection names in [Data Collections Overview](#data-collections-overview) . | Required |
| query | Query you want to search.<br/>e.g.: 8.8.8.8. | Required |
| date_from | Start date of search session. | Optional |
| date_to | End date of search session. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| id | String | Id of a feed that matches a query |
| additional_info | String | Additional info about feed |

#### Command Example

```!gibtia-local-search collection_name=attacks/phishing query=100.100.100.100```

#### Human Readable Output

### Search results

|id|additional_info|
|---|---|
| 8bd7e5cef2290b0c3f04bf283586406dceffe25d | phishingDomain_domain: some.com |
