
Use Group-IB Threat Intelligence & Attribution Feed integration to fetch IOCs from various Group-IB collections.
This integration was integrated and tested with version 1.0 of Group-IB Threat Intelligence & Attribution Feed

## Important Notes

### Limit Parameter

The **Limit (items per request)** parameter specifies the number of records requested per API page. This limit applies to **all collections** configured in the integration instance.

**Important considerations:**

- The limit determines how many records are fetched in a **single API request**. For example, if "Number of requests per collection" is set to 2 and the limit is 500, the integration will make 2 requests per collection, each requesting up to 500 records, resulting in up to 1000 records per collection per fetch cycle.
- Different collections may have different optimal limit values based on their data structure and API recommendations. We strongly recommend consulting the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) for specific limit recommendations for each collection.
- **Best practice**: Create separate integration instances for different collections or groups of collections that share similar optimal limit values. This allows you to optimize performance for each collection type.

### Collection Information

For detailed information about each collection, its structure, and available fields, please refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).

## Data Collections Overview

Once the configuration is complete, the following collections become available in Cortex XSOAR.

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
| `ioc/common` | General indicators of Compromise (IoCs) from threat reports (cybercriminals and APT) and Malware sections. Consists of Hashes (MD5, SHA1, SHA256), IPs, domains and URLs. Major source of IOCs. Contains: malware/malware, malware/cnc, hi/threat, apt/threat, hi/threat_actor, apt/threat_actor. | 90 days |
| `malware/cnc` | Information on malware Command-and-Control (C&C) servers used for data exfiltration and command distribution. This feed is also part of IOC Common. | 90 days |
| `malware/config` | Extracted malware configuration data. | 90 days |
| `malware/malware` | Detailed malware descriptions. | 2-4 years |
| `malware/signature` | Suricata signatures for malware detection. | 30 days |
| `malware/yara` | YARA rules for identifying specific malware families. | 30 days |
| `osi/git_repository` | Publicly available code from repositories like GitHub, filtered by your hunting rules. **Note:** Hunting rules are on by default here. | 30 days |
| `osi/public_leak` | Public data leaks from sources like Pastebin, ghostbin, and others, including credentials, database dumps, configuration files, and logs. **Note:** Hunting rules are on by default here. | 15 days |
| `osi/vulnerability` | Information on software vulnerabilities, associated exploits, and available proof-of-concept details. | 90 days |
| `suspicious_ip/tor_node` | Data about known Tor exit nodes used as anonymity relays. | 5 days |
| `suspicious_ip/open_proxy` | Information on publicly available proxy servers, including potentially misconfigured proxies. | 5 days |
| `suspicious_ip/scanner` | IP addresses identified as scanning or probing corporate networks. | 5 days |
| `suspicious_ip/socks_proxy` | IP addresses of infected hosts configured as SOCKS proxies used for anonymized attacks. | 5 days |
| `suspicious_ip/vpn` | Information about public and private VPN servers identified as potentially malicious or suspicious. | 5 days |

## Configure Group-IB Threat Intelligence & Attribution Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| GIB TI&amp;A URL | The FQDN/IP the integration should connect to. | True |
| Username | The API Key and Username required to authenticate to the service. | True |
| Trust any certificate (not secure) | Whether to allow connections without verifying SSL certificates validity. | False |
| Use system proxy settings | Whether to use XSOAR system proxy settings to connect to the API. | False |
| Incremental feed | Incremental feeds pull only new or modified indicators that have been sent from the integration. The determination if the indicator is new or modified happens on the 3rd-party vendor's side, so only indicators that are new or modified are sent to Cortex XSOAR. Therefore, all indicators coming from these feeds are labeled new or modified. | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Indicator collections | Collections List to include for fetching. | False |
| Indicator first fetch | Date to start fetching indicators from. | False |
| Number of requests per collection | A number of requests per collection that integration sends in one fetch iteration \(each request picks up to 200 objects with different amount of indicators\). If you face some runtime errors, lower the value. | False |
| Limit (items per request) | Number of items requested per API page. This limit applies to all collections in the instance. The limit determines how many records are fetched in a single API request. For example, if "Number of requests per collection" is 2 and limit is 500, the integration will make 2 requests per collection, each requesting up to 500 records, resulting in up to 1000 records per collection per fetch cycle. We recommend following the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) for collection-specific limit recommendations. Best practice: create separate integration instances for different collections or groups of collections with similar optimal limit values. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gibtia-get-indicators

***
Get limited count of indicators for specified collection and get all indicators from particular events by id.

#### Base Command

`gibtia-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | GIB Collection to get indicators from. Possible values are: compromised/mule, compromised/imei, attacks/ddos, attacks/deface, attacks/phishing, attacks/phishing_kit, hi/threat, apt/threat, osi/vulnerability, suspicious_ip/tor_node, suspicious_ip/open_proxy, suspicious_ip/socks_proxy, malware/cnc. | Required |
| id | Incident Id to get indicators(if set, all the indicators will be provided from particular incident). | Optional |
| limit | Limit of indicators to display in War Room. Possible values are: 10, 20, 30, 40, 50. Default is 50. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

```!gibtia-get-indicators collection=compromised/mule```

#### Human Readable Output

>### IP indicators

>|value|type|asn|geocountry|gibmalwarename|
>|---|---|---|---|---|
>| 11.11.11.11 | IP |  |  | Anubis |
>| 11.11.11.11 | IP | AS12121 | France | FlexNet |
>| 11.11.11.11 | IP | AS1313 | United States | FlexNet |
