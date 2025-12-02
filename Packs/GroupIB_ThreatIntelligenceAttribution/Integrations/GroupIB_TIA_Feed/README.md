# Group-IB Threat Intelligence Feed

Use Group-IB Threat Intelligence Feed integration to fetch IOCs (Indicators of Compromise) from various Group-IB collections. The integration supports multiple collections - see the [Data Collections Overview](#data-collections-overview) section below for the complete list with descriptions and recommended date ranges (indicator first fetch).

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
   - Make sure you have added Group-IB [API IPs/URLs](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FInitial%20Steps%2FInitial%20Steps) to your FW/Proxy rules.

## Important Notes

### Limit Parameter

The **Limit (items per request)** parameter specifies the number of records requested per API page. This limit applies to **all collections** configured in the integration instance.

**Important considerations:**

- The limit determines how many records are fetched in a **single API request**. For example, if "Number of requests per collection" is set to 2 and the limit is 100, the integration will make 2 requests per collection, each requesting up to 100 records, resulting in up to 200 records per collection per fetch cycle.
- Different collections may have different optimal limit values based on their data structure and API recommendations. We strongly recommend consulting the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) for specific limit recommendations for each collection.
- **Best practice**: Create separate integration instances for different collections or groups of collections that share similar optimal limit values. This allows you to optimize performance for each collection type.

## Data Collections Overview

Once the configuration is complete, the following collections become available in Cortex XSOAR. For detailed information about each collection, its structure, and available fields, please refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).

**Note:** If you're using a POC or partner license, access to data is limited to 30 days. The recommended date ranges below are guidelines and can be adjusted according to your needs.

| Collection | Description | Recommended Date Range |
|------------|-------------|----------------------|
| `compromised/account_group` | In your compromised accounts, there CNCs in place which can be used as IOCs. Usually included in IOC Common. | 2-4 years |
| `compromised/bank_card_group` | In your compromised cards, there CNCs in place which can be used as IOCs. Usually included in IOC Common. | 2 years |
| `compromised/mule` | Information on compromised accounts used by threat actors for money laundering and fund transfers. Collection is currently deprecated - only legacy information is available | 90 days |
| `attacks/ddos` | Data on Distributed Denial of Service (DDoS) attacks, including targeted resources and attack durations. | 5-10 days |
| `attacks/deface` | Records of defacement attacks, highlighting compromised websites and related actors. | 5-10 days |
| `attacks/phishing_group` | Information on phishing attacks, including URLs of phishing websites. **Note:** Do not use IPs for detection - it may cause many false positives. Focus only on URLs. | 3-5 days |
| `attacks/phishing_kit` | Collections of phishing website templates, scripts, and configurations used by attackers. | 30 days |
| `apt/threat` | IOCs only from APT reports. | 2-4 years |
| `hi/threat` | IOCs only from Cybercriminals reports. | 2-4 years |
| `ioc/common` | General indicators of Compromise (IoCs) from threat reports (Cybercriminals and APT) and Malware sections. Consists of Hashes (MD5, SHA1, SHA256), IPs, domains and URLs. Major source of IOCs. Contains: malware/malware, malware/cnc, hi/threat, apt/threat, hi/threat_actor, apt/threat_actor. | 90 days |
| `malware/cnc` | Information on malware Command-and-Control (C&C) servers used for data exfiltration and command distribution. This feed is also part of IOC Common. | 90 days |
| `osi/vulnerability` | Information on software vulnerabilities, associated exploits, and available proof-of-concept details. | 90 days |
| `suspicious_ip/tor_node` | Data about known Tor exit nodes used as anonymity relays. | 5 days |
| `suspicious_ip/open_proxy` | Information on publicly available proxy servers, including potentially misconfigured proxies. | 5 days |
| `suspicious_ip/scanner` | IP addresses identified as scanning or probing corporate networks. | 5 days |
| `suspicious_ip/socks_proxy` | IP addresses of infected hosts configured as SOCKS proxies used for anonymized attacks. | 5 days |
| `suspicious_ip/vpn` | Information about public and private VPN servers identified as potentially malicious or suspicious. | 5 days |

## Configure Group-IB Threat Intelligence Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| GIB TI URL | The FQDN/IP the integration should connect to (default: `https://tap.group-ib.com/api/v2/`). | True |
| Username | Enter the email address you use to log into the web interface. The API token serves as your password for authentication. | True |
| Trust any certificate (not secure) | Whether to allow connections without verifying SSL certificates validity. | False |
| Use system proxy settings | Whether to use XSOAR system proxy settings to connect to the API. | False |
| Fetches indicators | Enable to fetch indicators from the feed (default: enabled). | False |
| Indicator Reputation | Select the default reputation for indicators from this feed (default: Suspicious). Options: Unknown, Benign, Suspicious, Malicious. As an example, it is recommended to use Malicious for IOC common and Suspicious for Suspicious IP collections. | False |
| Source Reliability | Select the reliability rating for the source (**required**, default: A - Completely reliable). Options: A - Completely reliable, B - Usually reliable, C - Fairly reliable, D - Not usually reliable, E - Unreliable, F - Reliability cannot be judged. | True |
| Feed Fetch Interval | Configure how often to fetch indicators (hours and minutes, default: 1 minute). | False |
| Bypass exclusion list | When enabled, bypasses the exclusion list for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Indicator collections | Select the collections you want to fetch indicators from. Read more about collections [here](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details). | False |
| Indicator first fetch | Specify the date range for initial data fetch (default: "3 days"). | False |
| Number of requests per collection | Number of API requests per collection in each fetch iteration (default: 2). Each request picks up to 100 (limit) objects with different amount of indicators. If you face runtime errors, lower the value. | False |
| Limit (items per request) | Specifies the number of records fetched per API request (default: 100). This limit applies to all collections in the instance. For optimal performance, check the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) for recommended limit values per collection. Best practice: create separate integration instances for different collections or groups of collections with similar optimal limit values. | False |
| Tags | Enter tags for indicators if needed. | False |
| Traffic Light Protocol Color | Select the Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. Options: RED, AMBER, GREEN, WHITE (default: AMBER). | False |
| Indicator Expiration Method | Configure how indicators expire. Options: Time Interval, Never Expire, When removed from the feed. | False |

## Additional Resources

For detailed information about collections, their structure, available fields, and recommended date ranges, refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).

For step-by-step configuration instructions including classifier and mapper setup, refer to the integration description file.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gibtia-get-indicators

***
Get a limited count of indicators for a specified collection and get all indicators from particular events by ID.

#### Base Command

`gibtia-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | GIB Collection to get indicators from. Possible values are: compromised/mule, compromised/imei, attacks/ddos, attacks/deface, attacks/phishing, attacks/phishing_kit, hi/threat, apt/threat, osi/vulnerability, suspicious_ip/tor_node, suspicious_ip/open_proxy, suspicious_ip/socks_proxy, malware/cnc. | Required |
| id | Incident ID to get indicators. If set, all indicators will be provided from the particular incident. | Optional |
| limit | Limit of indicators to display in War Room. Possible values are: 10, 20, 30, 40, 50. Default is 50. | Optional |

#### Command Example

```!gibtia-get-indicators collection=ioc/common```
