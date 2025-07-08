GreyNoise tells security analysts what not to worry about. We do this by curating data on IPs that saturate security
tools with noise. This unique perspective helps analysts confidently ignore irrelevant or harmless activity, creating
more time to uncover and investigate true threats. The Action allows IP enrichment via the GreyNoise Community API.

The [GreyNoise Integration](https://github.com/demisto/content/tree/master/Packs/GreyNoise/Integrations/GreyNoise)
should be used by customers with a paid subscription to GreyNoise with the exception of the IP command, which is available with limit results to free users.

This integration was integrated and tested with version 3.0.0 of GreyNoise Python SDK.
Supported Cortex XSOAR versions: 6.0.0 and later.

## Configure GreyNoise in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| api_key | GreyNoise API Key | True |
| proxy | Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### greynoise-community-lookup

***
Queries IPs in the GreyNoise Community API.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Reliability | String | The reliability value. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| IP.address | string | IP address. |
| IP.ASN | string | ASN Value. |
| IP.Geo.Country | string | Source Country. |
| IP.Geo.Description | string | Additional Geo Information - City, Region, Country Code. |
| IP.Hostname | string | rDNS value. |
| IP.Malicious.Description | string | Description of Malicious IP. |
| IP.Malicious.Vendor | string | Vendor Identifying IP as Malicious. |
| GreyNoise.IP.actor | string | Name of identified organization scanning
| GreyNoise.IP.address | string | The IP address of the scanning device IP. |
| GreyNoise.IP.bot | boolean | Identifies if the IP is associated with BOT activity. |
| GreyNoise.IP.category | string | If a business service, identifies the category. |
| GreyNoise.IP.classification | string | Whether the device has been categorized as unknown, benign, or malicious. |
| GreyNoise.IP.descriptionn | string | If a business service, provides a description of the provider. |
| GreyNoise.IP.explanationn | string | If a business service, provides an explanation of the category. |
| GreyNoise.IP.found | boolean | Indicates if the IP is found in GreyNoise. |
| GreyNoise.IP.last_seen | string | Identifes the last observed scanning activity date. |
| GreyNoise.IP.last_seen_timestamp | string | Identifes the last observed scanning activity timestamp. |
| GreyNoise.IP.last_updated | string | If a business service, indicates the last time the source record was parsed. |
| GreyNoise.IP.metadata | object | Metadata about the source IP, such as IP Geo information
| GreyNoise.IP.name | string | If a business service, indicates the provider name. |
| GreyNoise.IP.reference | string | If a business service, indicates the references used to validate the entry. |
| GreyNoise.IP.riot | boolean | Indicates if the IP is in the business services dataset. |
| GreyNoise.IP.seen | boolean | Indicates if the IP is in the internet scanner dataset. |
| GreyNoise.IP.spoofable | boolean | Indicates if the IP complete a three-way handshake during scanning. |
| GreyNoise.IP.trust_level | string | If a business service, indicates the level of trustworthiness. |
| GreyNoise.IP.tor | boolean | Indicates if the IP is on the known TOR exit node list. |
| GreyNoise.IP.vpn | boolean | Indicates if the IP is associated with a knwon VPN service. |
| GreyNoise.IP.vpn_service | string | If the IP is part of a VPN, provides the name of the service. |

#### Command Example

``` !greynoise-community-lookup ips=1.1.1.1 ```
``` !IPReputation ip=1.1.1.1 ```

#### Human Readable Output

### IP: 1.1.1.1 found with Reputation: Good

#### Belongs to Common Business Service: Cloudflare Public DNS

### GreyNoise Business Service Intelligence Lookup

|IP|Business Service|Category|Name|Trust Level|Description|Last Updated|
|---|---|---|---|---|---|---|
| [1.1.1.1](https://viz.greynoise.io/ip/1.1.1.1) | true | public_dns | Cloudflare Public DNS | 1 - Reasonably Ignore | Cloudflare, Inc. is an American web infrastructure and website security company, providing content delivery network (CDN) services, distributed denial of service (DDoS) mitigation, Internet security, and distributed domain name system (DNS) services. This is their public DNS offering. | 2025-06-26T09:10:56Z |

### IP: 1.1.1.1 No Mass-Internet Scanning Observed

### GreyNoise Internet Scanner Intelligence Lookup

|IP|Internet Scanner|
|---|---|
| 1.1.1.1 | false |
