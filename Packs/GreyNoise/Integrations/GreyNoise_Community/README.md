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
| IP.Address | string | IP address. |
| IP.ASN | string | ASN Value. |
| IP.Geo.Country | string | Source Country. |
| IP.Geo.Description | string | Additional Geo Information - City, Region, Country Code. |
| IP.Hostname | string | rDNS value. |
| IP.Malicious.Description | string | Description of Malicious IP. |
| IP.Malicious.Vendor | string | Vendor Identifying IP as Malicious. |
| GreyNoise.IP.actor | string | Name of identified organization scanning. |
| GreyNoise.IP.address | string | The IP address of the scanning device IP. |
| GreyNoise.IP.bot | boolean | Identifies if the IP is associated with BOT activity. |
| GreyNoise.IP.category | string | If a business service, identifies the category. |
| GreyNoise.IP.classification | string | Whether the device has been categorized as unknown, benign, or malicious. |
| GreyNoise.IP.description | string | If there is a business service, provides a description of the provider. |
| GreyNoise.IP.explanation | string | If there is a business service, provides an explanation of the category. |
| GreyNoise.IP.first_seen | string | The date of the first observed scanning activity. |
| GreyNoise.IP.found | boolean | Whether the IP is found in GreyNoise. |
| GreyNoise.IP.ip | string | The IP address of the scanning device IP. |
| GreyNoise.IP.last_seen | string | The date of the last observed scanning activity. |
| GreyNoise.IP.last_seen_timestamp | string | The timestamp of the last observed scanning activity. |
| GreyNoise.IP.last_updated | string | If there is a business service, indicates the last time the source record was parsed. |
| GreyNoise.IP.metadata.asn | string | The autonomous system identification number. |
| GreyNoise.IP.metadata.carrier | string | The carrier information for the IP address. |
| GreyNoise.IP.metadata.category | string | Whether the device belongs to a business, isp, hosting, education, or mobile network. |
| GreyNoise.IP.metadata.datacenter | string | The datacenter information for the IP address. |
| GreyNoise.IP.metadata.destination_countries | array | The list of countries targeted by scanning. |
| GreyNoise.IP.metadata.destination_country_codes | array | The list of country codes targeted by scanning. |
| GreyNoise.IP.metadata.domain | string | The domain associated with the IP address. |
| GreyNoise.IP.metadata.latitude | number | The latitude coordinate of the IP address location. |
| GreyNoise.IP.metadata.longitude | number | The longitude coordinate of the IP address location. |
| GreyNoise.IP.metadata.mobile | boolean | Whether the device is on a mobile network. |
| GreyNoise.IP.metadata.organization | string | The organization that owns the network that the IP address belongs to. |
| GreyNoise.IP.metadata.os | string | The name of the operating system of the device. |
| GreyNoise.IP.metadata.rdns | string | Reverse DNS lookup of the IP address. |
| GreyNoise.IP.metadata.rdns_parent | string | The parent domain of the reverse DNS lookup. |
| GreyNoise.IP.metadata.rdns_validated | boolean | Whether the reverse DNS lookup has been validated. |
| GreyNoise.IP.metadata.region | string | The full name of the region the device is geographically located in. |
| GreyNoise.IP.metadata.sensor_count | number | The number of sensors that observed activity from this IP. |
| GreyNoise.IP.metadata.sensor_hits | number | The number of sensors events recorded from this IP. |
| GreyNoise.IP.metadata.single_destination | boolean | Whether the IP targets a single destination. |
| GreyNoise.IP.metadata.source_city | string | The city where the IP is geographically located. |
| GreyNoise.IP.metadata.source_country | string | The full name of the IP source country. |
| GreyNoise.IP.metadata.source_country_code | string | The country code of the IP source country. |
| GreyNoise.IP.name | string | If there is a business service, indicates the provider name. |
| GreyNoise.IP.raw_data.source.bytes | number | The number of bytes sent by the source. |
| GreyNoise.IP.reference | string | If there is a business service, indicates the references used to validate the entry. |
| GreyNoise.IP.riot | boolean | Whether the IP is in the business services dataset. |
| GreyNoise.IP.seen | boolean | Whether the IP is in the internet scanner dataset. |
| GreyNoise.IP.spoofable | boolean | Whether the IP complete a three-way handshake during scanning. |
| GreyNoise.IP.tags.category | string | The category of the given tag. |
| GreyNoise.IP.tags.created | date | The date the tag was added to the GreyNoise system. |
| GreyNoise.IP.tags.description | string | A description of what the tag identifies. |
| GreyNoise.IP.tags.id | string | The unique id of the tag. |
| GreyNoise.IP.tags.intention | string | The intention of the associated activity the tag identifies. |
| GreyNoise.IP.tags.name | string | The name of the tag. |
| GreyNoise.IP.tags.recommend_block | boolean | Indicates if IPs associated with this tag should be blocked. |
| GreyNoise.IP.tags.references | string | A list of references used to create the tag. |
| GreyNoise.IP.tags.slug | string | The unique slug of the tag. |
| GreyNoise.IP.tags.updated_at | date | The date the tag was last updated. |
| GreyNoise.IP.tor | boolean | Whether the IP is on the known TOR exit node list. |
| GreyNoise.IP.trust_level | string | If there is a business service, indicates the level of trustworthiness. |
| GreyNoise.IP.vpn | boolean | Whether the IP is associated with a knwon VPN service. |
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
