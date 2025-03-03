## Overview

Team Cymru's Scout integration with Palo Alto XSOAR helps streamline incident triage and accelerate threat response by providing domain and threat intelligence data.
This integration was integrated and tested with API of Team Cymru Scout.

### Key Features

- Leverage communication data to identify correlations between IP addresses, identify compromised hosts, and uncover other indications of an attack.
- Access a quick summary of NetFlow communications, Whois information, PDNS, X509 certificates, and fingerprinting details.
- Supports both IPv4 and IPv6 address queries.
- Provides real-time threat intelligence and helps in identifying and mitigating potential security threats.
- Offers extensive documentation and support resources to assist with setup, configuration, and troubleshooting.

## Prerequisites for configuring integration instance

- Access to the [Team Cymru Scout platform](https://scout.cymru.com/scout).
- An API Key or Basic Auth credentials for authentication.

### Generate API Keys

If you prefer to use an API key for authentication, you can generate one as follows:

1. Go to the [API Keys page](https://scout.cymru.com/api_keys).
2. Click on the "Create" button.
3. Provide the description for the key, if needed.
4. Click on the "Create Key" button to generate the API key.

Note:

- The number of API keys allowed for each organization is equal to the number of user seats. Therefore, an individual user may have multiple keys, but all the users in your organization may have a maximum of 5 keys. The [API Keys page](https://scout.cymru.com/api_keys) shows the total number of keys used by your organization.
- If the "Create" button is disabled, it indicates that you have reached the maximum number of keys allowed for your organization. To generate a new key, you need to:
  - Click on the "Revoke" button next to an old key.
  - Click on the "Create Key" button to start generating a new key.

## Configure Team Cymru Scout in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Authentication Type | The authentication type used for secure communication with the Team Cymru Scout platform. | True |
| API Key | The API key used for secure communication with the Team Cymru Scout platform. Required if "API Key" as Authentication Type is selected. | False |
| Username, Password | The username and password used for secure communication with the Team Cymru Scout platform. Required if "Basic Auth" as Authentication Type is selected. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Create relationships | Create relationships between indicators as part of enrichment. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### scout-api-usage

***
Returns all the information on used queries and remaining queries with the query limit.

#### Base Command

`scout-api-usage`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TeamCymruScout.QueryUsage.command_name | String | The name of the Cortex XSOAR command that triggered the Foundation API. | 
| TeamCymruScout.QueryUsage.used_queries | Number | The number of queries used. | 
| TeamCymruScout.QueryUsage.remaining_queries | Number | The number of remaining queries. | 
| TeamCymruScout.QueryUsage.query_limit | Number | The total number of queries allowed. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.used_queries | Number | The number of queries used for the Foundation API. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.remaining_queries | Number | The number of remaining queries for the Foundation API. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.query_limit | Number | The total number of queries allowed for the Foundation API. | 

#### Command example
```!scout-api-usage```
#### Context Example
```json
{
    "TeamCymruScout": {
        "QueryUsage": {
            "command_name": "scout-api-usage",
            "foundation_api_usage": {
                "query_limit": 0,
                "remaining_queries": 0,
                "used_queries": 9
            },
            "query_limit": 50000,
            "remaining_queries": 49834,
            "used_queries": 166
        }
    }
}
```

#### Human Readable Output

>### API Usage
>|Used Queries|Remaining Queries|Query Limit|Foundation Used Queries|Foundation Remaining Queries|Foundation Query Limit|
>|---|---|---|---|---|---|
>| 166 | 49834 | 50000 | 9 | 0 | 0 |


### ip

***
Return all the detailed information available for the given IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address for which to retrieve available IP details. | Required | 
| start_date | The start date for detailed information.<br/><br/>Supported formats: 2 days, 2 weeks, 2 months, yyyy-mm-dd.<br/><br/>For example: 01 June 2024, 2024-06-17. Default is 30 days. | Optional | 
| end_date | The end date for detailed information.<br/><br/>Supported formats: 2 days, 2 weeks, 2 months, yyyy-mm-dd.<br/><br/>For example: 01 June 2024, 2024-06-17. Default is now. | Optional | 
| days | Relative offset in days from the current time. It cannot exceed the maximum range of 30 days.<br/><br/>Note: This will take priority over start_date and end_date if all three are passed. | Optional | 
| size | The maximum number of records to return.<br/><br/>Note: The maximum allowed size is 1000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | String | IP address. | 
| IP.Relationships.EntityA | String | The source of the relationship. | 
| IP.Relationships.EntityB | String | The destination of the relationship. | 
| IP.Relationships.Relationship | String | The name of the relationship. | 
| IP.Relationships.EntityAType | String | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | String | The type of the destination of the relationship. | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Hostname | String | The hostname that is mapped to this IP address. | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Geo.Description | String | Additional information about the location. | 
| IP.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| IP.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Tags | Unknown | \(List\) Tags of the IP address. | 
| IP.FeedRelatedIndicators.value | String | Indicators that are associated with the IP address. | 
| IP.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the IP address. | 
| IP.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the IP address. | 
| IP.MalwareFamily | String | The malware family associated with the IP address. | 
| IP.Organization.Name | String | The organization of the IP address. | 
| IP.Organization.Type | String | The organization type of the IP address. | 
| IP.ASOwner | String | The autonomous system owner of the IP address. | 
| IP.Region | String | The region in which the IP address is located. | 
| IP.Port | String | Ports that are associated with the IP address. | 
| IP.Internal | Boolean | Whether the IP address is internal or external. | 
| IP.UpdatedDate | Date | The date that the IP address was last updated. | 
| IP.Registrar.Abuse.Name | String | The name of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Address | String | The address of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Country | String | The country of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Network | String | The network of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Phone | String | The phone number of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Email | String | The email address of the contact for reporting abuse. | 
| IP.Campaign | String | The campaign associated with the IP address. | 
| IP.TrafficLightProtocol | String | The Traffic Light Protocol \(TLP\) color that is suitable for the IP address. | 
| IP.CommunityNotes.note | String | Notes on the IP address that were given by the community. | 
| IP.CommunityNotes.timestamp | Date | The time in which the note was published. | 
| IP.Publications.source | String | The source in which the article was published. | 
| IP.Publications.title | String | The name of the article. | 
| IP.Publications.link | String | A link to the original article. | 
| IP.Publications.timestamp | Date | The time in which the article was published. | 
| IP.ThreatTypes.threatcategory | String | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. | 
| IP.ThreatTypes.threatcategoryconfidence | String | The confidence level provided by the vendor for the threat type category For example, a confidence of 90 for the threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. | 
| TeamCymruScout.QueryUsage.request_id | String | The request ID of the API call. | 
| TeamCymruScout.QueryUsage.size | Number | The number of records returned. | 
| TeamCymruScout.QueryUsage.start_date | Date | The earliest date for detailed information. | 
| TeamCymruScout.QueryUsage.end_date | Date | The latest date for detailed information. | 
| TeamCymruScout.QueryUsage.used_queries | Number | The number of queries used. | 
| TeamCymruScout.QueryUsage.remaining_queries | Number | The number of remaining queries. | 
| TeamCymruScout.QueryUsage.query_limit | Number | The maximum number of queries allowed. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.used_queries | Number | The number of queries used by the Foundation API. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.remaining_queries | Number | The number of remaining queries for the Foundation API. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.query_limit | Numbe | The maximum number of queries allowed for the Foundation API. | 
| TeamCymruScout.IP.ip | String | The IP address. | 
| TeamCymruScout.IP.sections | String | The sections of data returned. | 
| TeamCymruScout.IP.identity.tags | Unknown | The tags associated with the IP address. | 
| TeamCymruScout.IP.identity.reverse_hostnames | Unknown | The reverse hostnames associated with the IP address. | 
| TeamCymruScout.IP.identity.asn | Number | The autonomous system number associated with the IP address. | 
| TeamCymruScout.IP.identity.as_name | String | The name associated with the autonomous system number. | 
| TeamCymruScout.IP.identity.net_name | String | The name associated with the network. | 
| TeamCymruScout.IP.identity.org_name | String | The name associated with the organization. | 
| TeamCymruScout.IP.whois.modified | Date | The date the WHOIS information was last modified. | 
| TeamCymruScout.IP.whois.asn | Number | The autonomous system number associated with the IP address. | 
| TeamCymruScout.IP.whois.cidr | String | The network associated with the IP address. | 
| TeamCymruScout.IP.whois.as_name | String | The name associated with the autonomous system number. | 
| TeamCymruScout.IP.whois.bgp_asn | Number | The Border Gateway Protocol \(BGP\) autonomous system number \(ASN\) associated with the IP address. | 
| TeamCymruScout.IP.whois.bgp_asn_name | String | The name associated with the Border Gateway Protocol \(BGP\) autonomous system number \(ASN\). | 
| TeamCymruScout.IP.whois.net_name | String | The name associated with the network. | 
| TeamCymruScout.IP.whois.net_handle | String | The handle associated with the network. | 
| TeamCymruScout.IP.whois.description | String | The description associated with the network. | 
| TeamCymruScout.IP.whois.cc | String | The country code associated with the network. | 
| TeamCymruScout.IP.whois.city | String | The city associated with the network. | 
| TeamCymruScout.IP.whois.address | String | The address associated with the network. | 
| TeamCymruScout.IP.whois.abuse_contact_id | String | The abuse contact ID associated with the network. | 
| TeamCymruScout.IP.whois.about_contact_role | String | The role associated with the about contact. | 
| TeamCymruScout.IP.whois.about_contact_person | String | The person associated with the about contact. | 
| TeamCymruScout.IP.whois.about_contact_email | String | The email associated with the about contact. | 
| TeamCymruScout.IP.whois.about_contact_phone | String | The phone number associated with the about contact. | 
| TeamCymruScout.IP.whois.about_contact_country | String | The country associated with the about contact. | 
| TeamCymruScout.IP.whois.about_contact_city | String | The city associated with the about contact. | 
| TeamCymruScout.IP.whois.about_contact_address | String | The address associated with the about contact. | 
| TeamCymruScout.IP.whois.admin_contact_id | String | The ID associated with the admin contact. | 
| TeamCymruScout.IP.whois.admin_contact_role | String | The role associated with the admin contact. | 
| TeamCymruScout.IP.whois.admin_contact_person | String | The person associated with the admin contact. | 
| TeamCymruScout.IP.whois.admin_contact_email | String | The email associated with the admin contact. | 
| TeamCymruScout.IP.whois.admin_contact_phone | String | The phone number associated with the admin contact. | 
| TeamCymruScout.IP.whois.admin_contact_country | String | The country associated with the admin contact. | 
| TeamCymruScout.IP.whois.admin_contact_city | String | The city associated with the admin contact. | 
| TeamCymruScout.IP.whois.admin_contact_address | String | The address associated with the admin contact. | 
| TeamCymruScout.IP.whois.tech_contact_id | String | The ID associated with the tech contact. | 
| TeamCymruScout.IP.whois.tech_contact_role | String | The role associated with the tech contact. | 
| TeamCymruScout.IP.whois.tech_contact_person | String | The person associated with the tech contact. | 
| TeamCymruScout.IP.whois.tech_contact_email | String | The email associated with the tech contact. | 
| TeamCymruScout.IP.whois.tech_contact_phone | String | The phone number associated with the tech contact. | 
| TeamCymruScout.IP.whois.tech_contact_country | String | The country associated with the tech contact. | 
| TeamCymruScout.IP.whois.tech_contact_city | String | The city associated with the tech contact. | 
| TeamCymruScout.IP.whois.tech_contact_address | String | The address associated with the tech contact. | 
| TeamCymruScout.IP.whois.org_id | String | The ID associated with the organization. | 
| TeamCymruScout.IP.whois.org_name | String | The name associated with the organization. | 
| TeamCymruScout.IP.whois.org_email | String | The email associated with the organization. | 
| TeamCymruScout.IP.whois.org_phone | String | The phone number associated with the organization. | 
| TeamCymruScout.IP.whois.org_country | String | The country associated with the organization. | 
| TeamCymruScout.IP.whois.org_city | String | The city associated with the organization. | 
| TeamCymruScout.IP.whois.org_address | String | The address associated with the organization. | 
| TeamCymruScout.IP.whois.mnt_by_email | String | The email associated with the maintainer. | 
| TeamCymruScout.IP.whois.mnt_lower_email | String | The email associated with the lower maintenance router. | 
| TeamCymruScout.IP.whois.mnt_router_email | String | The email associated with the maintenance router. | 
| TeamCymruScout.IP.communications.event_count | Number | The count of events associated with the communication. | 
| TeamCymruScout.IP.communications.peers.proto | Number | The protocol associated with the peer. | 
| TeamCymruScout.IP.communications.peers.proto_text | String | The text associated with the protocol of the peer. | 
| TeamCymruScout.IP.communications.peers.local.ip | String | The IP address associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.min_port | Number | The minimum port associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.max_port | Number | The maximum port associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.country_codes | String | The country codes associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.as_info.asn | Number | The autonomous system number associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.as_info.as_name | String | The name associated with the autonomous system number of the local peer. | 
| TeamCymruScout.IP.communications.peers.local.tags.id | Number | The ID of the tags associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.tags.name | String | The name of the tags associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.tags.children.id | Number | The ID of the child tags associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.tags.children.name | String | The name of the child tags associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.tags.children.children | Unknown | The children of the child tags associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.unique_ports | Number | The unique ports associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.top_services.service_name | String | The name of the top service associated with the local peer. | 
| TeamCymruScout.IP.communications.peers.local.top_services.port | Number | The port associated with the top service of the local peer. | 
| TeamCymruScout.IP.communications.peers.local.top_services.proto_number | Number | The protocol number associated with the top service of the local peer. | 
| TeamCymruScout.IP.communications.peers.local.top_services.description | String | The description associated with the top service of the local peer. | 
| TeamCymruScout.IP.communications.peers.peer.ip | String | The IP address associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.min_port | Number | The minimum port associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.max_port | Number | The maximum port associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.country_codes | String | The country codes associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.as_info.asn | Number | The autonomous system number associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.as_info.as_name | String | The name associated with the autonomous system number of the peer. | 
| TeamCymruScout.IP.communications.peers.peer.tags | Unknown | The tags associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.unique_ports | Number | The unique ports associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.top_services.service_name | String | The name of the top service associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.top_services.port | Number | The port associated with the top service of the peer. | 
| TeamCymruScout.IP.communications.peers.peer.top_services.proto_number | Number | The protocol number associated with the top service of the peer. | 
| TeamCymruScout.IP.communications.peers.peer.top_services.description | String | The description associated with the top service of the peer. | 
| TeamCymruScout.IP.communications.peers.event_count | Number | The number of events associated with the communication. | 
| TeamCymruScout.IP.communications.peers.first_seen | Date | The first seen date associated with the communication. | 
| TeamCymruScout.IP.communications.peers.last_seen | Date | The last seen date associated with the communication. | 
| TeamCymruScout.IP.communications.peers.peer.tags.id | Number | The ID of the tags associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.tags.name | String | The name of the tags associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.tags.children.id | Number | The ID of the child tags associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.tags.children.name | String | The name of the child tags associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.tags.children.children.id | Number | The ID of the grandchild tags associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.tags.children.children.name | String | The name of the grandchild tags associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.tags.children.children.children | Unknown | The children of the grandchild tags associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.tags.children.children | Unknown | The grandchild tags associated with the peer. | 
| TeamCymruScout.IP.communications.peers.peer.tags.children | Unknown | The child tags associated with the peer. | 
| TeamCymruScout.IP.pdns.event_count | Number | The number of events associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.ip | String | The IP address associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.domain | String | The domain associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.root | String | The root associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.tld | String | The top level domain \(TLD\) associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.type | String | The type associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.registrar | String | The registrar associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.domain_created | Date | The creation date associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.domain_expires | Date | The expiration date associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.nameservers.root | String | The root of the nameserver associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.nameservers.nameservers | String | The nameservers associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.country_codes | String | The country codes associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.as_info.asn | Number | The autonomous system number associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.as_info.as_name | String | The name associated with the autonomous system number of the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.tags | Unknown | The tags associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.distinct_ips | Number | The number of distinct IP addresses associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.active_days | Number | The number of active days associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.event_count | Number | The count of events associated with the PDNS. | 
| TeamCymruScout.IP.pdns.pdns.first_seen | Date | The first date the PDNS was seen. | 
| TeamCymruScout.IP.pdns.pdns.last_seen | Date | The last date the PDNS was seen. | 
| TeamCymruScout.IP.pdns.pdns.nameservers | Unknown | The nameservers of the PDNS. | 
| TeamCymruScout.IP.fingerprints.event_count | Number | The number of events associated with the fingerprints. | 
| TeamCymruScout.IP.fingerprints.fingerprints.ip | String | The IP address of the fingerprint. | 
| TeamCymruScout.IP.fingerprints.fingerprints.type | String | The type of the fingerprint. | 
| TeamCymruScout.IP.fingerprints.fingerprints.fingerprint | String | The fingerprint of the host. | 
| TeamCymruScout.IP.fingerprints.fingerprints.port | Number | The port of the fingerprint. | 
| TeamCymruScout.IP.fingerprints.fingerprints.first_seen | Date | The first date the fingerprint was seen. | 
| TeamCymruScout.IP.fingerprints.fingerprints.last_seen | Date | The last date the fingerprint was seen. | 
| TeamCymruScout.IP.fingerprints.fingerprints.distinct_ips | Number | The number of distinct IP addresses associated with the fingerprints. | 
| TeamCymruScout.IP.fingerprints.fingerprints.active_days | Number | The number of active days associated with the fingerprints. | 
| TeamCymruScout.IP.fingerprints.fingerprints.event_count | Number | The number of events associated with the fingerprints. | 
| TeamCymruScout.IP.open_ports.event_count | Number | The number of events associated with the open ports. | 
| TeamCymruScout.IP.open_ports.unique_ports | Number | The number of unique ports in the open ports. | 
| TeamCymruScout.IP.open_ports.open_ports.ip | String | The IP address of the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.port | Number | The port of the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.protocol | Number | The protocol of the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.protocol_text | String | The protocol text of the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.service | String | The service of the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.banner | String | The banner of the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.banner_sha1 | String | The SHA1 hash of the banner of the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.first_seen | Date | The first date the open port was seen. | 
| TeamCymruScout.IP.open_ports.open_ports.last_seen | Date | The last date the open port was seen. | 
| TeamCymruScout.IP.open_ports.open_ports.country_codes | String | The country codes of the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.as_info.asn | Number | The autonomous system number of the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.as_info.as_name | String | The name of the autonomous system number of the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.tags.id | Number | The ID of the tag associated with the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.tags.name | String | The name of the tag associated with the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.tags.children.id | Number | The ID of the child tag associated with the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.tags.children.name | String | The name of the child tag associated with the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.tags.children.children | Unknown | The child tags of the child tag associated with the open port. | 
| TeamCymruScout.IP.open_ports.open_ports.event_count | Number | The number of events associated with the open port. | 
| TeamCymruScout.IP.x509.event_count | Number | The number of events associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.ip | String | The IP address associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.issuer | String | The issuer of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.issuer_common_name | String | The common name of the issuer of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.common_name | String | The common name of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.altnames | String | The alternative names associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.serial | String | The serial number of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.subject | String | The subject of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.not_after | Date | The expiration date of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.not_before | Date | The start date of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.validity_period | String | The validity period of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.md5 | String | The MD5 hash of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.sha1 | String | The SHA1 hash of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.sha256 | String | The SHA256 hash of the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.first_seen | Date | The first date the x509 certificate was seen. | 
| TeamCymruScout.IP.x509.x509.last_seen | Date | The last date the x509 certificate was seen. | 
| TeamCymruScout.IP.x509.x509.port | Number | The port associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.self_signed | Boolean | Indicates whether the x509 certificate is self-signed. | 
| TeamCymruScout.IP.x509.x509.country_codes | String | The country codes associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.as_info.asn | Number | The autonomous system number associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.as_info.as_name | String | The autonomous system name associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.tags.id | Number | The ID of the tag associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.tags.name | String | The name of the tag associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.tags.children.id | Number | The ID of the child tag associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.tags.children.name | String | The name of the child tag associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.tags.children.children | Unknown | The children of the child tag associated with the x509 certificate. | 
| TeamCymruScout.IP.x509.x509.count | Number | The count of the x509 certificate. | 
| TeamCymruScout.IP.summary.total | Number | The total count of the summary. | 
| TeamCymruScout.IP.summary.ip | String | The IP address associated with the summary. | 
| TeamCymruScout.IP.summary.start_date | Date | The start date of the summary. | 
| TeamCymruScout.IP.summary.end_date | Date | The end date of the summary. | 
| TeamCymruScout.IP.summary.geo_ip_cc | String | The country code associated with the geographic IP. | 
| TeamCymruScout.IP.summary.tags.id | Number | The ID of the tag associated with the summary. | 
| TeamCymruScout.IP.summary.tags.name | String | The name of the tag associated with the summary. | 
| TeamCymruScout.IP.summary.tags.children.id | Number | The ID of the child tag associated with the summary. | 
| TeamCymruScout.IP.summary.tags.children.name | String | The name of the child tag associated with the summary. | 
| TeamCymruScout.IP.summary.tags.children.children | Unknown | The children of the child tag associated with the summary. | 
| TeamCymruScout.IP.summary.reverse_hostnames | Unknown | The reverse hostnames associated with the summary. | 
| TeamCymruScout.IP.summary.bgp_asn | Number | The autonomous system number associated with the BGP. | 
| TeamCymruScout.IP.summary.bgp_asname | String | The autonomous system name associated with the BGP. | 
| TeamCymruScout.IP.summary.whois.asn | Number | The autonomous system number associated with the IP address. | 
| TeamCymruScout.IP.summary.whois.as_name | String | The name associated with the autonomous system number. | 
| TeamCymruScout.IP.summary.whois.net_name | String | The name associated with the network. | 
| TeamCymruScout.IP.summary.whois.org_name | String | The name associated with the organization. | 
| TeamCymruScout.IP.summary.pdns.total | Number | The total count of the DNS queries associated with the IP address. | 
| TeamCymruScout.IP.summary.pdns.top_pdns.event_count | Number | The number of events associated with the top DNS query. | 
| TeamCymruScout.IP.summary.pdns.top_pdns.domain | String | The domain associated with the top DNS query. | 
| TeamCymruScout.IP.summary.pdns.top_pdns.first_seen | Date | The first date the top DNS query was seen. | 
| TeamCymruScout.IP.summary.pdns.top_pdns.last_seen | Date | The last date the top DNS query was seen. | 
| TeamCymruScout.IP.summary.pdns.top_pdns.css_color | String | The CSS color associated with the top DNS query. | 
| TeamCymruScout.IP.summary.open_ports.total | Number | The total number of the open ports associated with the IP address. | 
| TeamCymruScout.IP.summary.open_ports.unique_ports | Number | The number of unique ports in the open ports. | 
| TeamCymruScout.IP.summary.open_ports.top_open_ports.event_count | Number | The number of events associated with the top open port. | 
| TeamCymruScout.IP.summary.open_ports.top_open_ports.port | Number | The port associated with the top open port. | 
| TeamCymruScout.IP.summary.open_ports.top_open_ports.protocol | Number | The protocol number associated with the top open port. | 
| TeamCymruScout.IP.summary.open_ports.top_open_ports.protocol_text | String | The protocol text associated with the top open port. | 
| TeamCymruScout.IP.summary.open_ports.top_open_ports.service | String | The service associated with the top open port. | 
| TeamCymruScout.IP.summary.open_ports.top_open_ports.inferred_service_name | Unknown | The inferred service name associated with the top open port. | 
| TeamCymruScout.IP.summary.open_ports.top_open_ports.first_seen | Date | The first date the top open port was seen. | 
| TeamCymruScout.IP.summary.open_ports.top_open_ports.last_seen | Date | The last date the top open port was seen. | 
| TeamCymruScout.IP.summary.open_ports.top_open_ports.css_color | String | The CSS color associated with the top open port. | 
| TeamCymruScout.IP.summary.certs.top_certs.issuer | String | The issuer of the certificate. | 
| TeamCymruScout.IP.summary.certs.top_certs.issuer_common_name | String | The common name of the issuer of the certificate. | 
| TeamCymruScout.IP.summary.certs.top_certs.common_name | String | The common name of the certificate. | 
| TeamCymruScout.IP.summary.certs.top_certs.subject | String | The subject of the certificate. | 
| TeamCymruScout.IP.summary.certs.top_certs.port | Number | The port associated with the certificate. | 
| TeamCymruScout.IP.summary.certs.top_certs.first_seen | Date | The first date the certificate was seen. | 
| TeamCymruScout.IP.summary.certs.top_certs.last_seen | Date | The last date the certificate was seen. | 
| TeamCymruScout.IP.summary.certs.top_certs.self_signed | Boolean | Indicates whether the certificate is self-signed. | 
| TeamCymruScout.IP.summary.certs.top_certs.not_before | Date | The date before which the certificate is not valid. | 
| TeamCymruScout.IP.summary.certs.top_certs.not_after | Date | The date after which the certificate is not valid. | 
| TeamCymruScout.IP.summary.certs.top_certs.valid_days | Number | The number of valid days for the certificate. | 
| TeamCymruScout.IP.summary.certs.top_certs.md5 | String | The MD5 hash of the certificate. | 
| TeamCymruScout.IP.summary.certs.top_certs.sha1 | String | The SHA1 hash of the certificate. | 
| TeamCymruScout.IP.summary.certs.top_certs.sha256 | String | The SHA256 hash of the certificate. | 
| TeamCymruScout.IP.summary.certs.top_certs.css_color | String | The CSS color associated with the certificate. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.id | Number | The ID of the tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.name | String | The name of the tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.description | String | The description of the tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.parent_ids | Number | The parent IDs of the tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.css_color | String | The CSS color associated with the tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.parents | Unknown | The parents of the tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.first_seen | Date | The first date the tag was seen. | 
| TeamCymruScout.IP.summary.tag_timeline.data.last_seen | Date | The last date the tag was seen. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.parents.id | Number | The ID of the parent tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.parents.name | String | The name of the parent tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.parents.description | String | The description of the parent tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.parents.parent_ids | Unknown | The parent IDs of the parent tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.parents.css_color | String | The CSS color associated with the parent tag. | 
| TeamCymruScout.IP.summary.tag_timeline.data.tag.parents.parents | Unknown | The parents of the parent tag. | 
| TeamCymruScout.IP.summary.insights.overall_rating | String | The overall rating of the insights. | 
| TeamCymruScout.IP.summary.insights.total | Number | The total count of the insights. | 
| TeamCymruScout.IP.summary.insights.insights.rating | String | The rating of the insight. | 
| TeamCymruScout.IP.summary.insights.insights.message | String | The message of the insight. | 
| TeamCymruScout.IP.summary.fingerprints.top_fingerprints.type | String | The type of the fingerprint. | 
| TeamCymruScout.IP.summary.fingerprints.top_fingerprints.signature | String | The signature of the fingerprint. | 
| TeamCymruScout.IP.summary.fingerprints.top_fingerprints.port | Number | The port associated with the fingerprint. | 
| TeamCymruScout.IP.summary.fingerprints.top_fingerprints.first_seen | Date | The first date the fingerprint was seen. | 
| TeamCymruScout.IP.summary.fingerprints.top_fingerprints.last_seen | Date | The last date the fingerprint was seen. | 
| TeamCymruScout.IP.summary.fingerprints.top_fingerprints.count | Number | The count of the fingerprint. | 

#### Command example
```!ip ip=0.0.0.1```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "0.0.0.1",
        "Reliability": "A - Completely reliable",
        "Score": 2,
        "Type": "ip",
        "Vendor": "Team Cymru Scout"
    },
    "IP": {
        "ASN": 15133,
        "ASOwner": "test_name",
        "Address": "0.0.0.1",
        "Description": "[\"data-03-EU-93-184-216-0-24\"]",
        "Organization": {
            "Name": "test_name Inc."
        },
        "Port": "443, 80",
        "Region": "EU",
        "Relationships": [
            {
                "EntityA": "0.0.0.1",
                "EntityAType": "IP",
                "EntityB": "0.0.0.2",
                "EntityBType": "IP",
                "Relationship": "communicated-with"
            }
        ],
        "Tags": "cdn: (test_name)",
        "UpdatedDate": "2012-06-22"
    },
    "TeamCymruScout": {
        "IP": {
            "ip": "0.0.0.1",
            "sections": [
                "identity",
                "comms",
                "pdns",
                "open_ports",
                "x509",
                "fingerprints",
                "whois",
                "summary"
            ],
            "identity": {
                "asn": 15133,
                "as_name": "test_name",
                "net_name": "test_name-data-03",
                "org_name": "test_name Inc."
            },
            "whois": {
                "modified": "2012-06-22",
                "asn": 15133,
                "cidr": "0.0.0.1/24",
                "as_name": "test_name",
                "bgp_asn": 15133,
                "bgp_asn_name": "test_name, US",
                "net_name": "test_name-data-03",
                "net_handle": "",
                "description": "[\"data-03-EU-93-184-216-0-24\"]",
                "cc": "EU",
                "city": "",
                "address": "",
                "abuse_contact_id": "",
                "about_contact_role": "",
                "about_contact_person": "",
                "about_contact_email": "",
                "about_contact_phone": "",
                "about_contact_country": "",
                "about_contact_city": "",
                "about_contact_address": "",
                "admin_contact_id": "DS7892-RIPE",
                "admin_contact_role": "",
                "admin_contact_person": "Derrick Sawyer",
                "admin_contact_email": "",
                "admin_contact_phone": "+18123456789",
                "admin_contact_country": "",
                "admin_contact_city": "",
                "admin_contact_address": "[\"11811 N. Tatum Blvd, Suite 3031, Phoenix, AZ 85028\"]",
                "tech_contact_id": "DS7892-RIPE",
                "tech_contact_role": "",
                "tech_contact_person": "Derrick Sawyer",
                "tech_contact_email": "",
                "tech_contact_phone": "+18987654321",
                "tech_contact_country": "",
                "tech_contact_city": "",
                "tech_contact_address": "[\"11811 N. Tatum Blvd, Suite 3031, Phoenix, AZ 85028\"]",
                "org_id": "",
                "org_name": "test_name Inc.",
                "org_email": "",
                "org_phone": "",
                "org_country": "",
                "org_city": "",
                "org_address": "",
                "mnt_by_email": "",
                "mnt_lower_email": "",
                "mnt_router_email": ""
            },
            "communications": {
                "event_count": 33264,
                "peers": [
                    {
                        "proto": 6,
                        "proto_text": "TCP",
                        "local": {
                            "ip": "0.0.0.1",
                            "min_port": 80,
                            "max_port": 80,
                            "country_codes": [
                                "US"
                            ],
                            "as_info": [
                                {
                                    "asn": 15133,
                                    "as_name": "test_name, US"
                                }
                            ],
                            "tags": [
                                {
                                    "id": 176,
                                    "name": "cdn",
                                    "children": [
                                        {
                                            "id": 206,
                                            "name": "test_name"
                                        }
                                    ]
                                }
                            ],
                            "unique_ports": 1,
                            "top_services": [
                                {
                                    "service_name": "http",
                                    "port": 80,
                                    "proto_number": 6,
                                    "description": "World Wide Web HTTP"
                                }
                            ]
                        },
                        "peer": {
                            "ip": "0.0.0.2",
                            "min_port": 52049,
                            "max_port": 64552,
                            "country_codes": [
                                "ZA"
                            ],
                            "as_info": [
                                {
                                    "asn": 327983,
                                    "as_name": "Interworks-Wireless-Solutions, ZA"
                                }
                            ],
                            "unique_ports": 3669,
                            "top_services": [
                                {
                                    "service_name": "",
                                    "port": 64552,
                                    "proto_number": 6,
                                    "description": ""
                                }
                            ]
                        },
                        "event_count": 6040,
                        "first_seen": "2024-06-04",
                        "last_seen": "2024-06-04"
                    }
                ]
            },
            "pdns": {
                "event_count": 1338,
                "pdns": [
                    {
                        "ip": "0.0.0.1",
                        "domain": "test1.aaa",
                        "root": "test1.aaa",
                        "tld": "aaa",
                        "type": "A",
                        "registrar": "PDR Ltd. d/b/a test1.com",
                        "domain_created": "2023-03-03",
                        "domain_expires": "2025-03-03",
                        "nameservers": [
                            {
                                "root": "test1.com.br",
                                "nameservers": [
                                    "ns1036.test1.com.br",
                                    "ns1037.test1.com.br"
                                ]
                            }
                        ],
                        "country_codes": [
                            "US"
                        ],
                        "as_info": [
                            {
                                "asn": 15133,
                                "as_name": ""
                            }
                        ],
                        "distinct_ips": 1,
                        "active_days": 20,
                        "event_count": 78,
                        "first_seen": "2024-05-27",
                        "last_seen": "2024-06-25"
                    }
                ]
            },
            "fingerprints": {
                "event_count": 5,
                "fingerprints": [
                    {
                        "ip": "0.0.0.1",
                        "type": "jarm",
                        "fingerprint": "testsignature",
                        "port": 443,
                        "first_seen": "2024-05-30",
                        "last_seen": "2024-06-21",
                        "distinct_ips": 830,
                        "active_days": 5,
                        "event_count": 5
                    }
                ]
            },
            "open_ports": {
                "event_count": 2,
                "unique_ports": 2,
                "open_ports": [
                    {
                        "ip": "0.0.0.1",
                        "port": 443,
                        "protocol": 6,
                        "protocol_text": "TCP",
                        "service": "https",
                        "banner": "TLS/1.1 cipher:0xc013, www.example.org, www.example.org, example.net, example.edu, example.com, example.org, www.example.com, www.example.edu, www.example.net",
                        "banner_sha1": "test_sha1",
                        "first_seen": "2024-05-30",
                        "last_seen": "2024-06-21",
                        "country_codes": [
                            "US"
                        ],
                        "as_info": [
                            {
                                "asn": 15133,
                                "as_name": "test_name, US"
                            }
                        ],
                        "tags": [
                            {
                                "id": 176,
                                "name": "cdn",
                                "children": [
                                    {
                                        "id": 206,
                                        "name": "test_name"
                                    }
                                ]
                            }
                        ],
                        "event_count": 5
                    }
                ]
            },
            "x509": {
                "event_count": 5,
                "x509": [
                    {
                        "ip": "0.0.0.1",
                        "issuer": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
                        "issuer_common_name": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                        "common_name": "www.example.org",
                        "altnames": [
                            "example.com",
                            "example.edu",
                            "example.net",
                            "example.org",
                            "www.example.com",
                            "www.example.edu",
                            "www.example.net",
                            "www.example.org"
                        ],
                        "serial": "testserial",
                        "subject": "CN=www.example.org, O=Internet Corporation for Assigned Names and Numbers.",
                        "not_after": "2025-03-01",
                        "not_before": "2024-01-30",
                        "validity_period": "397 Days",
                        "md5": "testmd5",
                        "sha1": "testsha1",
                        "sha256": "testsha256",
                        "first_seen": "2024-05-30",
                        "last_seen": "2024-06-21",
                        "port": 443,
                        "self_signed": false,
                        "country_codes": [
                            "US"
                        ],
                        "as_info": [
                            {
                                "asn": 15133,
                                "as_name": "test_name, US"
                            }
                        ],
                        "tags": [
                            {
                                "id": 176,
                                "name": "cdn",
                                "children": [
                                    {
                                        "id": 206,
                                        "name": "test_name"
                                    }
                                ]
                            }
                        ],
                        "count": 5
                    }
                ]
            },
            "summary": {
                "total": 1,
                "ip": "0.0.0.1",
                "start_date": "2024-05-27",
                "end_date": "2024-06-25",
                "geo_ip_cc": "US",
                "tags": [
                    {
                        "id": 176,
                        "name": "cdn",
                        "children": [
                            {
                                "id": 206,
                                "name": "test_name"
                            }
                        ]
                    }
                ],
                "bgp_asn": 15133,
                "bgp_asname": "test_name, US",
                "whois": {
                    "asn": 15133,
                    "as_name": "test_name",
                    "net_name": "test_name-data-03",
                    "org_name": "test_name Inc."
                },
                "pdns": {
                    "total": 1338,
                    "top_pdns": [
                        {
                            "event_count": 78,
                            "domain": "test1.aaa",
                            "first_seen": "2024-05-27",
                            "last_seen": "2024-06-25",
                            "css_color": "#a6abb7"
                        }
                    ]
                },
                "open_ports": {
                    "total": 2,
                    "unique_ports": 2,
                    "top_open_ports": [
                        {
                            "event_count": 53,
                            "port": 80,
                            "protocol": 6,
                            "protocol_text": "TCP",
                            "service": "http",
                            "first_seen": "2024-05-27",
                            "last_seen": "2024-06-25",
                            "css_color": "#a6abb7"
                        }
                    ]
                },
                "certs": {
                    "top_certs": [
                        {
                            "issuer": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
                            "issuer_common_name": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                            "common_name": "www.example.org",
                            "subject": "CN=www.example.org, O=Internet Corporation for Assigned Names and Numbers.",
                            "port": 443,
                            "first_seen": "2024-05-30",
                            "last_seen": "2024-06-21",
                            "self_signed": false,
                            "not_before": "2024-01-30",
                            "not_after": "2025-03-01",
                            "valid_days": 397,
                            "md5": "testmd5",
                            "sha1": "testsha1",
                            "sha256": "testsha256",
                            "css_color": "#b382d9"
                        }
                    ]
                },
                "tag_timeline": {
                    "data": [
                        {
                            "tag": {
                                "id": 176,
                                "name": "cdn",
                                "description": "The CDN tag characterizes IP addresses associated with Content Delivery Networks (CDNs).",
                                "css_color": "#8A532C"
                            },
                            "first_seen": "2024-05-27",
                            "last_seen": "2024-06-25"
                        }
                    ]
                },
                "insights": {
                    "overall_rating": "suspicious",
                    "total": 8,
                    "insights": [
                        {
                            "rating": "no_rating",
                            "message": "x509 subject \"CN=www.example.org, O=Internet Corporation for Assigned Names and Numbers."
                        }
                    ]
                },
                "fingerprints": {
                    "top_fingerprints": [
                        {
                            "type": "jarm",
                            "signature": "testsignature",
                            "port": 443,
                            "first_seen": "2024-05-30",
                            "last_seen": "2024-06-21",
                            "count": 5
                        }
                    ]
                }
            }
        },
        "QueryUsage": {
            "command_name": "ip",
            "foundation_api_usage": {
                "query_limit": 0,
                "remaining_queries": 0,
                "used_queries": 15
            },
            "query_limit": 50000,
            "remaining_queries": 49739,
            "request_id": "test_id",
            "size": 1000,
            "start_date": "2024-05-27",
            "end_date": "2024-06-25",
            "used_queries": 261
        }
    }
}
```

#### Human Readable Output

>### Summary Information For The Given Suspicious IP: [0.0.0.1](https://scout.cymru.com/scout/details?query=0.0.0.1)
>|Country Code|Whois|Tags|Insights|
>|---|---|---|---|
>| US | ***asn***: 15133<br>***as_name***: test_name<br>***net_name***: test_name-data-03<br>***org_name***: test_name Inc. | **-**	***id***: 176<br>	***name***: cdn<br>	**children**:<br>		**-**	***id***: 206<br>			***name***: test_name | **-**	***rating***: no_rating<br>	***message***: x509 subject "CN=www.example.org, O=Internet Corporation for Assigned Names and Numbers. |
>
>### Top PDNS
>|Domain|Event Count|First Seen|Last Seen|
>|---|---|---|---|
>| test1.aaa | 78 | 2024-05-27 | 2024-06-25 |
>
>### Top Peers
>|Proto|Client IP|Client Country Code(s)|Client Services|Server IP|Server Country Code(s)|Server Tag(s)|Server Services|Event Count|First Seen|Last Seen|Client AS Name|Server AS Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| TCP | 0.0.0.2 | ZA | **-**	***port***: 64552<br>	***proto_number***: 6 | 0.0.0.1 | US | cdn: (test_name) | **-**	***service_name***: http<br>	***port***: 80<br>	***proto_number***: 6<br>	***description***: World Wide Web HTTP | 6040 | 2024-06-04 | 2024-06-04 | Interworks-Wireless-Solutions, ZA | test_name, US |
>
>### Top Open Ports
>|Event Count|Port|Protocol|Protocol Text|Service|First Seen|Last Seen|
>|---|---|---|---|---|---|---|
>| 53 | 80 | 6 | TCP | http | 2024-05-27 | 2024-06-25 |
>
>### Top Fingerprints
>|Count|First Seen|Last Seen|Port|Signature|Type|
>|---|---|---|---|---|---|
>| 5 | 2024-05-30 | 2024-06-21 | 443 | testsignature | jarm |
>
>### Top Certificates
>|Common Name|First Seen|Issuer|Issuer Common Name|Last Seen|Md5|Not After|Not Before|Port|Self Signed|Sha1|Sha256|Subject|Valid Days|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| www.example.org | 2024-05-30 | CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US | DigiCert Global G2 TLS RSA SHA256 2020 CA1 | 2024-06-21 | testmd5 | 2025-03-01 | 2024-01-30 | 443 | false | testsha1 | testsha256 | CN=www.example.org, O=Internet Corporation for Assigned Names and Numbers. | 397 |

### scout-indicator-search

***
Return the summary information available for the given domain or IP address using Scout query language.

#### Base Command

`scout-indicator-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A simple or advanced Scout query which may contain the domain or IP address.<br/><br/>For example: comms.ip="0.0.0.1/24". | Required | 
| start_date | The start date to filter indicators.<br/><br/>Supported formats: 2 days, 2 weeks, 2 months, yyyy-mm-dd.<br/><br/>For example: 01 June 2024, 2024-06-17. Default is 30 days. | Optional | 
| end_date | The end date to filter indicators.<br/><br/>Supported formats: 2 days, 2 weeks, 2 months, yyyy-mm-dd.<br/><br/>For example: 01 June 2024, 2024-06-17. Default is now. | Optional | 
| days | Relative offset in days from current time. It cannot exceed the maximum range of 30 days.<br/><br/>Note: This will take priority over start_date and end_date if all three are passed. | Optional | 
| size | The maximum number of indicators to fetch.<br/><br/>Note: The maximum allowed size is 5000. Default is 20. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TeamCymruScout.IP.ip | String | The IP address. | 
| TeamCymruScout.IP.country_codes | String | The country code\(s\). | 
| TeamCymruScout.IP.as_info.asn | Number | The autonomous system number. | 
| TeamCymruScout.IP.as_info.as_name | String | The autonomous system name. | 
| TeamCymruScout.IP.tags.id | Number | The ID of the tag. | 
| TeamCymruScout.IP.tags.name | String | The name of the tag. | 
| TeamCymruScout.IP.tags.children.id | Number | The ID of the child tag. | 
| TeamCymruScout.IP.tags.children.name | String | The name of the child tag. | 
| TeamCymruScout.IP.tags.children.children | Unknown | The children of the child tag. | 
| TeamCymruScout.IP.event_count | Number | The number of events related to the IP address. | 
| TeamCymruScout.IP.summary.last_seen | Date | The last time the IP was seen. | 
| TeamCymruScout.IP.summary.whois.asn | Number | The autonomous system number associated with the IP. | 
| TeamCymruScout.IP.summary.whois.as_name | String | The name of the autonomous system associated with the IP. | 
| TeamCymruScout.IP.summary.whois.net_name | String | The network name associated with the IP. | 
| TeamCymruScout.IP.summary.whois.org_name | String | The organization name associated with the IP. | 
| TeamCymruScout.IP.summary.open_ports.ip | String | The IP address associated with the open port. | 
| TeamCymruScout.IP.summary.open_ports.port | Number | The port number associated with the open port. | 
| TeamCymruScout.IP.summary.open_ports.protocol | Number | The protocol number associated with the open port. | 
| TeamCymruScout.IP.summary.open_ports.protocol_text | String | The protocol name associated with the open port. | 
| TeamCymruScout.IP.summary.open_ports.service | String | The service name associated with the open port. | 
| TeamCymruScout.IP.summary.open_ports.event_count | Number | The number of events related to the open port. | 
| TeamCymruScout.IP.summary.pdns.ip | String | The IP address associated with the domain. | 
| TeamCymruScout.IP.summary.pdns.domain | String | The domain associated with the IP. | 
| TeamCymruScout.IP.summary.pdns.event_count | Number | The number of events related to the domain. | 
| TeamCymruScout.IP.summary.top_peers.ip | String | The IP address of the top peer. | 
| TeamCymruScout.IP.summary.top_peers.event_count | Number | The number of events related to the top peer. | 
| TeamCymruScout.IP.summary.comms_total | Number | The total number of communications related to the IP address. | 
| TeamCymruScout.IP.summary.service_counts.proto | Number | The protocol number associated with the service count. | 
| TeamCymruScout.IP.summary.service_counts.proto_text | String | The protocol name associated with the service count. | 
| TeamCymruScout.IP.summary.service_counts.port | Number | The port number associated with the service count. | 
| TeamCymruScout.IP.summary.service_counts.event_count | Number | The number of events related to the service count. | 
| TeamCymruScout.IP.summary.service_counts.service.service_name | String | The service name associated with the service count. | 
| TeamCymruScout.IP.summary.service_counts.service.port | Number | The port number associated with the service count. | 
| TeamCymruScout.IP.summary.service_counts.service.proto_number | Number | The protocol number associated with the service count. | 
| TeamCymruScout.IP.summary.service_counts.service.description | String | The description of the service associated with the service count. | 
| TeamCymruScout.IP.summary.fingerprints.ip | String | The IP address associated with the fingerprint. | 
| TeamCymruScout.IP.summary.fingerprints.type | String | The type of the fingerprint. | 
| TeamCymruScout.IP.summary.fingerprints.signature | String | The signature of the fingerprint. | 
| TeamCymruScout.IP.summary.fingerprints.event_count | Number | The number of events related to the fingerprint. | 
| TeamCymruScout.IP.summary.certs.ip | String | The IP address associated with the certificate. | 
| TeamCymruScout.IP.summary.certs.issuer | String | The issuer of the certificate. | 
| TeamCymruScout.IP.summary.certs.issuer_common_name | String | The common name of the issuer of the certificate. | 
| TeamCymruScout.IP.summary.certs.common_name | String | The common name of the certificate. | 
| TeamCymruScout.IP.summary.certs.port | Number | The port number associated with the certificate. | 
| TeamCymruScout.IP.summary.certs.event_count | Number | The number of events related to the certificate. | 
| TeamCymruScout.QueryUsage.command_name | String | The name of the Cortex XSOAR command that triggered the Foundation API. | 
| TeamCymruScout.QueryUsage.request_id | String | The unique request ID of the Foundation API response. | 
| TeamCymruScout.QueryUsage.total | Number | The total number of records available for provided filters. | 
| TeamCymruScout.QueryUsage.query | String | The query for which the search API was triggered. | 
| TeamCymruScout.QueryUsage.size | Number | The number of records requested using parameters. | 
| TeamCymruScout.QueryUsage.start_date | String | The start date from which the indicators are returned. | 
| TeamCymruScout.QueryUsage.end_date | String | The end date from which the indicators are returned. | 
| TeamCymruScout.QueryUsage.used_queries | Number | The number of queries used. | 
| TeamCymruScout.QueryUsage.remaining_queries | Number | The number of remaining queries. | 
| TeamCymruScout.QueryUsage.query_limit | Number | The total number of queries allowed. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.used_queries | Number | The number of queries used for the Foundation API. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.remaining_queries | Number | The number of remaining queries for the Foundation API. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.query_limit | Number | The total number of queries allowed for the Foundation API. | 
| IP.Address | String | IP address. | 
| IP.Relationships.EntityA | String | The source of the relationship. | 
| IP.Relationships.EntityB | String | The destination of the relationship. | 
| IP.Relationships.Relationship | String | The name of the relationship. | 
| IP.Relationships.EntityAType | String | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | String | The type of the destination of the relationship. | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Hostname | String | The hostname that is mapped to this IP address. | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Geo.Description | String | Additional information about the location. | 
| IP.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| IP.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Tags | Unknown | \(List\) Tags of the IP address. | 
| IP.FeedRelatedIndicators.value | String | Indicators that are associated with the IP address. | 
| IP.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the IP address. | 
| IP.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the IP address. | 
| IP.MalwareFamily | String | The malware family associated with the IP address. | 
| IP.Organization.Name | String | The organization of the IP address. | 
| IP.Organization.Type | String | The organization type of the IP address. | 
| IP.ASOwner | String | The autonomous system owner of the IP address. | 
| IP.Region | String | The region in which the IP address is located. | 
| IP.Port | String | Ports that are associated with the IP address. | 
| IP.Internal | Boolean | Whether the IP address is internal or external. | 
| IP.UpdatedDate | Date | The date that the IP address was last updated. | 
| IP.Registrar.Abuse.Name | String | The name of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Address | String | The address of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Country | String | The country of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Network | String | The network of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Phone | String | The phone number of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Email | String | The email address of the contact for reporting abuse. | 
| IP.Campaign | String | The campaign associated with the IP address. | 
| IP.TrafficLightProtocol | String | The Traffic Light Protocol \(TLP\) color that is suitable for the IP address. | 
| IP.CommunityNotes.note | String | Notes on the IP address that were given by the community. | 
| IP.CommunityNotes.timestamp | Date | The time in which the note was published. | 
| IP.Publications.source | String | The source in which the article was published. | 
| IP.Publications.title | String | The name of the article. | 
| IP.Publications.link | String | A link to the original article. | 
| IP.Publications.timestamp | Date | The time in which the article was published. | 
| IP.ThreatTypes.threatcategory | String | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. | 
| IP.ThreatTypes.threatcategoryconfidence | String | The confidence level provided by the vendor for the threat type category For example a confidence of 90 for threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The reputation score \(0: Unknown, 1: Good, 2: Suspicious, 3: Bad\). | 

#### Command example
```!scout-indicator-search query="0.0.0.1" size=1 start_date="30 days" end_date="now"```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "0.0.0.1",
        "Type": "ip",
        "Vendor": "Team Cymru Scout",
        "Score": 0,
        "Reliability": "B - Usually reliable"
    },
    "IP": {
        "Address": "0.0.0.1",
        "ASN": 15169,
        "ASOwner": "DUMMY",
        "Region": "US",
        "Port": "53,443",
        "UpdatedDate": "2024-06-27",
        "Hostname": "dns.dummy",
        "Geo": {
            "Country": "US"
        },
        "Organization": {
            "Name": "Dummy LLC"
        },
        "Tags": "cdn: (cloudflare)",
        "Relationships": [
            {
                "Relationship": "communicated-with",
                "EntityA": "0.0.0.1",
                "EntityAType": "IP",
                "EntityB": "0.0.0.2",
                "EntityBType": "IP"
            },
            {
                "Relationship": "communicated-with",
                "EntityA": "0.0.0.1",
                "EntityAType": "IP",
                "EntityB": "0.0.0.3",
                "EntityBType": "IP"
            },
            {
                "Relationship": "resolves-to",
                "EntityA": "0.0.0.1",
                "EntityAType": "IP",
                "EntityB": "dns.dummy",
                "EntityBType": "Domain"
            },
            {
                "Relationship": "resolves-to",
                "EntityA": "0.0.0.1",
                "EntityAType": "IP",
                "EntityB": "dns.dummy.com",
                "EntityBType": "Domain"
            }
        ]
    },
    "TeamCymruScout": {
        "IP": {
            "ip": "0.0.0.1",
            "country_codes": [
                "US"
            ],
            "as_info": [
                {
                    "asn": 15169,
                    "as_name": "DUMMY, US"
                }
            ],
            "tags": [
                {
                    "id": 176,
                    "name": "cdn",
                    "children": [
                        {
                            "id": 210,
                            "name": "cloudflare"
                        }
                    ]
                }
            ],
            "event_count": 164273621518,
            "summary": {
                "last_seen": "2024-06-27",
                "whois": {
                    "asn": 15169,
                    "as_name": "DUMMY",
                    "net_name": "DUMMY",
                    "org_name": "Dummy LLC"
                },
                "open_ports": [
                    {
                        "ip": "0.0.0.1",
                        "port": 53,
                        "protocol": 17,
                        "protocol_text": "UDP",
                        "service": "domain",
                        "event_count": 296728
                    },
                    {
                        "ip": "0.0.0.1",
                        "port": 443,
                        "protocol": 6,
                        "protocol_text": "TCP",
                        "service": "https",
                        "event_count": 257
                    }
                ],
                "pdns": [
                    {
                        "ip": "0.0.0.1",
                        "domain": "dns.dummy",
                        "event_count": 53408038
                    },
                    {
                        "ip": "0.0.0.1",
                        "domain": "dns.dummy.com",
                        "event_count": 2791811
                    }
                ],
                "top_peers": [
                    {
                        "ip": "0.0.0.2",
                        "event_count": 2784287448
                    },
                    {
                        "ip": "0.0.0.3",
                        "event_count": 1469283767
                    }
                ],
                "comms_total": 166356036813,
                "service_counts": [
                    {
                        "proto": 17,
                        "proto_text": "",
                        "port": 53,
                        "event_count": 141248029324,
                        "service": {
                            "service_name": "domain",
                            "port": 53,
                            "proto_number": 17,
                            "description": "Domain Name Server"
                        }
                    },
                    {
                        "proto": 17,
                        "proto_text": "",
                        "port": 443,
                        "event_count": 7214447854,
                        "service": {
                            "service_name": "https",
                            "port": 443,
                            "proto_number": 17,
                            "description": "http protocol over TLS/SSL"
                        }
                    },
                    {
                        "proto": 6,
                        "proto_text": "",
                        "port": 443,
                        "event_count": 4130470538,
                        "service": {
                            "service_name": "https",
                            "port": 443,
                            "proto_number": 6,
                            "description": "http protocol over TLS/SSL"
                        }
                    }
                ],
                "fingerprints": [
                    {
                        "ip": "0.0.0.1",
                        "type": "ja3s",
                        "signature": "00000000000000000000000000000001",
                        "event_count": 144337
                    },
                    {
                        "ip": "0.0.0.1",
                        "type": "ja3",
                        "signature": "00000000000000000000000000000001",
                        "event_count": 40708
                    }
                ],
                "certs": [
                    {
                        "ip": "0.0.0.1",
                        "issuer": "CN=WR2, O=Dummy Trust Services, C=US",
                        "issuer_common_name": "WR2",
                        "common_name": "dns.dummy",
                        "port": 853,
                        "event_count": 418
                    },
                    {
                        "ip": "0.0.0.1",
                        "issuer": "CN=WR2, O=Dummy Trust Services, C=US",
                        "issuer_common_name": "WR2",
                        "common_name": "dns.dummy",
                        "port": 443,
                        "event_count": 372
                    }
                ]
            }
        },
        "QueryUsage": {
            "command_name": "scout-indicator-search",
            "request_id": "00000000-0000-0000-0000-000000000001",
            "total": 1,
            "query": "0.0.0.1",
            "size": 1,
            "start_date": "2024-05-28",
            "end_date": "2024-06-26",
            "used_queries": 261,
            "remaining_queries": 49739,
            "query_limit": 50000,
            "foundation_api_usage": {
                "used_queries": 15,
                "remaining_queries": 0,
                "query_limit": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Summary Information for the given indicator: [0.0.0.1](https://scout.cymru.com/scout/details?query=0.0.0.1)
>|Country Code(S)|Whois|Event Count|Tags|Last Seen|
>|---|---|---|---|---|
>| US | ***asn***: 15169<br>***as_name***: DUMMY<br>***net_name***: DUMMY<br>***org_name***: Dummy LLC | 164273621518 | **-**	***id***: 176<br>	***name***: cdn<br>	**children**:<br>		**-**	***id***: 210<br>			***name***: cloudflare | 2024-06-27 |
>
>### PDNS Information
>|Domain|Event Count|IP|
>|---|---|---|
>| dns.dummy | 53408038 | 0.0.0.1 |
>| dns.dummy.com | 2791811 | 0.0.0.1 |
>
>### Open Ports Information
>|Event Count|IP|Port|Protocol|Protocol Text|Service|
>|---|---|---|---|---|---|
>| 296728 | 0.0.0.1 | 53 | 17 | UDP | domain |
>| 257 | 0.0.0.1 | 443 | 6 | TCP | https |
>
>### Top Peers Information
>|Source IP|Event Count|IP|
>|---|---|---|
>| 0.0.0.1 | 2784287448 | 0.0.0.2 |
>| 0.0.0.1 | 1469283767 | 0.0.0.3 |
>
>### Service Counts Information
>|Source IP|Event Count|Port|Proto|Service|
>|---|---|---|---|---|
>| 0.0.0.1 | 141248029324 | 53 | 17 | service_name: domain<br>port: 53<br>proto_number: 17<br>description: Domain Name Server |
>| 0.0.0.1 | 7214447854 | 443 | 17 | service_name: https<br>port: 443<br>proto_number: 17<br>description: http protocol over TLS/SSL |
>| 0.0.0.1 | 4130470538 | 443 | 6 | service_name: https<br>port: 443<br>proto_number: 6<br>description: http protocol over TLS/SSL |
>
>### Fingerprints Information
>|Event Count|IP|Signature|Type|
>|---|---|---|---|
>| 144337 | 0.0.0.1 | 00000000000000000000000000000001 | ja3s |
>| 40708 | 0.0.0.1 | 00000000000000000000000000000001 | ja3 |
>
>### Certs Information
>|Common Name|Event Count|IP|Issuer|Issuer Common Name|Port|
>|---|---|---|---|---|---|
>| dns.dummy | 418 | 0.0.0.1 | CN=WR2, O=Dummy Trust Services, C=US | WR2 | 853 |
>| dns.dummy | 372 | 0.0.0.1 | CN=WR2, O=Dummy Trust Services, C=US | WR2 | 443 |
>
>### API Usage
>|Used Queries|Remaining Queries|Query Limit|Foundation Used Queries|Foundation Remaining Queries|Foundation Query Limit|
>|---|---|---|---|---|---|
>| 261 | 49739 | 50000 | 15 | 0 | 0 |

### scout-ip-list

***
Returns the summary information available for the given list of IP addresses.

#### Base Command

`scout-ip-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_addresses | A comma-separated list of IP addresses to retrieve available IP details. Note: Maximum of 10 IP addresses are allowed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TeamCymruScout.IP.ip | String | The IP address. | 
| TeamCymruScout.IP.country_code | String | The country code. | 
| TeamCymruScout.IP.as_info.asn | Number | The autonomous system number. | 
| TeamCymruScout.IP.as_info.as_name | String | The autonomous system name. | 
| TeamCymruScout.IP.insights.overall_rating | String | The overall rating for the IP address. | 
| TeamCymruScout.IP.insights.insights.rating | String | The individual insight rating for the IP address. | 
| TeamCymruScout.IP.insights.insights.message | String | The individual insight message for the IP address. | 
| TeamCymruScout.IP.tags.id | Number | The ID of the tag. | 
| TeamCymruScout.IP.tags.name | String | The name of the tag. | 
| TeamCymruScout.IP.tags.children.id | Number | The ID of the child tag. | 
| TeamCymruScout.IP.tags.children.name | String | The name of the child tag. | 
| TeamCymruScout.IP.tags.children.children | Unknown | The children of the child tag. | 
| TeamCymruScout.QueryUsage.command_name | String | The name of the Cortex XSOAR command that triggered the Foundation API. | 
| TeamCymruScout.QueryUsage.request_id | String | The unique request ID of the Foundation API response. | 
| TeamCymruScout.QueryUsage.ips | Unknown | The list of IP addresses for which the Foundation API was triggered. | 
| TeamCymruScout.QueryUsage.used_queries | Number | The number of queries used. | 
| TeamCymruScout.QueryUsage.remaining_queries | Number | The number of remaining queries. | 
| TeamCymruScout.QueryUsage.query_limit | Number | The total number of queries allowed. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.used_queries | Number | The number of queries used for the Foundation API. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.remaining_queries | Number | The number of remaining queries for the Foundation API. | 
| TeamCymruScout.QueryUsage.foundation_api_usage.query_limit | Number | The total number of queries allowed for the Foundation API. | 
| IP.Address | String | IP address. | 
| IP.Relationships.EntityA | String | The source of the relationship. | 
| IP.Relationships.EntityB | String | The destination of the relationship. | 
| IP.Relationships.Relationship | String | The name of the relationship. | 
| IP.Relationships.EntityAType | String | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | String | The type of the destination of the relationship. | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Hostname | String | The hostname that is mapped to this IP address. | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Geo.Description | String | Additional information about the location. | 
| IP.DetectionEngines | Number | The total number of engines that checked the indicator. | 
| IP.PositiveDetections | Number | The number of engines that positively detected the indicator as malicious. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Tags | Unknown | \(List\) Tags of the IP address. | 
| IP.FeedRelatedIndicators.value | String | Indicators that are associated with the IP address. | 
| IP.FeedRelatedIndicators.type | String | The type of the indicators that are associated with the IP address. | 
| IP.FeedRelatedIndicators.description | String | The description of the indicators that are associated with the IP address. | 
| IP.MalwareFamily | String | The malware family associated with the IP address. | 
| IP.Organization.Name | String | The organization of the IP address. | 
| IP.Organization.Type | String | The organization type of the IP address. | 
| IP.ASOwner | String | The autonomous system owner of the IP address. | 
| IP.Region | String | The region in which the IP address is located. | 
| IP.Port | String | Ports that are associated with the IP address. | 
| IP.Internal | Boolean | Whether the IP address is internal or external. | 
| IP.UpdatedDate | Date | The date that the IP address was last updated. | 
| IP.Registrar.Abuse.Name | String | The name of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Address | String | The address of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Country | String | The country of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Network | String | The network of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Phone | String | The phone number of the contact for reporting abuse. | 
| IP.Registrar.Abuse.Email | String | The email address of the contact for reporting abuse. | 
| IP.Campaign | String | The campaign associated with the IP address. | 
| IP.TrafficLightProtocol | String | The Traffic Light Protocol \(TLP\) color that is suitable for the IP address. | 
| IP.CommunityNotes.note | String | Notes on the IP address that were given by the community. | 
| IP.CommunityNotes.timestamp | Date | The time in which the note was published. | 
| IP.Publications.source | String | The source in which the article was published. | 
| IP.Publications.title | String | The name of the article. | 
| IP.Publications.link | String | A link to the original article. | 
| IP.Publications.timestamp | Date | The time in which the article was published. | 
| IP.ThreatTypes.threatcategory | String | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. | 
| IP.ThreatTypes.threatcategoryconfidence | String | The confidence level provided by the vendor for the threat type category For example a confidence of 90 for threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The reputation score \(0: Unknown, 1: Good, 2: Suspicious, 3: Bad\). | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

#### Command example
```!scout-ip-list ip_addresses="0.0.0.1"```
#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "0.0.0.1",
            "Reliability": "B - Usually reliable",
            "Score": 2,
            "Type": "ip",
            "Vendor": "Team Cymru Scout"
        }
    ],
    "IP": [
        {
            "Address": "0.0.0.1",
            "ASN": 13335,
            "ASOwner": "NET, US",
            "Region": "US",
            "Description": "0.0.0.1 has been identified as a \"cdn\", indicating private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598, as well as net that have not been allocated to a Regional Internet Registry (RIR) by the Internet Assigned Numbers Authority.",
            "Geo": {
                "Country": "US"
            },
            "Organization": {
                "Name": "NET, US"
            },
            "Tags": "cdn: (cloudflare)"
        }
    ],
    "TeamCymruScout": {
        "IP": [
            {
                "ip": "0.0.0.1",
                "country_code": "US",
                "as_info": [
                    {
                        "asn": 13335,
                        "as_name": "NET, US"
                    }
                ],
                "insights": {
                    "overall_rating": "suspicious",
                    "insights": [
                        {
                            "rating": "suspicious",
                            "message": "0.0.0.1 has been identified as a \"cdn\", indicating private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598, as well as net that have not been allocated to a Regional Internet Registry (RIR) by the Internet Assigned Numbers Authority."
                        }
                    ]
                },
                "tags": [
                    {
                        "id": 81,
                        "name": "cdn",
                        "children": [
                            {
                                "id": 210,
                                "name": "cloudflare"
                            }
                        ]
                    }
                ]
            }
        ],
        "QueryUsage": {
            "command_name": "scout-ip-list",
            "foundation_api_usage": {
                "query_limit": 0,
                "remaining_queries": 0,
                "used_queries": 3
            },
            "ips": [
                "0.0.0.1"
            ],
            "query_limit": 50000,
            "remaining_queries": 49840,
            "request_id": "00000000-0000-0000-0000-000000000001",
            "used_queries": 160
        }
    }
}
```

#### Human Readable Output

>### Summary Information for the given Suspicious IP: [0.0.0.1](https://scout.cymru.com/scout/details?query=0.0.0.1)
>|Country Code|AS Info|Insights|Tags|
>|---|---|---|---|
>| US | **-**	***asn***: 13335<br>	***as_name***: NET, US | ***overall_rating***: suspicious<br>**insights**:<br>	**-**	***rating***: suspicious<br>		***message***: 0.0.0.1 has been identified as a "cdn", indicating private and reserved addresses defined by RFC 1918, RFC 5735, and RFC 6598, as well as net that have not been allocated to a Regional Internet Registry (RIR) by the Internet Assigned Numbers Authority. | **-**	***id***: 81<br>	***name***: cdn<br>	**children**:<br>		**-**	***id***: 210<br>			***name***: cloudflare |
>
>### API Usage
>|Used Queries|Remaining Queries|Query Limit|Foundation Used Queries|Foundation Remaining Queries|Foundation Query Limit|
>|---|---|---|---|---|---|
>| 160 | 49840 | 50000 | 3 | 0 | 0 |
