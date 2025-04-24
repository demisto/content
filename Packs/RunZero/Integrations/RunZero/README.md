RunZero is a network discovery and asset inventory
 platform that uncovers every network in use and identifies every device connected – without credentials.
 Scan your network and build your asset inventory in minutes.
This integration was integrated and tested with version 3.3.0 of RunZero

## Configure RunZero in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key | The API Key to use for connection. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### runzero-asset-search
***
Get assets.


#### Base Command

`runzero-asset-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_ids | A comma-separated list of asset IDs. | Optional | 
| search | The query by which to search. For information on the syntax, see: https://www.runzero.com/docs/runzero-manual.pdf page 288. | Optional | 
| ips | A comma-separated list of IP addresses. | Optional | 
| hostnames | A comma-separated list of hostnames. | Optional | 
| display_attributes | Whether to include the attributes section in the returned result. Possible values are: True, False. | Optional | 
| display_services | Whether to include a services section in the returned result. Possible values are: True, False. | Optional | 
| limit | Limit the number of assets returned. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RunZero.Asset.ID | UUID | Asset service ID. | 
| RunZero.Asset.Addresses | Array | Asset addresses. | 
| RunZero.Asset.Asset_Status | Boolean | Asset status. | 
| RunZero.Asset.Hostname | Array | Asset hostname. | 
| RunZero.Asset.OS | String | Operating system version. | 
| RunZero.Asset.Type | String | Asset type. | 
| RunZero.Asset.Hardware | String | Asset hardware. | 
| RunZero.Asset.Outlier | String | Asset outlier score. | 
| RunZero.Asset.MAC_Vendor | String | Asset vendor MAC address is allocated to. | 
| RunZero.Asset.MAC_Age | Integer | Asset date MAC address was allocated. | 
| RunZero.Asset.MAC | UUID | Asset MAC address. | 
| RunZero.Asset.OS_EOL | String | Asset operating system end-of-life date. | 
| RunZero.Asset.Sources | String | Asset data sources. | 
| RunZero.Asset.Comments | String | Comments attached to the asset. | 
| RunZero.Asset.Tags | Array | Tags attached to the asset. | 
| RunZero.Asset.Svcs | Integer | Number of total service count. | 
| RunZero.Asset.TCP | Integer | Asset TCP service count. | 
| RunZero.Asset.UDP | Integer | Asset UDP service count. | 
| RunZero.Asset.ICMP | Integer | Asset ICMP response. | 
| RunZero.Asset.ARP | Integer | Asset ARP response. | 
| RunZero.Asset.SW | Integer | Asset identified software. | 
| RunZero.Asset.Vulns | Integer | Asset identified vulnerability count. | 
| RunZero.Asset.RTT/ms | Integer | Asset round-trip time latency. | 
| RunZero.Asset.Hops | Integer | Asset estimated hop count from scanner. | 
| RunZero.Asset.Detected | String | Asset method of detection. | 
| RunZero.Asset.First_Seen | String | Datetime of when the asset was first seen. | 
| RunZero.Asset.Last_Seen | String | Datetime of when the asset was last seen. | 
| RunZero.Asset.Explorer | String | Name of the RunZero explorer which most recently found the asset. | 
| RunZero.Asset.Hosted_Zone | String | Asset hosted zone. | 
| RunZero.Asset.Site | String | Asset site name. | 

#### Command example
```!runzero-asset-search```
#### Context Example
```json
{
    "RunZero": {
        "Asset": {
            "addresses": [
                "192.168.1.91",
                "fe80::250:56ff:fe89:b0e1"
            ],
            "addresses_extra": [],
            "agent_external_ip": null,
            "agent_name": "RHEL85.LOCALDOMAIN",
            "alive": true,
            "comments": "integration comment",
            "created_at": 1672007446,
            "credentials": {},
            "detected_by": "arp",
            "domains": [],
            "eol_os": 0,
            "eol_os_ext": 0,
            "first_seen": 1672007309,
            "foreign_attributes": {},
            "hosted_zone_name": null,
            "hw": "VMware VM",
            "hw_product": "",
            "hw_vendor": "",
            "hw_version": "",
            "id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
            "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
            "last_seen": 1672008118,
            "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
            "lowest_rtt": 837561,
            "lowest_ttl": 0,
            "mac_vendors": [
                "VMware, Inc."
            ],
            "macs": [
                "00:50:56:89:b0:e1"
            ],
            "names": [
                "RHEL85",
                "RHEL85.LOCALDOMAIN"
            ],
            "newest_mac": "00:50:56:89:b0:e1",
            "newest_mac_age": null,
            "newest_mac_vendor": "VMware, Inc.",
            "org_name": "Org name LTD",
            "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
            "os": "Red Hat Enterprise Linux",
            "os_product": "Enterprise Linux",
            "os_vendor": "Red Hat",
            "os_version": "8.5",
            "outlier_raw": 0,
            "outlier_score": 0,
            "owners": [],
            "rtts": {
                "icmp/echo": [
                    837561,
                    5320391,
                    6077638
                ]
            },
            "scanned": true,
            "service_count": 11,
            "service_count_arp": 1,
            "service_count_icmp": 1,
            "service_count_tcp": 3,
            "service_count_udp": 4,
            "service_ports_tcp": [
                "22",
                "111",
                "9090"
            ],
            "service_ports_udp": [
                "111",
                "5353"
            ],
            "service_products": [
                "cockpit",
                "openbsd openssh"
            ],
            "service_protocols": [
                "http",
                "mdns",
                "rpcbind",
                "ssh",
                "sunrpc",
                "tls"
            ],
            "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
            "site_name": "Primary",
            "software_count": 2,
            "source_ids": [
                1
            ],
            "sources": [
                "runZero"
            ],
            "subnets": {},
            "tag_descriptions": {},
            "tags": {
                "ThisTag": "Value",
                "ThisTag-ThisTag2": "",
                "ThisTag2": "Value",
                "try": "value",
                "try3": "value3"
            },
            "type": "Server",
            "updated_at": 1674661963,
            "vulnerability_count": 0
        }
    }
}
```

#### Human Readable Output

>### Asset
>|ARP|Addresses|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|RTT/ms|SW|Site|Sources|Svcs|TCP|Tags|Type|UDP|Vulns|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 192.168.1.91,<br/>fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | bf707048-7ce9-4249-a58c-0aaa257d69f0 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0.84 | 2 | Primary | runZero | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | Server | 4 | 0 |


#### Command example
```!runzero-asset-search hostnames=RHEL85```
#### Context Example
```json
{
    "RunZero": {
        "Asset": {
            "addresses": [
                "192.168.1.91",
                "fe80::250:56ff:fe89:b0e1"
            ],
            "addresses_extra": [],
            "agent_external_ip": null,
            "agent_name": "RHEL85.LOCALDOMAIN",
            "alive": true,
            "comments": "integration comment",
            "created_at": 1672007446,
            "credentials": {},
            "detected_by": "arp",
            "domains": [],
            "eol_os": 0,
            "eol_os_ext": 0,
            "first_seen": 1672007309,
            "foreign_attributes": {},
            "hosted_zone_name": null,
            "hw": "VMware VM",
            "hw_product": "",
            "hw_vendor": "",
            "hw_version": "",
            "id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
            "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
            "last_seen": 1672008118,
            "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
            "lowest_rtt": 837561,
            "lowest_ttl": 0,
            "mac_vendors": [
                "VMware, Inc."
            ],
            "macs": [
                "00:50:56:89:b0:e1"
            ],
            "names": [
                "RHEL85",
                "RHEL85.LOCALDOMAIN"
            ],
            "newest_mac": "00:50:56:89:b0:e1",
            "newest_mac_age": null,
            "newest_mac_vendor": "VMware, Inc.",
            "org_name": "Palo Alto Networks LTD",
            "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
            "os": "Red Hat Enterprise Linux",
            "os_product": "Enterprise Linux",
            "os_vendor": "Red Hat",
            "os_version": "8.5",
            "outlier_raw": 0,
            "outlier_score": 0,
            "owners": [],
            "rtts": {
                "icmp/echo": [
                    837561,
                    5320391,
                    6077638
                ]
            },
            "scanned": true,
            "service_count": 11,
            "service_count_arp": 1,
            "service_count_icmp": 1,
            "service_count_tcp": 3,
            "service_count_udp": 4,
            "service_ports_tcp": [
                "22",
                "111",
                "9090"
            ],
            "service_ports_udp": [
                "111",
                "5353"
            ],
            "service_products": [
                "cockpit",
                "openbsd openssh"
            ],
            "service_protocols": [
                "http",
                "mdns",
                "rpcbind",
                "ssh",
                "sunrpc",
                "tls"
            ],
            "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
            "site_name": "Primary",
            "software_count": 2,
            "source_ids": [
                1
            ],
            "sources": [
                "runZero"
            ],
            "subnets": {},
            "tag_descriptions": {},
            "tags": {
                "ThisTag": "Value",
                "ThisTag-ThisTag2": "",
                "ThisTag2": "Value",
                "try": "value",
                "try3": "value3"
            },
            "type": "Server",
            "updated_at": 1674661963,
            "vulnerability_count": 0
        }
    }
}
```

#### Human Readable Output

>### Asset
>|ARP|Addresses|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|RTT/ms|SW|Site|Sources|Svcs|TCP|Tags|Type|UDP|Vulns|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 192.168.1.91,<br/>fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | bf707048-7ce9-4249-a58c-0aaa257d69f0 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0.84 | 2 | Primary | runZero | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | Server | 4 | 0 |


#### Command example
```!runzero-asset-search ips=192.168.1.91,192.168.1.1```
#### Context Example
```json
{
    "RunZero": {
        "Asset": {
            "addresses": [
                "192.168.1.91",
                "fe80::250:56ff:fe89:b0e1"
            ],
            "addresses_extra": [],
            "agent_external_ip": null,
            "agent_name": "RHEL85.LOCALDOMAIN",
            "alive": true,
            "comments": "integration comment",
            "created_at": 1672007446,
            "credentials": {},
            "detected_by": "arp",
            "domains": [],
            "eol_os": 0,
            "eol_os_ext": 0,
            "first_seen": 1672007309,
            "foreign_attributes": {},
            "hosted_zone_name": null,
            "hw": "VMware VM",
            "hw_product": "",
            "hw_vendor": "",
            "hw_version": "",
            "id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
            "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
            "last_seen": 1672008118,
            "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
            "lowest_rtt": 837561,
            "lowest_ttl": 0,
            "mac_vendors": [
                "VMware, Inc."
            ],
            "macs": [
                "00:50:56:89:b0:e1"
            ],
            "names": [
                "RHEL85",
                "RHEL85.LOCALDOMAIN"
            ],
            "newest_mac": "00:50:56:89:b0:e1",
            "newest_mac_age": null,
            "newest_mac_vendor": "VMware, Inc.",
            "org_name": "Org name LTD",
            "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
            "os": "Red Hat Enterprise Linux",
            "os_product": "Enterprise Linux",
            "os_vendor": "Red Hat",
            "os_version": "8.5",
            "outlier_raw": 0,
            "outlier_score": 0,
            "owners": [],
            "rtts": {
                "icmp/echo": [
                    837561,
                    5320391,
                    6077638
                ]
            },
            "scanned": true,
            "service_count": 11,
            "service_count_arp": 1,
            "service_count_icmp": 1,
            "service_count_tcp": 3,
            "service_count_udp": 4,
            "service_ports_tcp": [
                "22",
                "111",
                "9090"
            ],
            "service_ports_udp": [
                "111",
                "5353"
            ],
            "service_products": [
                "cockpit",
                "openbsd openssh"
            ],
            "service_protocols": [
                "http",
                "mdns",
                "rpcbind",
                "ssh",
                "sunrpc",
                "tls"
            ],
            "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
            "site_name": "Primary",
            "software_count": 2,
            "source_ids": [
                1
            ],
            "sources": [
                "runZero"
            ],
            "subnets": {},
            "tag_descriptions": {},
            "tags": {
                "ThisTag": "Value",
                "ThisTag-ThisTag2": "",
                "ThisTag2": "Value",
                "try": "value",
                "try3": "value3"
            },
            "type": "Server",
            "updated_at": 1674661963,
            "vulnerability_count": 0
        }
    }
}
```

#### Human Readable Output

>### Asset
>|ARP|Addresses|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|RTT/ms|SW|Site|Sources|Svcs|TCP|Tags|Type|UDP|Vulns|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 192.168.1.91,<br/>fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | bf707048-7ce9-4249-a58c-0aaa257d69f0 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0.84 | 2 | Primary | runZero | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | Server | 4 | 0 |


#### Command example
```!runzero-asset-search search=os:Windows ```
#### Human Readable Output

>### Asset
>**No entries.**


### runzero-asset-delete
***
Bulk delete assets.


#### Base Command

`runzero-asset-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_ids | A comma-separated list of UUIDs of the asset to delete. | Required | 


#### Context Output

There is no context output for this command.
### runzero-service-search
***
Get services.


#### Base Command

`runzero-service-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | UUID of the service to retrieve. | Optional | 
| search | The query by which to search. For information on the syntax, see: https://www.runzero.com/docs/runzero-manual.pdf page 288. | Optional | 
| service_addresses | A comma-separated list of services by addresses. | Optional | 
| display_attributes | Whether to include an attributes section in the returned result. Possible values are: True, False. | Optional | 
| limit | Limit the number of assets returned. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RunZero.Service.ID | UUID | Service ID. | 
| RunZero.Service.Address | String | Service addresses. | 
| RunZero.Service.Asset_Status | Boolean | Service asset status. | 
| RunZero.Service.Hostname | Array | Service hostname. | 
| RunZero.Service.Transport | String | Service transport. | 
| RunZero.Service.Port | Integer | Service port. | 
| RunZero.Service.Protocol | Array | Service protocol. | 
| RunZero.Service.VHost | Array | Service virtual host. | 
| RunZero.Service.Summary | Array | Service summary. | 
| RunZero.Service.Hostname | Array | Service hostname. | 
| RunZero.Service.OS | String | Service operating system version. | 
| RunZero.Service.Type | String | Service type. | 
| RunZero.Service.Hardware | String | Service hardware. | 
| RunZero.Service.Outlier | String | Service outlier score. | 
| RunZero.Service.MAC_Vendor | String | Service vendor MAC address is allocated to. | 
| RunZero.Service.MAC_Age | Integer | Service date MAC address was allocated. | 
| RunZero.Service.MAC | UUID | Service MAC address. | 
| RunZero.Service.OS_EOL | String | Service operating system end-of-life. | 
| RunZero.Service.Comments | String | Comments attached to the service. | 
| RunZero.Service.Tags | Array | Tags attached to the service. | 
| RunZero.Service.Svcs | Integer | Total service count. | 
| RunZero.Service.TCP | Integer | TCP service count. | 
| RunZero.Service.UDP | Integer | UDP service count. | 
| RunZero.Service.ICMP | Integer | ICMP response. | 
| RunZero.Service.ARP | Integer | ARP response. | 
| RunZero.Service.SW | Integer | Identified software. | 
| RunZero.Service.Vulns | Integer | Identified vulnerabilities. | 
| RunZero.Service.RTT/ms | Integer | Service round-trip time latency. | 
| RunZero.Service.Hops | Integer | Estimated hop count from scanner. | 
| RunZero.Service.Detected | String | Method of detection. | 
| RunZero.Service.First_Seen | String | Datetime of when the service was first seen. | 
| RunZero.Service.Last_Seen | String | Datetime of when the service was last seen. | 
| RunZero.Service.Explorer | String | Name of the RunZero explorer which most recently found the asset. | 
| RunZero.Service.Hosted_Zone | String | Service hosted zone. | 
| RunZero.Service.Site | String | Service site name. | 

#### Command example
```!runzero-service-search```
#### Context Example
```json
{
    "RunZero": {
        "Service": [
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "agent_external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "04d60ddf-8d28-494c-8186-8cd514e5b9cb",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Org name LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "fe80::250:56ff:fe89:b0e1",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "protocol": "rpcbind\tsunrpc",
                    "rpcbind.programs": "100000-v4-tcp-111\t100000-v3-tcp-111\t100000-v2-tcp-111\t100000-v4-udp-111\t100000-v3-udp-111\t100000-v2-udp-111",
                    "source": "rpcbind",
                    "ts": "1672008083"
                },
                "service_has_screenshot": false,
                "service_id": "04d60ddf-8d28-494c-8186-8cd514e5b9cb",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 111,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [
                    "rpcbind",
                    "sunrpc"
                ],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "udp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "agent_external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "10f9e421-d80a-47d6-9643-d3e0c423a0f7",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Org name LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "fe80::250:56ff:fe89:b0e1",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "icmp6.addrs": "fe80::250:56ff:fe89:b0e1",
                    "icmp6.code": "0",
                    "icmp6.id": "58719",
                    "icmp6.rtts": "5320391",
                    "icmp6.seq": "14753",
                    "icmp6.sum": "40758",
                    "icmp6.type": "129",
                    "icmp6.typeCode": "EchoReply",
                    "ts": "1672008077"
                },
                "service_has_screenshot": false,
                "service_id": "10f9e421-d80a-47d6-9643-d3e0c423a0f7",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 0,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "icmp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "agent_external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "4cdaab83-a513-42e1-8ff1-ba1d70c64cc3",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Org name LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "192.168.1.91",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "banner": "SSH-2.0-OpenSSH_8.0",
                    "fp.certainty": "0.85",
                    "product": "OpenBSD:OpenSSH:8.0",
                    "protocol": "ssh",
                    "source": "connect",
                    "ssh.authMethods": "password\tpublickey",
                    "ssh.authPassword": "true",
                    "ssh.authPublicKey": "true",
                    "ssh.hostKey.data": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDcG6E/EoCvbnwDNgz7GPvM7rireCOeuWdHF1cxdR+yAzlltEeTrBoFNx/AdePTpsnIvBF9g4aP0XV7JVJXIWmI3UmAG/KBcIeXBdp5amnbSo7EVpyyQi6sAc5bmdYS3OjM9AdOL7aRpWdt/kzqUtDx60O/igS2QJf5LX+oxAWk1fQcaJtW+FxWVw2H6RVI4mBJ+T9LWvMmqMui56wa/onIkFQEVecHxCF868LtdGm+cChk/BtZKkUjG/CO/uzbBdCx6FjBIsK9kp3w6v2iLlxfPL9wVO5ilO8PBZCzVOnkr3ZgaYs/v1UYPiKD7NFEteW1pdFhuROWg7H9mdkd2VNG+6j28Xb1fLhOSUJu7flGXGx3mqmPsdog4+L06ZCXqpRBPCXimByYrstOkNm/kKZSqrigj+pM9i8QXnBTrokPd7VbQ1eCgHTyJzGefqv6JjoXnwEmxXGKQxw2kj6H9SyPaNqfIaPcIk3sRq6MncuQL+zvvH8QC0iyykeRlQxHlTk=",
                    "ssh.hostKey.md5": "md5",
                    "ssh.hostKey.sha256": "SHA256",
                    "ssh.hostKey.type": "ssh-rsa",
                    "ssh.hostKeyAlgorithms": "ecdsa-sha2-nistp256\trsa-sha2-256\trsa-sha2-512\tssh-ed25519\tssh-rsa",
                    "ssh.kexAlgorithms": "curve25519-sha256\tcurve25519-sha256@libssh.org\tdiffie-hellman-group-exchange-sha1\tdiffie-hellman-group-exchange-sha256\tdiffie-hellman-group14-sha1\tdiffie-hellman-group14-sha256\tdiffie-hellman-group16-sha512\tdiffie-hellman-group18-sha512\tecdh-sha2-nistp256\tecdh-sha2-nistp384\tecdh-sha2-nistp521",
                    "ssh.kexCookie": "60a4aaf8a8ed37501fb9dd97df32d1d7",
                    "ssh.kexPadding": "5",
                    "ssh.toClientCiphers": "aes128-cbc\taes128-ctr\mail@mail.com\taes256-cbc\taes256-ctr\mail@mail.com\mail@mail.com",
                    "ssh.toClientCompression": "none\tmail@mail.com",
                    "ssh.toClientMACs": "hmac-sha1\mail@mail.com\thmac-sha2-256\mail@mail.com\thmac-sha2-512\thmac-sha2-512-etm@openssh.com\tumac-128-etm@openssh.com\mail@mail.com",
                    "ssh.toServerCiphers": "aes128-cbc\taes128-ctr\mail@mail.com\taes256-cbc\taes256-ctr\mail@mail.com\mail@mail.com",
                    "ssh.toServerCompression": "none\tmail@mail.com",
                    "ssh.toServerMACs": "hmac-sha1\mail@mail.com\thmac-sha2-256\mail@mail.com\thmac-sha2-512\thmac-sha2-512-etm@openssh.com\tumac-128-etm@openssh.com\mail@mail.com",
                    "ts": "1672008108"
                },
                "service_has_screenshot": false,
                "service_id": "4cdaab83-a513-42e1-8ff1-ba1d70c64cc3",
                "service_link": "ssh://192.168.1.91:22",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 22,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [
                    "ssh"
                ],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "SSH-2.0-OpenSSH_8.0",
                "service_transport": "tcp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "89308b21-7c53-4a06-8e65-616f2dea019e",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Palo Alto Networks LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "192.168.1.91",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "mdns.addrs": "192.168.1.91\tfe80::250:56ff:fe89:b0e1",
                    "mdns.hostname": "RHEL85",
                    "mdns.replies": "1.1.1.1.in-addr.arpa.=PTR,RHEL85.local.\tPCP pmcd on RHEL85.localdomain._pmcd._tcp.local.=SRV,RHEL85.local.:44321\tRHEL85.local.=A,192.168.1.91\tRHEL85.local.=AAAA,fe80::250:56ff:fe89:b0e1\t_pmcd._tcp.local.=PTR,PCP pmcd on RHEL85.localdomain._pmcd._tcp.local.",
                    "mdns.services": "pmcd/tcp",
                    "protocol": "mdns",
                    "ts": "1672008085"
                },
                "service_has_screenshot": false,
                "service_id": "89308b21-7c53-4a06-8e65-616f2dea019e",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 5353,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [
                    "mdns"
                ],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "udp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "9b65b530-1540-47fb-9638-1f49081b2a09",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Palo Alto Networks LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "192.168.1.91",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "protocol": "rpcbind\tsunrpc",
                    "rpcbind.addrs": "192.168.1.91",
                    "rpcbind.programs": "100000-v4-tcp-111\t100000-v3-tcp-111\t100000-v2-tcp-111\t100000-v4-udp-111\t100000-v3-udp-111\t100000-v2-udp-111",
                    "source": "rpcbind",
                    "ts": "1672008083"
                },
                "service_has_screenshot": false,
                "service_id": "9b65b530-1540-47fb-9638-1f49081b2a09",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 111,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [
                    "rpcbind",
                    "sunrpc"
                ],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "udp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "a0dafbdd-e56d-4d01-be51-99dbbaaa8322",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Palo Alto Networks LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "fe80::250:56ff:fe89:b0e1",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "arp.mac": "00:50:56:89:b0:e1",
                    "arp.macDateAdded": "2000-01-04",
                    "arp.macVendor": "VMware, Inc.",
                    "source": "arp",
                    "ts": "1672008068"
                },
                "service_has_screenshot": false,
                "service_id": "a0dafbdd-e56d-4d01-be51-99dbbaaa8322",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 0,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "arp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "b3760c57-934f-4e45-ad9b-3aef27a9825a",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Palo Alto Networks LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "192.168.1.91",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "icmp.addrs": "192.168.1.91",
                    "icmp.code": "0",
                    "icmp.id": "11495",
                    "icmp.rtts": "6077638",
                    "icmp.seq": "10791",
                    "icmp.sum": "39266",
                    "icmp.type": "0",
                    "icmp.typeCode": "EchoReply",
                    "ip.id": "60115",
                    "ip.tos": "0",
                    "ip.ttl": "64",
                    "ts": "1672008077"
                },
                "service_has_screenshot": false,
                "service_id": "b3760c57-934f-4e45-ad9b-3aef27a9825a",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 0,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "icmp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "c807c93b-3b63-4937-89f5-c3d89eb36003",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Palo Alto Networks LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "fe80::250:56ff:fe89:b0e1",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "mdns.addrs": "fe80::250:56ff:fe89:b0e1",
                    "mdns.hostname": "RHEL85",
                    "mdns.replies": "1.e.0.b.9.8.e.f.f.f.6.5.0.5.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.=PTR,RHEL85.local.\tPCP pmcd on RHEL85.localdomain._pmcd._tcp.local.=SRV,RHEL85.local.:44321\tRHEL85.local.=AAAA,fe80::250:56ff:fe89:b0e1\t_pmcd._tcp.local.=PTR,PCP pmcd on RHEL85.localdomain._pmcd._tcp.local.",
                    "mdns.services": "pmcd/tcp",
                    "protocol": "mdns",
                    "ts": "1672008085"
                },
                "service_has_screenshot": false,
                "service_id": "c807c93b-3b63-4937-89f5-c3d89eb36003",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 5353,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [
                    "mdns"
                ],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "udp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "d2972ca1-4bbc-45b5-a5fb-a4019d9c3f0b",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Palo Alto Networks LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "192.168.1.91",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "arp.mac": "00:50:56:89:b0:e1",
                    "arp.macDateAdded": "2000-01-04",
                    "arp.macVendor": "VMware, Inc.",
                    "source": "arp",
                    "ts": "1672008068"
                },
                "service_has_screenshot": false,
                "service_id": "d2972ca1-4bbc-45b5-a5fb-a4019d9c3f0b",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 0,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "arp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "e9e37c0a-a952-40b2-880d-077df0434794",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Palo Alto Networks LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "192.168.1.91",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "banner": "HTTP/1.1 301 Moved Permanently\r\nContent-Type: text/html\r\nLocation: https://192.168.1.91:9090/\r\nContent-Length: 73\r\nX-DNS-Prefetch-Control: off\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nCross-Origin-Resource-Policy: same-origin\r\n\r\n<html><head><title>Moved</title></head><body>Please use TLS</body></html>",
                    "cockpit.os": "Red Hat Enterprise Linux 8.5 (Ootpa)",
                    "fp.certainty": "0.85",
                    "host.name": "RHEL85.localdomain",
                    "html.forms": "GET:/",
                    "html.title": "Loading...\tMoved",
                    "http.body": "<!DOCTYPE html>\n<html>\n\n<head>\n  <title>Loading...</title>\n  <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n  <meta name=\"robots\" content=\"noindex\">\n  <meta insert_dynamic_content_here><base href=\"/\">\n    <script>\nvar environment = {\"page\":{\"connect\":true,\"require_host\":false},\"hostname\":\"RHEL85.localdomain\",\"os-release\":{\"NAME\":\"Red Hat Enterprise Linux\",\"ID\":\"rhel\",\"PRETTY_NAME\":\"Red Hat Enterprise Linux 8.5 (Ootpa)\",\"CPE_NAME\":\"cpe:/o:redhat:enterprise_linux:8::baseos\",\"ID_LIKE\":\"fedora\",\"DOCUMENTATION_URL\":\"https://access.redhat.com/documentation/red_hat_enterprise_linux/8/\"},\"CACertUrl\":\"/ca.cer\"};\n    </script>\n  <script type=\"text/javascript\">\n    /* Patch IE to support forEach on NodeLists, used in show/hide */\n    if (window.NodeList && !NodeList.prototype.forEach)\n        NodeList.prototype.forEach = Array.prototype.forEach;\n  </script>\n  <script type=\"text/javascript\">/*insert_translations_here*/</script>\n  <script type=\"text/javascript\" src=\"cockpit/static/login.js\"></script>\n  <link href=\"cockpit/static/login.css\" type=\"text/css\" rel=\"stylesheet\">\n  <link href=\"cockpit/static/branding.css\" type=\"text/css\" rel=\"stylesheet\">\n</head>\n\n<body class=\"login-pf\">\n  <div id=\"banner\" class=\"pf-c-alert pf-m-info pf-m-inline dialog-error\" aria-label=\"inline danger alert\" hidden>\n    <svg fill=\"currentColor\" viewBox=\"0 0 448 512\" aria-hidden=\"true\">\n      <path d=\"M224 512c35.32 0 63.97-28.65 63.97-64H160.03c0 35.35 28.65 64 63.97 64zm215.39-149.71c-19.32-20.76-55.47-51.99-55.47-154.29 0-77.7-54.48-139.9-127.94-155.16V32c0-17.67-14.32-32-31.98-32s-31.98 14.33-31.98 32v20.84C118.56 68.1 64.08 130.3 64.08 208c0 102.3-36.15 133.53-55.47 154.29-6 6.45-8.66 14.16-8.61 21.71.11 16.4 12.98 32 32.1 32h383.8c19.12 0 32-15.6 32.1-32 .05-7.55-2.61-15.27-8.61-21.71z\" />\n    </svg>\n    <span id=\"banner-message\" class=\"pf-c-alert__title\"></span>\n  </div>\n\n  <span id=\"badge\"></span>\n\n  <div class=\"container\">\n    <h1 id=\"brand\" class=\"hide-before\"></h1>\n\n    <div id=\"error-group\" class=\"pf-c-alert pf-m-danger pf-m-inline dialog-error noscript\" aria-label=\"inline danger alert\">\n      <svg fill=\"currentColor\" viewBox=\"0 0 512 512\" aria-hidden=\"true\">\n        <path d=\"M504 256c0 136.997-111.043 248-248 248S8 392.997 8 256C8 119.083 119.043 8 256 8s248 111.083 248 248zm-248 50c-25.405 0-46 20.595-46 46s20.595 46 46 46 46-20.595 46-46-20.595-46-46-46zm-43.673-165.346l7.418 136c.347 6.364 5.609 11.346 11.982 11.346h28.546c6.373 0 11.635-4.982 11.982-11.346l7.418-136c.375-6.874-5.098-12.654-11.982-12.654h-63.383c-6.884 0-12.356 5.78-11.981 12.654z\" />\n      </svg>\n      <h2 id=\"login-error-message\" class=\"pf-c-alert__title\">\n        <span class=\"noscript\" translate>Please enable JavaScript to use the Web Console.</span>\n      </h2>\n    </div>\n\n    <div id=\"info-group\" class=\"pf-c-alert pf-m-info pf-m-inline dialog-error\" aria-label=\"inline danger alert\" hidden>\n      <svg fill=\"currentColor\" viewBox=\"0 0 512 512\" aria-hidden=\"true\">\n        <path d=\"M256 8C119.043 8 8 119.083 8 256c0 136.997 111.043 248 248 248s248-111.003 248-248C504 119.083 392.957 8 256 8zm0 110c23.196 0 42 18.804 42 42s-18.804 42-42 42-42-18.804-42-42 18.804-42 42-42zm56 254c0 6.627-5.373 12-12 12h-88c-6.627 0-12-5.373-12-12v-24c0-6.627 5.373-12 12-12h12v-64h-12c-6.627 0-12-5.373-12-12v-24c0-6.627 5.373-12 12-12h64c6.627 0 12 5.373 12 12v100h12c6.627 0 12 5.373 12 12v24z\" />\n      </svg>\n      <h2 id=\"login-info-message\" class=\"pf-c-alert__title\"></h2>\n    </div>\n\n    <div id=\"login\" class=\"login-area\" hidden>\n      <form onsubmit=\"return false\">\n\n        <div id=\"conversation-group\" class=\"form-group\" hidden>\n          <div id=\"conversation-message\"></div>\n          <label id=\"conversation-prompt\" for=\"conversation-input\"></label>\n          <input type=\"password\" class=\"form-control\" id=\"conversation-input\">\n        </div>\n\n        <div id=\"hostkey-group\" class=\"form-group\" hidden>\n          <h1 id=\"hostkey-title\"></h1>\n          <div id=\"hostkey-warning-group\" class=\"pf-c-alert\t<html><head><title>Moved</title></head><body>Please use TLS</body></html>",
                    "http.code": "200\t301",
                    "http.head.cacheControl": "no-cache, no-store",
                    "http.head.contentLength": "73",
                    "http.head.contentSecurityPolicy": "connect-src 'self' https://192.168.1.91:9090 wss://192.168.1.91:9090; form-action 'self' https://192.168.1.91:9090; base-uri 'self' https://192.168.1.91:9090; object-src 'none'; font-src 'self' https://192.168.1.91:9090 data:; img-src 'self' https://192.168.1.91:9090 data:; block-all-mixed-content; default-src 'self' https://192.168.1.91:9090 'unsafe-inline'",
                    "http.head.contentType": "text/html",
                    "http.head.crossOriginResourcePolicy": "same-origin",
                    "http.head.location": "https://192.168.1.91:9090/",
                    "http.head.referrerPolicy": "no-referrer",
                    "http.head.setCookie": "cockpit=deleted; PATH=/; SameSite=strict; Secure; HttpOnly",
                    "http.head.xcontenttypeoptions": "nosniff",
                    "http.head.xdnsprefetchcontrol": "off",
                    "http.message": "200 OK\t301 Moved Permanently",
                    "http.uri": "/",
                    "http.url": "http://192.168.1.91:9090/\thttps://192.168.1.91:9090/",
                    "os.cpe23": "cpe:/o:redhat:enterprise_linux:8.5",
                    "os.family": "Linux",
                    "os.product": "Enterprise Linux",
                    "os.vendor": "Red Hat",
                    "os.version": "8.5",
                    "product": "Cockpit Project:Cockpit:",
                    "protocol": "http\ttls",
                    "source": "connect",
                    "tls.authorityKeyID": "6345348e3284ca5dbe58d7c894a77a3ff7cc3287",
                    "tls.caUnknown": "issuer=CN=RHEL85.localdomain, OU=ca-93049768678360241, O=a1e0eaed94b94ba38e499f8c45abf326, C=US",
                    "tls.certificates": "MIIE0DCCArigAwIBAgIIN2Z7pNSSJKcwDQYJKoZIhvcNAQELBQAwdDELMAkGA1UEBhMCVVMxKTAnBgNVBAoMIGExZTBlYWVkOTRiOTRiYTM4ZTQ5OWY4YzQ1YWJmMzI2MR0wGwYDVQQLDBRjYS05MzA0OTc2ODY3ODM2MDI0MTEbMBkGA1UEAwwSUkhFTDg1LmxvY2FsZG9tYWluMB4XDTIyMTIyNTIyMjkwM1oXDTI0MDEzMDEwMDkwM1owVTELMAkGA1UEBhMCVVMxKTAnBgNVBAoMIGExZTBlYWVkOTRiOTRiYTM4ZTQ5OWY4YzQ1YWJmMzI2MRswGQYDVQQDDBJSSEVMODUubG9jYWxkb21haW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCweRShOn3NkR/F/DDhTOkK/fAarh32uRLv8xZ+4+4JnedtoTeSVpjLVf/nTdr18oRcnSiA6cT75e/kefgrfWiP9M+GKeAyCqXlBS4uUGijA1YLoAzqm1FwUUlA6lHujFCzoyIYKRT9F/idWZkAQraGLFkXsds0ZJHaKaE097E7a5Ts0A6/hPFP5lgXVLDuZk3ABYcPzJmyb6B1ufnMCjIYeFXxZ6Ay12umcvd4ZBegD7SVfy0wXInAsZVtTupIJmzTWzhPhDnJ0891wWNll+6rTcT07n6DTdYUOpJNVkKSXBzw/3bTzcOmNgWK+kzvv5xyZWBXumcZP21rqvK4a0BAgMBAAGjgYQwgYEwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAkGA1UdEwQCMAAwLgYDVR0RBCcwJYISUkhFTDg1LmxvY2FsZG9tYWlugglsb2NhbGhvc3SHBH8AAAEwHwYDVR0jBBgwFoAUY0U0jjKEyl2+WNfIlKd6P/fMMocwDQYJKoZIhvcNAQELBQADggIBAIVf/m5qAAD9MWI0v6t1py1eSf7/dHtaYIhLI/cRJiCKtnCDTpu0qku9jM1lWGr9cw/im31o340pjssTCXWvbLGgpJ+K0QqFjF0eZj6Z9A70Dn8HteGr7b2lxysQw76waeRd1OoDx6pr7wzIwS1hQxdoQ3dzZ2ubdZgYeAMARhdo/CvThodKn99iwYA0/cpt4w7c4rHH/CH96RD/iD5zOtJsZQ0tt4ZPMFu4g1RTCCVtdIo/toUNfshojkpEkZGBeWKisQHbVVaJQMKbRRPF7TH04JvB7PcI3HlRovdcH9gZZfZtOU1MxkuqcM7Yy+P9m2/HiXaS2UXo1nNcMh7weQslAsCMT1kNRr4gLkigsYNpPkEMfawP2FwjTn775VFzpOqKDS1Dx8ikn9rh+TpBaNqL+/VPbGkvnnSrE5wdm4TS1ZMprsXNDEmPjyqKHLlsJ7vyv9YcIDus4JULTFeitZQkHqBim+q3cNIQpWaLwVcl3V4waAGOjgDLNAxBfATXCIHnhUrQS1QCsn7zc8qLGFjQtPZhc2LqEsID+HwALJSLXLSAAGeBztWlL9tYUf3UDH1JnkNalrJ+aYR1iSed5tyysZ/LaMKpUOF86lMfTAWHYWMAIIRyoYkEiusU8MfQ1evJW+E1AY0KeW4VBO5Xf5h08+fQiO2PwVbWR23Bf6rp",
                    "tls.cipher": "0x1303",
                    "tls.cipherName": "TLS_CHACHA20_POLY1305_SHA256",
                    "tls.cn": "RHEL85.localdomain",
                    "tls.fp.sha1": "6e02c6bbf44cbc812575217e3ac0709366286d80",
                    "tls.fp.sha256": "sha256",
                    "tls.issuer": "CN=RHEL85.localdomain, OU=ca-93049768678360241, O=a1e0eaed94b94ba38e499f8c45abf326, C=US",
                    "tls.names": "127.0.0.1\tlocalhost\trhel85.localdomain",
                    "tls.notAfter": "2024-01-30T10:09:03Z",
                    "tls.notAfterTS": "1706609343",
                    "tls.notBefore": "2022-12-25T22:29:03Z",
                    "tls.notBeforeTS": "1672007343",
                    "tls.serial": "37667ba4d49224a7",
                    "tls.signatureAlgorithm": "sha256WithRSAEncryption",
                    "tls.subject": "CN=RHEL85.localdomain, O=a1e0eaed94b94ba38e499f8c45abf326, C=US",
                    "tls.version": "0x0304",
                    "tls.versionName": "TLSv1.3",
                    "ts": "1672008102"
                },
                "service_has_screenshot": false,
                "service_id": "e9e37c0a-a952-40b2-880d-077df0434794",
                "service_link": "https://192.168.1.91:9090",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 9090,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [
                    "http",
                    "tls"
                ],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "HTTP/1.1 301 Moved Permanently\r\nContent-Type: text/html\r\nLocation: https://192.168.1.91:9090/\r\nContent-Length: 73\r\nX-DNS-Prefetch-Control: off\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nCross-Origin-Resource-Policy: same-origin\r\n\r\n<html><head><title>Moved</title></head><body>Please use TLS</body></html>",
                "service_transport": "tcp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "agent_external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "f9917aca-cc6b-4c49-96fa-4cd00e748719",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Org name LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "192.168.1.91",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "protocol": "sunrpc",
                    "source": "rpcbind",
                    "ts": "1672008083"
                },
                "service_has_screenshot": false,
                "service_id": "f9917aca-cc6b-4c49-96fa-4cd00e748719",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 111,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [
                    "sunrpc"
                ],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "tcp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Service
>|ARP|Address|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|Port|Protocol|RTT/ms|SW|Site|Summary|Svcs|TCP|Tags|Transport|Type|UDP|Vulns|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | 04d60ddf-8d28-494c-8186-8cd514e5b9cb | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br/>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | udp | Server | 4 | 0 |
>| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | 10f9e421-d80a-47d6-9643-d3e0c423a0f7 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | icmp | Server | 4 | 0 |
>| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | 4cdaab83-a513-42e1-8ff1-ba1d70c64cc3 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 22 | ssh | 0.84 | 2 | Primary | SSH-2.0-OpenSSH_8.0 | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | tcp | Server | 4 | 0 |
>| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | 89308b21-7c53-4a06-8e65-616f2dea019e | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | udp | Server | 4 | 0 |
>| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | 9b65b530-1540-47fb-9638-1f49081b2a09 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br/>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | udp | Server | 4 | 0 |
>| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | a0dafbdd-e56d-4d01-be51-99dbbaaa8322 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | arp | Server | 4 | 0 |
>| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | b3760c57-934f-4e45-ad9b-3aef27a9825a | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | icmp | Server | 4 | 0 |
>| 1 | fe80::250:56ff:fe89:b0e1 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | c807c93b-3b63-4937-89f5-c3d89eb36003 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | udp | Server | 4 | 0 |
>| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | d2972ca1-4bbc-45b5-a5fb-a4019d9c3f0b | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 0 |  | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | arp | Server | 4 | 0 |
>| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | e9e37c0a-a952-40b2-880d-077df0434794 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 9090 | http,<br/>tls | 0.84 | 2 | Primary | HTTP/1.1 301 Moved Permanently<br/>Content-Type: text/html<br/>Location: https:<span>//</span>192.168.1.91:9090/<br/>Content-Length: 73<br/>X-DNS-Prefetch-Control: off<br/>Referrer-Policy: no-referrer<br/>X-Content-Type-Options: nosniff<br/>Cross-Origin-Resource-Policy: same-origin<br/><br/><html><head><title>Moved</title></head><body>Please use TLS</body></html> | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | tcp | Server | 4 | 0 |
>| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | f9917aca-cc6b-4c49-96fa-4cd00e748719 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | tcp | Server | 4 | 0 |


#### Command example
```!runzero-service-search service_addresses=192.168.1.2,192.168.1.91 limit=3 display_attributes=True```
#### Context Example
```json
{
    "RunZero": {
        "Service": [
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "agent_external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "attributes": {
                    "_asset.match": "mac=00:50:56:89:b0:e1",
                    "_macs.ipmap": "00:50:56:89:b0:e1=192.168.1.91\t00:50:56:89:b0:e1=fe80::250:56ff:fe89:b0e1",
                    "fp.certainty": "0.85",
                    "ip.ttl.hops": "0",
                    "ip.ttl.source.icmp": "64",
                    "match.db": "operating-system",
                    "match.score": "00",
                    "match.score.hw": "00",
                    "match.score.os": "85",
                    "mdns.hostname": "RHEL85",
                    "os.cpe23": "cpe:/o:redhat:enterprise_linux:8.5",
                    "os.family": "Linux",
                    "os.product": "Enterprise Linux",
                    "os.vendor": "Red Hat",
                    "os.version": "8.5",
                    "ssh.authMethods": "password\tpublickey",
                    "virtual": "VMware"
                },
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "4cdaab83-a513-42e1-8ff1-ba1d70c64cc3",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Org name LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "192.168.1.91",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "banner": "SSH-2.0-OpenSSH_8.0",
                    "fp.certainty": "0.85",
                    "product": "OpenBSD:OpenSSH:8.0",
                    "protocol": "ssh",
                    "source": "connect",
                    "ssh.authMethods": "password\tpublickey",
                    "ssh.authPassword": "true",
                    "ssh.authPublicKey": "true",
                    "ssh.hostKey.data": "AAAAB3NzaC1yc2EAAAADAQABAAABgQDcG6E/EoCvbnwDNgz7GPvM7rireCOeuWdHF1cxdR+yAzlltEeTrBoFNx/AdePTpsnIvBF9g4aP0XV7JVJXIWmI3UmAG/KBcIeXBdp5amnbSo7EVpyyQi6sAc5bmdYS3OjM9AdOL7aRpWdt/kzqUtDx60O/igS2QJf5LX+oxAWk1fQcaJtW+FxWVw2H6RVI4mBJ+T9LWvMmqMui56wa/onIkFQEVecHxCF868LtdGm+cChk/BtZKkUjG/CO/uzbBdCx6FjBIsK9kp3w6v2iLlxfPL9wVO5ilO8PBZCzVOnkr3ZgaYs/v1UYPiKD7NFEteW1pdFhuROWg7H9mdkd2VNG+6j28Xb1fLhOSUJu7flGXGx3mqmPsdog4+L06ZCXqpRBPCXimByYrstOkNm/kKZSqrigj+pM9i8QXnBTrokPd7VbQ1eCgHTyJzGefqv6JjoXnwEmxXGKQxw2kj6H9SyPaNqfIaPcIk3sRq6MncuQL+zvvH8QC0iyykeRlQxHlTk=",
                    "ssh.hostKey.md5": "md5",
                    "ssh.hostKey.sha256": "SHA256:tovkrBOsS9d1cTtdZMBi53eZY3DLO8bNvrUWgTrr9vg",
                    "ssh.hostKey.type": "ssh-rsa",
                    "ssh.hostKeyAlgorithms": "ecdsa-sha2-nistp256\trsa-sha2-256\trsa-sha2-512\tssh-ed25519\tssh-rsa",
                    "ssh.kexAlgorithms": "curve25519-sha256\tcurve25519-sha256@libssh.org\tdiffie-hellman-group-exchange-sha1\tdiffie-hellman-group-exchange-sha256\tdiffie-hellman-group14-sha1\tdiffie-hellman-group14-sha256\tdiffie-hellman-group16-sha512\tdiffie-hellman-group18-sha512\tecdh-sha2-nistp256\tecdh-sha2-nistp384\tecdh-sha2-nistp521",
                    "ssh.kexCookie": "60a4aaf8a8ed37501fb9dd97df32d1d7",
                    "ssh.kexPadding": "5",
                    "ssh.toClientCiphers": "aes128-cbc\taes128-ctr\mail@mail.com\taes256-cbc\taes256-ctr\mail@mail.com\mail@mail.com",
                    "ssh.toClientCompression": "none\tmail@mail.com",
                    "ssh.toClientMACs": "hmac-sha1\mail@mail.com\thmac-sha2-256\mail@mail.com\thmac-sha2-512\thmac-sha2-512-etm@openssh.com\tumac-128-etm@openssh.com\mail@mail.com",
                    "ssh.toServerCiphers": "aes128-cbc\taes128-ctr\mail@mail.com\taes256-cbc\taes256-ctr\mail@mail.com\mail@mail.com",
                    "ssh.toServerCompression": "none\tmail@mail.com",
                    "ssh.toServerMACs": "hmac-sha1\mail@mail.com\thmac-sha2-256\mail@mail.com\thmac-sha2-512\thmac-sha2-512-etm@openssh.com\tumac-128-etm@openssh.com\mail@mail.com",
                    "ts": "1672008108"
                },
                "service_has_screenshot": false,
                "service_id": "4cdaab83-a513-42e1-8ff1-ba1d70c64cc3",
                "service_link": "ssh://192.168.1.91:22",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 22,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [
                    "ssh"
                ],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "SSH-2.0-OpenSSH_8.0",
                "service_transport": "tcp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "attributes": {
                    "_asset.match": "mac=00:50:56:89:b0:e1",
                    "_macs.ipmap": "00:50:56:89:b0:e1=192.168.1.91\t00:50:56:89:b0:e1=fe80::250:56ff:fe89:b0e1",
                    "fp.certainty": "0.85",
                    "ip.ttl.hops": "0",
                    "ip.ttl.source.icmp": "64",
                    "match.db": "operating-system",
                    "match.score": "00",
                    "match.score.hw": "00",
                    "match.score.os": "85",
                    "mdns.hostname": "RHEL85",
                    "os.cpe23": "cpe:/o:redhat:enterprise_linux:8.5",
                    "os.family": "Linux",
                    "os.product": "Enterprise Linux",
                    "os.vendor": "Red Hat",
                    "os.version": "8.5",
                    "ssh.authMethods": "password\tpublickey",
                    "virtual": "VMware"
                },
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "89308b21-7c53-4a06-8e65-616f2dea019e",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Palo Alto Networks LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "192.168.1.91",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "mdns.addrs": "192.168.1.91\tfe80::250:56ff:fe89:b0e1",
                    "mdns.hostname": "RHEL85",
                    "mdns.replies": "1.1.1.1.in-addr.arpa.=PTR,RHEL85.local.\tPCP pmcd on RHEL85.localdomain._pmcd._tcp.local.=SRV,RHEL85.local.:44321\tRHEL85.local.=A,192.168.1.91\tRHEL85.local.=AAAA,fe80::250:56ff:fe89:b0e1\t_pmcd._tcp.local.=PTR,PCP pmcd on RHEL85.localdomain._pmcd._tcp.local.",
                    "mdns.services": "pmcd/tcp",
                    "protocol": "mdns",
                    "ts": "1672008085"
                },
                "service_has_screenshot": false,
                "service_id": "89308b21-7c53-4a06-8e65-616f2dea019e",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 5353,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [
                    "mdns"
                ],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "udp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            },
            {
                "addresses": [
                    "192.168.1.91",
                    "fe80::250:56ff:fe89:b0e1"
                ],
                "addresses_extra": [],
                "agent_external_ip": "external_ip",
                "agent_name": "RHEL85.LOCALDOMAIN",
                "alive": true,
                "attributes": {
                    "_asset.match": "mac=00:50:56:89:b0:e1",
                    "_macs.ipmap": "00:50:56:89:b0:e1=192.168.1.91\t00:50:56:89:b0:e1=fe80::250:56ff:fe89:b0e1",
                    "fp.certainty": "0.85",
                    "ip.ttl.hops": "0",
                    "ip.ttl.source.icmp": "64",
                    "match.db": "operating-system",
                    "match.score": "00",
                    "match.score.hw": "00",
                    "match.score.os": "85",
                    "mdns.hostname": "RHEL85",
                    "os.cpe23": "cpe:/o:redhat:enterprise_linux:8.5",
                    "os.family": "Linux",
                    "os.product": "Enterprise Linux",
                    "os.vendor": "Red Hat",
                    "os.version": "8.5",
                    "ssh.authMethods": "password\tpublickey",
                    "virtual": "VMware"
                },
                "comments": "integration comment",
                "created_at": 1672007446,
                "credentials": {},
                "detected_by": "arp",
                "domains": [],
                "eol_os": 0,
                "eol_os_ext": 0,
                "first_seen": 1672007309,
                "foreign_attributes": null,
                "hosted_zone_name": null,
                "hw": "VMware VM",
                "hw_product": "",
                "hw_vendor": "",
                "hw_version": "",
                "id": "9b65b530-1540-47fb-9638-1f49081b2a09",
                "last_agent_id": "1b1de331-e7dd-48c1-8d21-18db913e79e2",
                "last_seen": 1672008118,
                "last_task_id": "f3740388-e892-4a42-b5a3-b0a2454017e2",
                "lowest_rtt": 837561,
                "lowest_ttl": 0,
                "mac_vendors": [
                    "VMware, Inc."
                ],
                "macs": [
                    "00:50:56:89:b0:e1"
                ],
                "names": [
                    "RHEL85",
                    "RHEL85.LOCALDOMAIN"
                ],
                "newest_mac": "00:50:56:89:b0:e1",
                "newest_mac_age": null,
                "newest_mac_vendor": "VMware, Inc.",
                "org_name": "Palo Alto Networks LTD",
                "organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "os": "Red Hat Enterprise Linux",
                "os_product": "Enterprise Linux",
                "os_vendor": "Red Hat",
                "os_version": "8.5",
                "outlier_raw": 0,
                "outlier_score": 0,
                "owners": [],
                "ownership": {},
                "rtts": {
                    "icmp/echo": [
                        837561,
                        5320391,
                        6077638
                    ]
                },
                "scanned": true,
                "service_address": "192.168.1.91",
                "service_asset_id": "bf707048-7ce9-4249-a58c-0aaa257d69f0",
                "service_count": 11,
                "service_count_arp": 1,
                "service_count_icmp": 1,
                "service_count_tcp": 3,
                "service_count_udp": 4,
                "service_created_at": 1672008222,
                "service_data": {
                    "protocol": "rpcbind\tsunrpc",
                    "rpcbind.addrs": "192.168.1.91",
                    "rpcbind.programs": "100000-v4-tcp-111\t100000-v3-tcp-111\t100000-v2-tcp-111\t100000-v4-udp-111\t100000-v3-udp-111\t100000-v2-udp-111",
                    "source": "rpcbind",
                    "ts": "1672008083"
                },
                "service_has_screenshot": false,
                "service_id": "9b65b530-1540-47fb-9638-1f49081b2a09",
                "service_link": "",
                "service_organization_id": "ba370042-b8fc-44dd-8858-56747a2e716e",
                "service_port": 111,
                "service_ports_tcp": [
                    "22",
                    "111",
                    "9090"
                ],
                "service_ports_udp": [
                    "111",
                    "5353"
                ],
                "service_products": [
                    "cockpit",
                    "openbsd openssh"
                ],
                "service_protocol": [
                    "rpcbind",
                    "sunrpc"
                ],
                "service_protocols": [
                    "http",
                    "mdns",
                    "rpcbind",
                    "ssh",
                    "sunrpc",
                    "tls"
                ],
                "service_screenshot_key": "",
                "service_screenshot_link": "",
                "service_source_ids": null,
                "service_summary": "",
                "service_transport": "udp",
                "service_updated_at": 0,
                "service_vhost": "",
                "services": {},
                "site_id": "b5f8a8b7-019d-4f6a-9520-7e37ae149c81",
                "site_name": "Primary",
                "software_count": 2,
                "source_ids": [
                    1
                ],
                "tags": {
                    "ThisTag": "Value",
                    "ThisTag-ThisTag2": "",
                    "ThisTag2": "Value",
                    "try": "value",
                    "try3": "value3"
                },
                "type": "Server",
                "updated_at": 1674661963,
                "vulnerability_count": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Service
>|ARP|Address|Asset_Status|Comments|Detected|Explorer|First_Seen|Hardware|Hops|Hostname|ICMP|ID|Last_Seen|MAC|MAC_Vendor|OS|OS_EOL|Outlier|Port|Protocol|RTT/ms|SW|Site|Summary|Svcs|TCP|Tags|Transport|Type|UDP|Vulns|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | 4cdaab83-a513-42e1-8ff1-ba1d70c64cc3 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 22 | ssh | 0.84 | 2 | Primary | SSH-2.0-OpenSSH_8.0 | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | tcp | Server | 4 | 0 |
>| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | 89308b21-7c53-4a06-8e65-616f2dea019e | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 5353 | mdns | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | udp | Server | 4 | 0 |
>| 1 | 192.168.1.91 | true | integration comment | arp | RHEL85.LOCALDOMAIN | 2022-12-25T22:28:29.000Z | VMware VM | 0 | RHEL85,<br/>RHEL85.LOCALDOMAIN | 1 | 9b65b530-1540-47fb-9638-1f49081b2a09 | 2022-12-25T22:41:58.000Z | 00:50:56:89:b0:e1 | VMware, Inc. | Red Hat Enterprise Linux 8.5 | 0 | 0 | 111 | rpcbind,<br/>sunrpc | 0.84 | 2 | Primary |  | 11 | 3 | ThisTag: Value<br/>ThisTag-ThisTag2: <br/>ThisTag2: Value<br/>try: value<br/>try3: value3 | udp | Server | 4 | 0 |


#### Command example
```!runzero-service-search search=os:Windows ```
#### Human Readable Output

>### Service
>**No entries.**


### runzero-service-delete
***
Delete a service.


#### Base Command

`runzero-service-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | UUID of the service to delete. | Required | 


#### Context Output

There is no context output for this command.
### runzero-comment-add
***
Add a comment or override an existing asset comment.


#### Base Command

`runzero-comment-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required | 
| comment | Comment to add. | Required | 


#### Context Output

There is no context output for this command.
### runzero-tag-add
***
Add tag or tags to the asset.


#### Base Command

`runzero-tag-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required | 
| tags | Tags to add to the asset. | Required | 


#### Context Output

There is no context output for this command.
### runzero-quota-get
***
Get information about the API key used. Type, Limit, usage etc.


#### Base Command

`runzero-quota-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RunZero.Quota.id | UUID | API key ID. | 
| RunZero.Quota.client_id | UUID | Client ID. | 
| RunZero.Quota.organization_id | UUID | Organization ID. | 
| RunZero.Quota.created_at | Integer | Time the API was created. | 
| RunZero.Quota.comment | String | API key comment. | 
| RunZero.Quota.last_used_at | Integer | The time when the API key was last seen. | 
| RunZero.Quota.last_used_ip | String | The IP address last used by the API key. | 
| RunZero.Quota.last_used_ua | String | The user agent last used by the API key. | 
| RunZero.Quota.counter | Integer | The API key usage counter. | 
| RunZero.Quota.usage_today | Integer | The API key usage today. | 
| RunZero.Quota.usage_limit | Integer | The API key usage limit. | 
| RunZero.Quota.token | String | The API key. | 
| RunZero.Quota.inactive | String | Whether the API key is inactive. | 
| RunZero.Quota.type | String | API key type \(org, etc.\). | 

#### Command example
```!runzero-quota-get```
#### Context Example
```json
{
    "RunZero": {
        "Quota": {
            "client_id": "3c4f1d12-352b-4c0a-a5bf-7d37ab3d4dac",
            "comment": "",
            "counter": 454,
            "created_at": 1672325319,
            "created_by": "user@orgid.com",
            "id": "id",
            "inactive": false,
            "last_used_at": 1675007349,
            "last_used_ip": "last_used_ip",
            "last_used_ua": "python-requests/2.28.2",
            "organization_id": "organization_id",
            "token": "",
            "type": "org",
            "usage_limit": 1000,
            "usage_today": 25
        }
    }
}
```

#### Human Readable Output

>### Quota
>|counter|usage_limit|usage_today|
>|---|---|---|
>| 454 | 1672325319 | 25 |


### runzero-tag-delete
***
Delete tags for specific asset.


#### Base Command

`runzero-tag-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID from which to remove specified tags. | Required | 
| tags | A comma separated list of tags to delete. | Required | 


#### Context Output

There is no context output for this command.
### runzero-wireless-lan-search
***
Get all wireless LANs.


#### Base Command

`runzero-wireless-lan-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| wireless_id | The wireless LAN ID. | Optional | 
| search | The query by which to search. For information on the syntax, see: https://www.runzero.com/docs/runzero-manual.pdf page 288. | Optional | 
| limit | Limit the number of wireless LAN returned. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RunZero.WirelessLAN.ID | UUID | Wireless LAN ID. | 
| RunZero.WirelessLAN.ESSID | String | Wireless LAN extended service set identifier \(ESSID\). | 
| RunZero.WirelessLAN.BSSID | String | Wireless LAN basic service set identifier \(BSSID\). | 
| RunZero.WirelessLAN.Vendor | String | Wireless LAN vendor. | 
| RunZero.WirelessLAN.Family | String | Wireless LAN family. | 
| RunZero.WirelessLAN.Type | String | Wireless LAN type. | 
| RunZero.WirelessLAN.Auth | String | Wireless LAN auth. | 
| RunZero.WirelessLAN.Enc | String | Wireless LAN encryption. | 
| RunZero.WirelessLAN.Sig | Integer | WirelessLAN signal strength. | 
| RunZero.WirelessLAN.Int | String | Wireless LAN interface. | 
| RunZero.WirelessLAN.Additional | Array | Wireless LAN additional information. | 
| RunZero.WirelessLAN.First_seen | String | Datetime of when the wireless LAN was first seen. | 
| RunZero.WirelessLAN.Last_seen | String | Datetime of when the wireless LAN was last seen. | 
| RunZero.WirelessLAN.Site | String | Wireless LAN site name. | 

### runzero-wireless-lan-delete
***
Remove a wireless LAN.


#### Base Command

`runzero-wireless-lan-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| wireless_id | UUID of the wireless LAN to remove. | Required | 


#### Context Output

There is no context output for this command.