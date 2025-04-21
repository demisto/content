FortiGate provides flawless convergence that can scale to any location: remote office, branch, campus, data center, and cloud. FortiGate always delivered on the concept of hybrid mesh firewalls with FortiManager for unified management and consistent security across complex hybrid environments. The Fortinet FortiOS operating system provides deep visibility and security across a variety of form factors.
This integration was integrated and tested with version 7.2.5 of FortiGate.

## Configure FortiGate in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://192.168.0.1) | True |
| Account username | False |
| Password | False |
| API Key | False |
| API Key | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fortigate-list-firewall-address-ipv4s

***
Retrieve firewall IPv4 addresses. Addresses define sources and destinations of network traffic and can be used in many functions such as firewall policies, ZTNA, etc.

#### Base Command

`fortigate-list-firewall-address-ipv4s`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of a specific address to return. | Optional |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/220620/config-firewall-address`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/220620/config-firewall-address`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Address.Name | String | Address name. |
| Fortigate.Address.Subnet | String | IP address and subnet mask of address. |
| Fortigate.Address.StartIP | String | First IP address \(inclusive\) in the range for the address. |
| Fortigate.Address.EndIP | String | Final IP address \(inclusive\) in the range for the address. |
| Fortigate.Address.FQDN | String | Fully Qualified Domain Name address. |
| Fortigate.Address.MACAddresses | String | Multiple MAC address ranges &lt;start&gt;\[-&lt;end&gt;\] separated by a space. |
| Fortigate.Address.Type | String | Type of the address. Can be: \`ipmask\`, \`iprange\`, \`fqdn\`, \`geography\`, \`wildcard\`, \`dynamic\`, \`interface-subnet\` or \`mac\`. |
| Fortigate.Address.FabricObject | String | Security Fabric global object setting. Can be \`enable\` or \`disable\`. If \`enable\`, the object is set as a security fabric-wide global object, otherwise the object is local to this security fabric member. |
| Fortigate.Address.AllowRouting | String | Enable/disable use of this address in the static route configuration. |
| Fortigate.Address.Tagging | String | List of tags associated to the object. |
| Fortigate.Address.IPs | String | List of IP addresses. |
| Fortigate.Address.SDNAddressType | String | Type of addresses to collect. Can be: \`private\`, \`public\`, or \`all\`. |
| Fortigate.Address.AssociatedInterface | String | Network interface associated with the address. |
| Fortigate.Address.Comment | String | The object\`s comment. |
| Fortigate.Address.Dirty | String | Whether the object is clean. |
| Fortigate.Address.TagType | String | Tag type of dynamic address object. |
| Fortigate.Address.TagDetectionLevel | String | Tag detection level of dynamic address object. |
| Fortigate.Address.ObjectType | String | IP or MAC address. |
| Fortigate.Address.Interface | String | Name of the interface whose IP address is to be used. |
| Fortigate.Address.FSSOGroup | String | Fortinet Single Sign-On group name. |
| Fortigate.Address.SDN | String | Software-defined networking. |
| Fortigate.Address.SDNTag | String | Software-defined networking tag. |
| Fortigate.Address.CacheTTL | Number | Defines the minimal TTL of individual IP addresses in FQDN cache measured in seconds. |
| Fortigate.Address.Country | String | IP addresses associated to a specific country. |
| Fortigate.Address.ClearpassSPT | String | System Posture Token value. Can be: \`unknown\`, \`healthy\`, \`quarantine\`, \`checkup\`, \`transient\` or \`infected\`. |
| Fortigate.Address.SubType | String | Sub-type of address. Can be: \`sdn\`, \`clearpass-spt\`, \`fsso\`, \`ems-tag\`, \`fortivoice-tag\`, \`fortinac-tag\`, \`fortipolicy-tag\` or \`swc-tag\`. |
| Fortigate.Address.UUID | String | Universally Unique Identifier. |
| Fortigate.Address.ObjectTag | String | Tag of dynamic address object. |
| Fortigate.Address.VDOM | String | Virtual domains \(VDOMs\) enable you to partition and use your FortiGate unit as if it were multiple units. |

#### Command example
```!fortigate-list-firewall-address-ipv4s name=playbook-address-ipv4```
#### Context Example
```json
{
    "Fortigate": {
        "Address": {
            "AllowRouting": "disable",
            "AssociatedInterface": "",
            "CacheTTL": 0,
            "ClearpassSPT": "unknown",
            "Comment": "",
            "Country": "IL",
            "Dirty": "dirty",
            "FabricObject": "disable",
            "Interface": "",
            "Name": "playbook-address-ipv4",
            "ObjectType": "ip",
            "SDN": "",
            "SDNAddressType": "private",
            "SubType": "sdn",
            "TagDetectionLevel": "",
            "TagType": "",
            "Type": "geography",
            "UUID": "d30118b0-aa22-51ee-8e1b-bd78f7129431",
            "VDOM": "root"
        }
    }
}
```

#### Human Readable Output

>### Firewall Address IPv4s
>|Name|Details|Type|Routable|
>|---|---|---|---|
>| playbook-address-ipv4 | IL | geography | disable |


### fortigate-create-firewall-address-ipv4

***
Create firewall IPv4 addresses. Addresses define sources and destinations of network traffic and can be used in many functions such as firewall policies, ZTNA, etc. The command parameters can be used only in the following combinations: All-[vdom,name,comment,associated_interface], Subnet-[address,mask,allow_routing], IP Range-[start_ip,end_ip], FQDN-[fqdn,allow_routing], Geography-[country], Device (Mac Address)-[mac_addresses].

#### Base Command

`fortigate-create-firewall-address-ipv4`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| name | The name of the address to create. | Required |
| address | The IP address. | Optional |
| mask | The subnet mask as an IP address. Default value: `255.255.255.255`. | Optional |
| fqdn | Fully Qualified Domain Name address. | Optional |
| start_ip | First IP address (inclusive) in the range for the address. | Optional |
| end_ip | Final IP address (inclusive) in the range for the address. | Optional |
| country | IP addresses associated to a specific country. Input must be according to the two-letter counter codes, for example: `IL`. | Optional |
| mac_addresses | Comma-separated list of MAC addresses. Can be single or range. Range must be separated by `-`, for examlpe: `00:00:00:00:00:00` or `00:00:00:00:00:00-FF:FF:FF:FF:FF:FF`. | Optional |
| associated_interface | Network interface associated with address. | Optional |
| allow_routing | Enable/disable use of this address in the static route configuration. Possible values are: enable, disable. | Optional |
| comment | A comment for the address. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.Address.Name | String | The name of the updated address. |
| Frotigate.Address.IPAddress | String | The IP address. |
| Frotigate.Address.Mask | String | The subnet mask of the address. |
| Frotigate.Address.FQDN | String | The Fully Qualified Domain Name address. |
| Frotigate.Address.StartIP | String | First IP address \(inclusive\) in the range for the address. |
| Frotigate.Address.EndIP | String | Final IP address \(inclusive\) in the range for the address. |
| Frotigate.Address.Country | String | IP addresses associated to a specific country. |
| Frotigate.Address.MAC | String | MAC addresses. |

#### Command example
```!fortigate-create-firewall-address-ipv4 name=playbook-address-ipv4 country=IL```
#### Context Example
```json
{
    "Fortigate": {
        "Address": {
            "Country": "IL",
            "Name": "playbook-address-ipv4"
        }
    }
}
```

#### Human Readable Output

>## The firewall address 'playbook-address-ipv4' was successfully created.

### fortigate-update-firewall-address-ipv4

***
Update firewall IPv4 addresses. Addresses define sources and destinations of network traffic and can be used in many functions such as firewall policies, ZTNA, etc. The command parameters can be used only in the following combinations: All-[vdom,name,comment,associated_interface,type], Subnet-[address,mask,allow_routing], IP Range-[start_ip,end_ip], FQDN-[fqdn,allow_routing], Geography-[country], Device (Mac Address)-[mac_addresses].

#### Base Command

`fortigate-update-firewall-address-ipv4`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the address to update. Names can be retrieved with the command `fortigate-list-firewall-address-ipv4s`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| address | The IP address. | Optional |
| mask | The subnet mask of the address. | Optional |
| fqdn | Fully Qualified Domain Name address. | Optional |
| start_ip | First IP address (inclusive) in the range for the address. | Optional |
| end_ip | Final IP address (inclusive) in the range for the address. | Optional |
| country | IP addresses associated to a specific country. Input must be according to the two-letter counter codes, for example: `IL`. | Optional |
| mac_addresses | Comma-separated list of MAC addresses. Can be single or range. Range must be separated by `-`, for example: `00:00:00:00:00:00` or `00:00:00:00:00:00-FF:FF:FF:FF:FF:FF`. | Optional |
| associated_interface | Network interface associated with address. | Optional |
| allow_routing | Enable/disable use of this address in the static route configuration. Possible values are: enable, disable. | Optional |
| comment | A comment for the address. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.Address.Name | String | The name of the created address. |
| Frotigate.Address.IPAddress | String | The IP address. |
| Frotigate.Address.Mask | String | The subnet mask of the address. |
| Frotigate.Address.FQDN | String | The Fully Qualified Domain Name address. |
| Frotigate.Address.StartIP | String | First IP address \(inclusive\) in the range for the address. |
| Frotigate.Address.EndIP | String | Final IP address \(inclusive\) in the range for the address. |
| Frotigate.Address.Country | String | IP addresses associated to a specific country. |
| Frotigate.Address.MAC | String | MAC addresses. |

#### Command example
```!fortigate-update-firewall-address-ipv4 name=playbook-address-ipv4 comment=helloworld```
#### Context Example
```json
{
    "Fortigate": {
        "Address": {
            "Name": "playbook-address-ipv4"
        }
    }
}
```

#### Human Readable Output

>## The firewall address 'playbook-address-ipv4' was successfully updated.

### fortigate-delete-firewall-address-ipv4

***
Delete firewall IPv4 addresses. Addresses define sources and destinations of network traffic and can be used in many functions such as firewall policies, ZTNA, etc.

#### Base Command

`fortigate-delete-firewall-address-ipv4`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address to delete. Names can be retrieved with the command `fortigate-list-firewall-address-ipv4s`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.Address.Name | String | The name of the deleted address. |
| Frotigate.Address.Deleted | Boolean | Whether the address was deleted. |

#### Command example
```!fortigate-delete-firewall-address-ipv4 name=playbook-address-ipv4```
#### Context Example
```json
{
    "Fortigate": {
        "Address": {
            "Deleted": true,
            "Name": "playbook-address-ipv4"
        }
    }
}
```

#### Human Readable Output

>## The firewall address 'playbook-address-ipv4' was successfully deleted.

### fortigate-list-firewall-address-ipv6s

***
Retrieve firewall IPv6 addresses. Addresses define sources and destinations of network traffic and can be used in many functions such as firewall policies, ZTNA, etc.

#### Base Command

`fortigate-list-firewall-address-ipv6s`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of a specific address to return. | Optional |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/223620/config-firewall-address6`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/223620/config-firewall-address6`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Address6.FabricObject | String | Security Fabric global object setting. Can be \`enable\` or \`disable\`. If \`enable\`, the object is set as a security fabric-wide global object, otherwise the object is local to this security fabric member. |
| Fortigate.Address6.SDNTag | String | Software-defined networking tag. |
| Fortigate.Address6.Tenant | String | Specifies the instance or environment in a multi-tenancy setup for configuring address objects. |
| Fortigate.Address6.HostType | String | Can be a wildcard or a specific host address. |
| Fortigate.Address6.SubnetSegment.Name | String | The subnet segment name. |
| Fortigate.Address6.SubnetSegment.Type | String | The subnet segment type. Can be a wildcard or a specific address. |
| Fortigate.Address6.SubnetSegment.Value | String | The subnet segment value. |
| Fortigate.Address6.Template | String | IPv6 address template. |
| Fortigate.Address6.Comment | String | The object\`s comment. |
| Fortigate.Address6.Tagging | String | List of tags associated to the object. |
| Fortigate.Address6.IPs | String | List of IP addresses. |
| Fortigate.Address6.Country | String | IP addresses associated to a specific country. |
| Fortigate.Address6.FQDN | String | Fully Qualified Domain Name address. |
| Fortigate.Address6.StartIP | String | First IP address \(inclusive\) in the range for the address. |
| Fortigate.Address6.EndIP | String | Final IP address \(inclusive\) in the range for the address. |
| Fortigate.Address6.IPv6 | String | IPv6 address prefix. |
| Fortigate.Address6.SDN | String | Software-defined networking. |
| Fortigate.Address6.MACAddresses | Unknown | Multiple MAC address ranges &lt;start&gt;\[-&lt;end&gt;\] separated by a space. |
| Fortigate.Address6.Type | String | Type of IPv6 address object. Can be: \`ipprefix\`, \`iprange\`, \`fqdn\`, \`geography\`, \`dynamic\`, \`template\`, \`mac\`. |
| Fortigate.Address6.UUID | String | Universally Unique Identifier. |
| Fortigate.Address6.Name | String | Address name. |
| Fortigate.Address6.Host | String | Host address. |
| Fortigate.Address6.CacheTTL | Number | Defines the minimal TTL of individual IP addresses in FQDN cache measured in seconds. |
| Fortigate.Address6.VDOM | String | Virtual domains \(VDOMs\) enable you to partition and use your FortiGate unit as if it were multiple units. |

#### Command example
```!fortigate-list-firewall-address-ipv6s name=playbook-address-ipv6 comment=helloworld```
#### Context Example
```json
{
    "Fortigate": {
        "Address6": {
            "CacheTTL": 0,
            "Comment": "",
            "Country": "IL",
            "EndIP": "::",
            "FQDN": "",
            "FabricObject": "disable",
            "HostType": "any",
            "Name": "playbook-address-ipv6",
            "SDN": "",
            "SDNTag": "",
            "Template": "",
            "Tenant": "",
            "Type": "geography",
            "UUID": "d827aafc-aa22-51ee-2088-2123aa731857",
            "VDOM": "root"
        }
    }
}
```

#### Human Readable Output

>### Firewall Address IPv6s
>|Name|Details|Type|
>|---|---|---|
>| playbook-address-ipv6 | IL | geography |


### fortigate-create-firewall-address-ipv6

***
Create firewall IPv6 addresses. Addresses define sources and destinations of network traffic and can be used in many functions such as firewall policies, ZTNA, etc. The command parameters can be used only in the following combinations: All-[vdom,name,comment], Subnet-[address,mask], IP Range-[start_ip,end_ip], FQDN-[fqdn], Geography-[country], Fabric Connector Address-[sdn_connector], Device (Mac Address)-[mac_addresses].

#### Base Command

`fortigate-create-firewall-address-ipv6`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| name | Name of the address to create. | Required |
| address | IPv6 address prefix. Can be in short form (e.g., 2001:db8::) or long form (e.g., 0000:0000:0000:0000:0000:0000:0000:0000). | Optional |
| mask | Subnet mask indicating the prefix length (format: xxx, range: 0-128). | Optional |
| fqdn | Fully Qualified Domain Name address. | Optional |
| start_ip | First IP address (inclusive) in the range for the address. | Optional |
| end_ip | Final IP address (inclusive) in the range for the address. | Optional |
| country | IP addresses associated to a specific country. Input must be according to the two-letter counter codes, for example: `IL`. | Optional |
| mac_addresses | Comma-separated list of MAC addresses. Can be single or range. Range must be separated by `-`, for example: `00:00:00:00:00:00` or `00:00:00:00:00:00-FF:FF:FF:FF:FF:FF`. | Optional |
| sdn_connector | Software-defined networking connector enables to interact with SDN controllers. For more information, go to: https://docs.fortinet.com/document/fortigate/7.2.5/administration-guide/753961/public-and-private-sdn-connectors. | Optional |
| comment | A comment for the address. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.Address6.Name | String | The name of the updated address. |
| Frotigate.Address6.IPAddress | String | The IP address. |
| Frotigate.Address6.Mask | String | The subnet mask of the address. |
| Frotigate.Address6.FQDN | String | The Fully Qualified Domain Name address. |
| Frotigate.Address6.StartIP | String | First IP address \(inclusive\) in the range for the address. |
| Frotigate.Address6.EndIP | String | Final IP address \(inclusive\) in the range for the address. |
| Frotigate.Address6.Country | String | IP addresses associated to a specific country. |
| Frotigate.Address6.MAC | String | MAC addresses. |
| Frotigate.Address6.SDN | String | Software-defined networking. |

#### Command example
```!fortigate-create-firewall-address-ipv6 name=playbook-address-ipv6 country=IL```
#### Context Example
```json
{
    "Fortigate": {
        "Address6": {
            "Country": "IL",
            "Name": "playbook-address-ipv6"
        }
    }
}
```

#### Human Readable Output

>## The firewall address 'playbook-address-ipv6' was successfully created.

### fortigate-update-firewall-address-ipv6

***
Update firewall IPv6 addresses. Addresses define sources and destinations of network traffic and can be used in many functions such as firewall policies, ZTNA, etc. The command parameters can be used only in the following combinations: All-[vdom,name,comment,associated_interface], Subnet-[address,mask], IP Range-[start_ip,end_ip], FQDN-[fqdn], Geography-[country], Fabric Connector Address-[sdn_connector], Device (Mac Address)-[mac_addresses].

#### Base Command

`fortigate-update-firewall-address-ipv6`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| name | Name of the address to update. Names can be retrieved with the command `fortigate-list-firewall-address-ipv6s`. | Required |
| type | The type of the address to update. Possible values are: Subnet, IP Range, FQDN, Geography, Device (Mac Address), Fabric Connector Address. | Optional |
| address | The IP address. | Optional |
| mask | The subnet mask of the address. | Optional |
| fqdn | Fully Qualified Domain Name address. | Optional |
| start_ip | First IP address (inclusive) in the range for the address. | Optional |
| end_ip | Final IP address (inclusive) in the range for the address. | Optional |
| country | IP addresses associated to a specific country. Input must be according to the two-letter counter codes, for example: `IL`. | Optional |
| mac_addresses | Comma-separated list of MAC addresses. Can be single or range. Range must be separated by `-`, for example: `00:00:00:00:00:00` or `00:00:00:00:00:00-FF:FF:FF:FF:FF:FF`. | Optional |
| sdn_connector | Software-defined networking connector enables to interact with SDN controllers. For more information, go to: https://docs.fortinet.com/document/fortigate/7.2.5/administration-guide/753961/public-and-private-sdn-connectors. | Optional |
| comment | A comment for the address. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.Address6.Name | String | The name of the updated address. |
| Frotigate.Address6.IPAddress | String | The IP address. |
| Frotigate.Address6.Mask | String | The subnet mask of the address. |
| Frotigate.Address6.FQDN | String | The Fully Qualified Domain Name address. |
| Frotigate.Address6.StartIP | String | First IP address \(inclusive\) in the range for the address. |
| Frotigate.Address6.EndIP | String | Final IP address \(inclusive\) in the range for the address. |
| Frotigate.Address6.Country | String | IP addresses associated to a specific country. |
| Frotigate.Address6.MAC | String | MAC addresses. |
| Frotigate.Address6.SDN | String | Software-defined networking. |

#### Command example
```!fortigate-update-firewall-address-ipv6 name=playbook-address-ipv6```
#### Context Example
```json
{
    "Fortigate": {
        "Address6": {
            "Name": "playbook-address-ipv6"
        }
    }
}
```

#### Human Readable Output

>## The firewall address 'playbook-address-ipv6' was successfully updated.

### fortigate-delete-firewall-address-ipv6

***
Delete firewall IPv6 addresses. Addresses define sources and destinations of network traffic and can be used in many functions such as firewall policies, ZTNA, etc.

#### Base Command

`fortigate-delete-firewall-address-ipv6`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address to delete. Names can be retrieved with the command `fortigate-list-firewall-address-ipv6s`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Address6.Name | String | The name of the address. |
| Fortigate.Address6.Deleted | Boolean | Whether the address was deleted. |

#### Command example
```!fortigate-delete-firewall-address-ipv6 name=playbook-address-ipv6```
#### Context Example
```json
{
    "Fortigate": {
        "Address6": {
            "Deleted": true,
            "Name": "playbook-address-ipv6"
        }
    }
}
```

#### Human Readable Output

>## The firewall address 'playbook-address-ipv6' was successfully deleted.

### fortigate-list-firewall-address-ipv4-multicasts

***
Retrieve firewall IPv4 multicast addresses. Multicasting allows a single source to send data to multiple receivers efficiently, conserving bandwidth and minimizing network traffic. It is suitable for media streaming, news feeds, financial updates, and certain dynamic routing protocols like RIPv2, OSPF, and EIGRP.

#### Base Command

`fortigate-list-firewall-address-ipv4-multicasts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of a specific address to return. | Optional |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/221620/config-firewall-multicast-address`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/221620/config-firewall-multicast-address`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.AddressMulticast.Tagging | String | List of tags associated to the object. |
| Fortigate.AddressMulticast.AssociatedInterface | String | Network interface associated with address. |
| Fortigate.AddressMulticast.Comment | String | The object\`s comment. |
| Fortigate.AddressMulticast.EndIP | String | Final IP address \(inclusive\) in the range for the address. |
| Fortigate.AddressMulticast.StartIP | String | First IP address \(inclusive\) in the range for the address. |
| Fortigate.AddressMulticast.Subnet | String | Broadcast address and subnet. |
| Fortigate.AddressMulticast.Type | String | Type of the address multicast. Can be: \`multicastrange\` or \`broadcastmask\`. |
| Fortigate.AddressMulticast.Name | String | Address multicast name. |
| Fortigate.AddressMulticast.VDOM | String | Virtual domains \(VDOMs\) enable you to partition and use your FortiGate unit as if it were multiple units. |

#### Command example
```!fortigate-list-firewall-address-ipv4-multicasts name=playbook-address-ipv4-multicast```
#### Context Example
```json
{
    "Fortigate": {
        "AddressMulticast": {
            "AssociatedInterface": "",
            "Comment": "",
            "Name": "playbook-address-ipv4-multicast",
            "Subnet": "0.0.0.0-0.0.0.0",
            "Type": "broadcastmask",
            "VDOM": "root"
        }
    }
}
```

#### Human Readable Output

>### Firewall Address IPv4 Multicasts
>|Name|Details|Type|
>|---|---|---|
>| playbook-address-ipv4-multicast | 0.0.0.0-0.0.0.0 | broadcastmask |


### fortigate-create-firewall-address-ipv4-multicast

***
Create firewall IPv4 multicast addresses. Multicasting allows a single source to send data to multiple receivers efficiently, conserving bandwidth and minimizing network traffic. It`s suitable for media streaming, news feeds, financial updates, and certain dynamic routing protocols like RIPv2, OSPF, and EIGRP.

#### Base Command

`fortigate-create-firewall-address-ipv4-multicast`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| name | Name of the address multicast to create. | Required |
| comment | A comment for the address. | Optional |
| associated_interface | Network interface associated with address. | Optional |
| type | Specifies the format of the multicast address. Possible values are: Broadcast Subnet, Multicast IP Range. | Required |
| first_ip | For `Broadcast Subnet`, this is the network address. For `Multicast IP Range`, (inclusive) this is the beginning of the IP range. | Required |
| final_ip | For `Broadcast Subnet` this should be the network mask as an IP address. For `Multicast IP Range`, (inclusive) this is the end of the IP range. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.AddressMulticast.Name | String | The name of the updated address multicast. |
| Frotigate.AddressMulticast.Type | String | Specifies the format of the multicast address. |
| Frotigate.AddressMulticast.FirstIP | String | First input IP address. |
| Frotigate.AddressMulticast.FinalIP | String | Final input IP address. |

#### Command example
```!fortigate-create-firewall-address-ipv4-multicast name=playbook-address-ipv4-multicast type="Broadcast Subnet" first_ip=0.0.0.0 final_ip=0.0.0.0```
#### Context Example
```json
{
    "Fortigate": {
        "AddressMulticast": {
            "FinalIP": "0.0.0.0",
            "FirstIP": "0.0.0.0",
            "Name": "playbook-address-ipv4-multicast",
            "Type": "Broadcast Subnet"
        }
    }
}
```

#### Human Readable Output

>## The firewall address multicast IPv4 'playbook-address-ipv4-multicast' was successfully created.

### fortigate-update-firewall-address-ipv4-multicast

***
Update firewall IPv4 multicast addresses. Multicasting allows a single source to send data to multiple receivers efficiently, conserving bandwidth and minimizing network traffic. It`s suitable for media streaming, news feeds, financial updates, and certain dynamic routing protocols like RIPv2, OSPF, and EIGRP.

#### Base Command

`fortigate-update-firewall-address-ipv4-multicast`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| name | Name of the address multicast to update. Names can be retrieved with the command `fortigate-list-firewall-address-ipv4-multicasts`. | Required |
| comment | A comment for the address. | Optional |
| associated_interface | Network interface associated with address. | Optional |
| type | Specifies the format of the multicast address. Possible values are: Broadcast Subnet, Multicast IP Range. | Optional |
| first_ip | For 'Broadcast Subnet', this is the network address. For 'Multicast IP Range', (inclusive) this is the beginning of the IP range. | Optional |
| final_ip | For 'Broadcast Subnet' this should be the network mask as an IP address. For `Multicast IP Range`, (inclusive) this is the end of the IP range. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.AddressMulticast.Name | String | The name of the updated address multicast. |
| Frotigate.AddressMulticast.Type | String | Specifies the format of the multicast address. |
| Frotigate.AddressMulticast.FirstIP | String | First input IP address. |
| Frotigate.AddressMulticast.FinalIP | String | Final input IP address. |

#### Command example
```!fortigate-update-firewall-address-ipv4-multicast name=playbook-address-ipv4-multicast comment=helloworld```
#### Context Example
```json
{
    "Fortigate": {
        "AddressMulticast": {
            "Name": "playbook-address-ipv4-multicast"
        }
    }
}
```

#### Human Readable Output

>## The firewall address multicast IPv4 'playbook-address-ipv4-multicast' was successfully updated.

### fortigate-delete-firewall-address-ipv4-multicast

***
Delete firewall IPv4 multicast addresses. Multicasting allows a single source to send data to multiple receivers efficiently, conserving bandwidth and minimizing network traffic. It is suitable for media streaming, news feeds, financial updates, and certain dynamic routing protocols like RIPv2, OSPF, and EIGRP.

#### Base Command

`fortigate-delete-firewall-address-ipv4-multicast`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address multicast to delete. Names can be retrieved with the command `fortigate-list-firewall-address-ipv4-multicasts`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.AddressMulticast.Name | String | The name of the address multicast. |
| Fortigate.AddressMulticast.Deleted | Boolean | Whether the address multicast was deleted. |

#### Command example
```!fortigate-delete-firewall-address-ipv4-multicast name=playbook-address-ipv4-multicast```
#### Context Example
```json
{
    "Fortigate": {
        "AddressMulticast": {
            "Deleted": true,
            "Name": "playbook-address-ipv4-multicast"
        }
    }
}
```

#### Human Readable Output

>## The firewall address multicast IPv4 'playbook-address-ipv4-multicast' was successfully deleted.

### fortigate-list-firewall-address-ipv6-multicasts

***
Retrieve firewall IPv6 multicast addresses. Multicasting allows a single source to send data to multiple receivers efficiently, conserving bandwidth and minimizing network traffic. It is suitable for media streaming, news feeds, financial updates, and certain dynamic routing protocols like RIPv2, OSPF, and EIGRP.

#### Base Command

`fortigate-list-firewall-address-ipv6-multicasts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of a specific address multicast to return. | Optional |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/224620/config-firewall-multicast-address6`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/224620/config-firewall-multicast-address6`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Address6Multicast.Tagging | String | List of tags associated to the object. |
| Fortigate.Address6Multicast.Comment | String | The object\`s comment. |
| Fortigate.Address6Multicast.IPv6 | String | Broadcast address and subnet. |
| Fortigate.Address6Multicast.Name | String | Address multicast name. |
| Fortigate.Address6Multicast.VDOM | String | Virtual domains \(VDOMs\) enable you to partition and use your FortiGate unit as if it were multiple units. |

#### Command example
```!fortigate-list-firewall-address-ipv6-multicasts name=playbook-address-ipv6-multicast```
#### Context Example
```json
{
    "Fortigate": {
        "Address6Multicast": {
            "Comment": "",
            "IPv6": "ff00::/8",
            "Name": "playbook-address-ipv6-multicast",
            "VDOM": "root"
        }
    }
}
```

#### Human Readable Output

>### Firewall Address IPv6 Multicasts
>|Name|Details|
>|---|---|
>| playbook-address-ipv6-multicast | ff00::/8 |


### fortigate-create-firewall-address-ipv6-multicast

***
Create firewall IPv6 multicast addresses. Multicasting allows a single source to send data to multiple receivers efficiently, conserving bandwidth and minimizing network traffic. It is suitable for media streaming, news feeds, financial updates, and certain dynamic routing protocols like RIPv2, OSPF, and EIGRP.

#### Base Command

`fortigate-create-firewall-address-ipv6-multicast`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| name | Name of the address multicast to create. | Required |
| comment | A comment for the address. | Optional |
| address | IPv6 address prefix. Can be in short form (e.g., 2001:db8::) or long form (e.g., 0000:0000:0000:0000:0000:0000:0000:0000). | Required |
| mask | Subnet mask indicating the prefix length (format: xxx, range: 0-128). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.Address6Multicast.Name | String | The name of the updated address multicast. |
| Frotigate.Address6Multicast.IPAddress | String | The IP address. |
| Frotigate.Address6Multicast.Mask | String | The subnet mask of the address. |

#### Command example
```!fortigate-create-firewall-address-ipv6-multicast name=playbook-address-ipv6-multicast address=ff00:: mask=8```
#### Context Example
```json
{
    "Fortigate": {
        "Address6Multicast": {
            "IPAddress": "ff00::",
            "Mask": "8",
            "Name": "playbook-address-ipv6-multicast"
        }
    }
}
```

#### Human Readable Output

>## The firewall address multicast IPv6 'playbook-address-ipv6-multicast' was successfully created.

### fortigate-update-firewall-address-ipv6-multicast

***
Update firewall IPv6 multicast addresses. Multicasting allows a single source to send data to multiple receivers efficiently, conserving bandwidth and minimizing network traffic. It is suitable for media streaming, news feeds, financial updates, and certain dynamic routing protocols like RIPv2, OSPF, and EIGRP.

#### Base Command

`fortigate-update-firewall-address-ipv6-multicast`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address multicast to update. Names can be retrieved with the command `fortigate-list-firewall-address-ipv6-multicasts`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| comment | A comment for the address. | Optional |
| address | IPv6 address prefix. Can be in short form (e.g., 2001:db8::) or long form (e.g., 0000:0000:0000:0000:0000:0000:0000:0000). | Optional |
| mask | Subnet mask indicating the prefix length (format: xxx, range: 0-128). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.Address6Multicast.Name | String | The name of the updated address multicast. |
| Frotigate.Address6Multicast.IPAddress | String | The IP address. |
| Frotigate.Address6Multicast.Mask | String | The subnet mask of the address. |

#### Command example
```!fortigate-update-firewall-address-ipv6-multicast name=playbook-address-ipv6-multicast comment=helloworld```
#### Context Example
```json
{
    "Fortigate": {
        "Address6Multicast": {
            "Name": "playbook-address-ipv6-multicast"
        }
    }
}
```

#### Human Readable Output

>## The firewall address multicast IPv6 'playbook-address-ipv6-multicast' was successfully updated.

### fortigate-delete-firewall-address-ipv6-multicast

***
Delete firewall IPv6 multicast addresses. Multicasting allows a single source to send data to multiple receivers efficiently, conserving bandwidth and minimizing network traffic. It is suitable for media streaming, news feeds, financial updates, and certain dynamic routing protocols like RIPv2, OSPF, and EIGRP.

#### Base Command

`fortigate-delete-firewall-address-ipv6-multicast`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address multicast to delete. Names can be retrieved with the command `fortigate-list-firewall-address-ipv6-multicasts`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Address6Multicast.Name | String | The name of the address multicast. |
| Fortigate.Address6Multicast.Deleted | Boolean | Whether the address multicast was deleted. |

#### Command example
```!fortigate-delete-firewall-address-ipv6-multicast name=playbook-address-ipv6-multicast```
#### Context Example
```json
{
    "Fortigate": {
        "Address6Multicast": {
            "Deleted": true,
            "Name": "playbook-address-ipv6-multicast"
        }
    }
}
```

#### Human Readable Output

>## The firewall address multicast IPv6 'playbook-address-ipv6-multicast' was successfully deleted.

### fortigate-list-firewall-address-ipv4-groups

***
Retrieve firewall IPv4 address groups. Address groups are designed for ease of use in the administration of the device.

#### Base Command

`fortigate-list-firewall-address-ipv4-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | Name of a specific address group to return. | Optional |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/225620/config-firewall-addrgrp`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/225620/config-firewall-addrgrp`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.AddressGroup.FabricObject | String | Security Fabric global object setting. Can be \`enable\` or \`disable\`. If \`enable\`, the object is set as a security fabric-wide global object, otherwise the object is local to this security fabric member. |
| Frotigate.AddressGroup.AllowRouting | String | Enable/disable use of this address in the static route configuration. |
| Frotigate.AddressGroup.Tagging | String | List of tags associated to the object. |
| Frotigate.AddressGroup.ExcludeMember | String | Address name exclusion member. |
| Frotigate.AddressGroup.Exclude | String | Enable/disable address exclusion. |
| Frotigate.AddressGroup.Comment | String | The object\`s comment. |
| Frotigate.AddressGroup.Member.Name | String | Address objects contained within the group. |
| Frotigate.AddressGroup.UUID | String | Universally Unique Identifier. |
| Frotigate.AddressGroup.Category | String | Address group category. \`default\`: Default address group category \(cannot be used as ztna-ems-tag/ztna-geo-tag in policy\). \`ztna-ems-tag\`: Members must be ztna-ems-tag group or ems-tag address. Can be used as ztna-ems-tag in policy. \`ztna-geo-tag\`: Members must be ztna-geo-tag group or geographic address. Can be used as ztna-geo-tag in policy. |
| Frotigate.AddressGroup.Type | String | Address group type. Default address group type \(address may belong to multiple groups\). Address folder group \(members may not belong to any other group\). |
| Frotigate.AddressGroup.Name | String | Address group name. |
| Fortigate.AddressGroup.VDOM | String | Virtual domains \(VDOMs\) enable you to partition and use your FortiGate unit as if it were multiple units. |

#### Command example
```!fortigate-list-firewall-address-ipv4-groups groupName=playbook-address-ipv4-group```
#### Context Example
```json
{
    "Fortigate": {
        "AddressGroup": {
            "AllowRouting": "disable",
            "Category": "default",
            "Comment": "",
            "Exclude": "disable",
            "FabricObject": "disable",
            "Member": {
                "Name": [
                    "playbook-address-ipv4-1"
                ]
            },
            "Name": "playbook-address-ipv4-group",
            "Type": "default",
            "UUID": "e7adb0ca-aa22-51ee-b304-c7fc8ce5e274",
            "VDOM": "root"
        }
    }
}
```

#### Human Readable Output

>### Firewall Address IPv4 Groups
>|Name|Details|Type|Routable|
>|---|---|---|---|
>| playbook-address-ipv4-group | playbook-address-ipv4-1 | default | disable |


### fortigate-create-firewall-address-ipv4-group

***
Create firewall IPv4 address groups. Address groups are designed for ease of use in the administration of the device.

#### Base Command

`fortigate-create-firewall-address-ipv4-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| groupName | Name of the address group to create. | Required |
| type | Address group type. `group`: Default address group type (address may belong to multiple groups). `folder`: Address folder group (members may not belong to any other group). Possible values are: group, folder. Default is group. | Optional |
| address | Comma-separated list of address names. Names can be retrieved with the commands `fortigate-list-firewall-address-ipv4s`, `fortigate-list-firewall-address-ipv4-multicasts` and `fortigate-list-firewall-address-ipv4-groups`. | Optional |
| excluded_addresses | Comma-separated list of address names to exclude. Names can be retrieved with the commands `fortigate-list-firewall-address-ipv4s`, `fortigate-list-firewall-address-ipv4-multicasts` and `fortigate-list-firewall-address-ipv4-groups`. | Optional |
| allow_routing | Enable/disable use of this address in the static route configuration. Possible values are: enable, disable. | Optional |
| comment | A comment for the address group. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.AddressGroup.Name | String | The address group name. |
| Fortigate.AddressGroup.Address | String | The address group members. |

#### Command example
```!fortigate-create-firewall-address-ipv4-group groupName=playbook-address-ipv4-group address=playbook-address-ipv4-1```
#### Context Example
```json
{
    "Fortigate": {
        "AddressGroup": {
            "Address": "playbook-address-ipv4-1",
            "Name": "playbook-address-ipv4-group"
        }
    }
}
```

#### Human Readable Output

>## The firewall address IPv4 group 'playbook-address-ipv4-group' was successfully created.

### fortigate-update-firewall-address-ipv4-group

***
Update firewall IPv4 address groups. Address groups are designed for ease of use in the administration of the device. New members will override the existing members within the group incase of a conflict.

#### Base Command

`fortigate-update-firewall-address-ipv4-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| groupName | Name of the address group to update. Names can be retrieved with the command `fortigate-list-firewall-address-ipv4-groups`. | Required |
| address | Comma-separated list of address names. Names can be retrieved with the commands `fortigate-list-firewall-address-ipv4s`, `fortigate-list-firewall-address-ipv4-multicasts` and `fortigate-list-firewall-address-ipv4-groups`. | Optional |
| excluded_addresses | Comma-separated list of address names to exclude. Names can be retrieved with the commands `fortigate-list-firewall-address-ipv4s`, `fortigate-list-firewall-address-ipv4-multicasts` and `fortigate-list-firewall-address-ipv4-groups`. | Optional |
| allow_routing | Enable/disable use of this address in the static route configuration. Possible values are: enable, disable. | Optional |
| comment | A comment for the address group. | Optional |
| action | Whether to add or remove members or excluded_members from address group. Possible values are: add, remove. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.AddressGroup.Name | String | The address group name. |
| Fortigate.AddressGroup.Address.Name | String | The address group members. |
| Frotigate.AddressGroup.UUID | String | Universally Unique Identifier. |

#### Command example
```!fortigate-update-firewall-address-ipv4-group groupName=playbook-address-ipv4-group address=playbook-address-ipv4-2 action=add```
#### Context Example
```json
{
    "Fortigate": {
        "AddressGroup": {
            "Address": {
                "Name": [
                    "playbook-address-ipv4-1",
                    "playbook-address-ipv4-2"
                ]
            },
            "Name": "playbook-address-ipv4-group",
            "UUID": "e7adb0ca-aa22-51ee-b304-c7fc8ce5e274"
        }
    }
}
```

#### Human Readable Output

>## The firewall address IPv4 group 'playbook-address-ipv4-group' was successfully updated.

### fortigate-delete-firewall-address-ipv4-group

***
Delete firewall IPv4 address groups. Address groups are designed for ease of use in the administration of the device.

#### Base Command

`fortigate-delete-firewall-address-ipv4-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address group to delete. Names can be retrieved with the command `fortigate-list-firewall-address-ipv4-groups`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.AddressGroup.Name | String | The name of the address group. |
| Fortigate.AddressGroup.Deleted | Boolean | Whether the address group was deleted. |

#### Command example
```!fortigate-delete-firewall-address-ipv4-group name=playbook-address-ipv4-group```
#### Context Example
```json
{
    "Fortigate": {
        "AddressGroup": {
            "Deleted": true,
            "Name": "playbook-address-ipv4-group"
        }
    }
}
```

#### Human Readable Output

>## The firewall address IPv4 group 'playbook-address-ipv4-group' was successfully deleted.

### fortigate-list-firewall-address-ipv6-groups

***
Retrieve firewall IPv6 address groups. Address groups are designed for ease of use in the administration of the device.

#### Base Command

`fortigate-list-firewall-address-ipv6-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of a specific address group to return. | Optional |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/226620/config-firewall-addrgrp6`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/226620/config-firewall-addrgrp6`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Frotigate.Address6Group.FabricObject | String | Security Fabric global object setting. Can be \`enable\` or \`disable\`. If \`enable\`, the object is set as a security fabric-wide global object, otherwise the object is local to this security fabric member. |
| Frotigate.Address6Group.Tagging | String | List of tags associated to the object. |
| Frotigate.Address6Group.Member.Name | String | Address objects contained within the group. |
| Frotigate.Address6Group.Comment | String | The object\`s comment. |
| Frotigate.Address6Group.UUID | String | Universally Unique Identifier. |
| Frotigate.Address6Group.Name | String | Address group name. |
| Fortigate.Address6Group.VDOM | String | Virtual domains \(VDOMs\) enable you to partition and use your FortiGate unit as if it were multiple units. |

#### Command example
```!fortigate-list-firewall-address-ipv6-groups name=playbook-address-ipv6-group```
#### Context Example
```json
{
    "Fortigate": {
        "Address6Group": {
            "Comment": "",
            "FabricObject": "disable",
            "Name": "playbook-address-ipv6-group",
            "UUID": "ecd06d9a-aa22-51ee-a0a1-29b8ccdf7714",
            "VDOM": "root"
        }
    }
}
```

#### Human Readable Output

>### Firewall Address IPv6 Groups
>|Name|
>|---|
>| playbook-address-ipv6-group |


### fortigate-create-firewall-address-ipv6-group

***
Create firewall IPv6 address groups. Address groups are designed for ease of use in the administration of the device.

#### Base Command

`fortigate-create-firewall-address-ipv6-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| name | Name of the address group to create. | Required |
| members | Comma-separated list of address names. Names can be retrieved with the commands `fortigate-list-firewall-address-ipv6s`, `fortigate-list-firewall-address-ipv6-multicasts` and `fortigate-list-firewall-address-ipv6-groups`. | Optional |
| comment | A comment for the address group. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Address6Group.Name | String | The address group name. |
| Fortigate.Address6Group.Address | String | The address group members. |

#### Command example
```!fortigate-create-firewall-address-ipv6-group name=playbook-address-ipv6-group```
#### Context Example
```json
{
    "Fortigate": {
        "Address6Group": {
            "Address": null,
            "Name": "playbook-address-ipv6-group"
        }
    }
}
```

#### Human Readable Output

>## The firewall address IPv6 group 'playbook-address-ipv6-group' was successfully created.

### fortigate-update-firewall-address-ipv6-group

***
Update firewall IPv6 address groups. Address groups are designed for ease of use in the administration of the device. New members will override the existing members within the group incase of a conflict.

#### Base Command

`fortigate-update-firewall-address-ipv6-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| name | Name of the address group to update. Names can be retrieved with the command `fortigate-list-firewall-address-ipv6-groups`. | Required |
| members | Comma-separated list of address names. Names can be retrieved with the commands `fortigate-list-firewall-address-ipv6s`, `fortigate-list-firewall-address-ipv6-multicasts` and `fortigate-list-firewall-address-ipv6-groups`. | Optional |
| comment | A comment for the address group. | Optional |
| action | Whether to add or remove members from address group. Possible values are: add, remove. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Address6Group.Name | String | The address group name. |
| Fortigate.Address6Group.Address | String | The address group members. |

#### Command example
```!fortigate-update-firewall-address-ipv6-group name=playbook-address-ipv6-group members=playbook-address-ipv6-1 action=add```
#### Context Example
```json
{
    "Fortigate": {
        "Address6Group": {
            "Address": {
                "Name": [
                    "playbook-address-ipv6-1"
                ]
            },
            "Name": "playbook-address-ipv6-group"
        }
    }
}
```

#### Human Readable Output

>## The firewall address IPv6 group 'playbook-address-ipv6-group' was successfully updated.

### fortigate-delete-firewall-address-ipv6-group

***
Delete firewall IPv6 address groups. Address groups are designed for ease of use in the administration of the device.

#### Base Command

`fortigate-delete-firewall-address-ipv6-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the address group to delete. Names can be retrieved with the command `fortigate-list-firewall-address-ipv6-groups`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Address6Group.Name | String | The name of the deleted address group. |
| Fortigate.Address6Group.Deleted | Boolean | Whether the address group was deleted. |

#### Command example
```!fortigate-delete-firewall-address-ipv6-group name=playbook-address-ipv6-group```
#### Context Example
```json
{
    "Fortigate": {
        "Address6Group": {
            "Deleted": true,
            "Name": "playbook-address-ipv6-group"
        }
    }
}
```

#### Human Readable Output

>## The firewall address IPv6 group 'playbook-address-ipv6-group' was successfully deleted.

### fortigate-list-firewall-services

***
Retrieve firewall services. A service is the combination of network protocols and port numbers that define traffic sources or destinations.

#### Base Command

`fortigate-list-firewall-services`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serviceName | Name of a specific service to return. | Optional |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/231620/config-firewall-service-custom`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/231620/config-firewall-service-custom`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Service.FabricObject | String | Security Fabric global object setting. Can be \`enable\` or \`disable\`. If \`enable\`, the object is set as a security fabric-wide global object, otherwise the object is local to this security fabric member. |
| Fortigate.Service.Application | Number | The application ID. |
| Fortigate.Service.AppCategory | Number | Application category ID. |
| Fortigate.Service.AppServiceType | String | Application service type. Can be: \`disable\`, \`app-id\` or \`app-category\`. |
| Fortigate.Service.Comment | String | The object\`s comment. |
| Fortigate.Service.CheckResetRange | String | The configuration type of ICMP error message verification. |
| Fortigate.Service.SessionTTL | String | Session time to live. |
| Fortigate.Service.UDPIdleTimer | Number | Number of seconds before an idle UDP connection times out. |
| Fortigate.Service.TCPRSTTimer | Number | Set the length of the TCP CLOSE state in seconds. |
| Fortigate.Service.TCPTimewaitTimer | Number | Set the length of the TCP TIME-WAIT state in seconds. |
| Fortigate.Service.TCPHalfopenTimer | Number | Wait time to close a TCP session waiting for an unanswered open session packet. |
| Fortigate.Service.TCPHalfcloseTimer | Number | Wait time to close a TCP session waiting for an unanswered open session packet. |
| Fortigate.Service.Ports.SCTP | String | Multiple SCTP port ranges. |
| Fortigate.Service.Ports.UDP | String | Multiple UDP port ranges. |
| Fortigate.Service.Ports.TCP | String | Multiple TCP port ranges. |
| Fortigate.Service.FQDN | String | Fully Qualified Domain Name address. |
| Fortigate.Service.IPRange | String | Start and end of the IP range associated with the service. |
| Fortigate.Service.Helper | String | Helper protocol name. |
| Fortigate.Service.Protocol | String | Protocol type based on IANA numbers. |
| Fortigate.Service.Category | String | The service category. |
| Fortigate.Service.Proxy | String | Enable/disable web proxy service. |
| Fortigate.Service.Name | String | The service name. |
| Fortigate.Service.ICMPCode | Number | ICMP code. |
| Fortigate.Service.ICMPType | Number | ICMP type. |
| Fortigate.Service.ProtocolNumber | Number | IP protocol number. |
| Fortigate.Service.VDOM | String | Virtual domains \(VDOMs\) enable you to partition and use your FortiGate unit as if it were multiple units. |

#### Command example
```!fortigate-list-firewall-services serviceName=playbook-service```
#### Context Example
```json
{
    "Fortigate": {
        "Service": {
            "AppServiceType": "disable",
            "Category": "",
            "CheckResetRange": "default",
            "Comment": "",
            "FQDN": "",
            "FabricObject": "disable",
            "Helper": "auto",
            "IPRange": "0.0.0.0",
            "Name": "playbook-service",
            "Ports": {
                "SCTP": "5-6",
                "TCP": "1-2",
                "UDP": "3-4"
            },
            "Protocol": "TCP/UDP/SCTP",
            "Proxy": "disable",
            "SessionTTL": "0",
            "TCPHalfcloseTimer": 0,
            "TCPHalfopenTimer": 0,
            "TCPRSTTimer": 0,
            "TCPTimewaitTimer": 0,
            "UDPIdleTimer": 0,
            "VDOM": "root"
        }
    }
}
```

#### Human Readable Output

>### Firewall Services
>|Name|Details|IP/FQDN|Protocol|
>|---|---|---|---|
>| playbook-service | TCP/1-2 UDP/3-4 SCTP/5-6 | 0.0.0.0 | TCP/UDP/SCTP |


### fortigate-create-firewall-service

***
Create firewall services. A service is the combination of network protocols and port numbers that define traffic sources or destinations. The command parameters can be used only in the following combinations: All-[vdom,name,comment,category], TCP/UDP/SCTP-[(start_ip,end_ip or fqdn),tcpRange,udpRange,sctpRange], IP-[ip_protocol], ICMP/ICMP6-[icmp_version,icmp_code,icmp_type].

#### Base Command

`fortigate-create-firewall-service`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| serviceName | Name of the service to create. | Required |
| comment | A comment for the service. | Optional |
| category | Service category. | Optional |
| start_ip | Start of the IP range associated with the service. | Optional |
| end_ip | End of the IP range associated with the service. | Optional |
| fqdn | Fully Qualified Domain Name address. | Optional |
| tcpRange | Comma-separated list of TCP ports. Must be in the following template: {single} for example 5, {start}-{end} for example 1-50 or {start_source}-{end_source}:{start_destination}-{end_destinatinon} for example 1-3:6-9. | Optional |
| udpRange | Comma-separated list of TCP ports. Must be in the following template: {single} for example 5, {start}-{end} for example 1-50 or {start_source}-{end_source}:{start_destination}-{end_destinatinon} for example 1-3:6-9. | Optional |
| sctpRange | Comma-separated list of TCP ports. Must be in the following template: {single} for example 5, {start}-{end} for example 1-50 or {start_source}-{end_source}:{start_destination}-{end_destinatinon} for example 1-3:6-9. | Optional |
| icmp_type | Specifies the ICMP message type, defining the purpose or condition of the message. | Optional |
| icmp_code | Identifies the variant or additional information for the corresponding ICMP message type. | Optional |
| icmp_version | Determines the version of the Internet Control Message Protocol, either ICMP or ICMP6. Possible values are: ICMP, ICMP6. | Optional |
| ip_protocol | IP protocol number. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Service.Ports.SCTP | String | Multiple SCTP port ranges. |
| Fortigate.Service.Ports.UDP | String | Multiple UDP port ranges. |
| Fortigate.Service.Ports.TCP | String | Multiple TCP port ranges. |
| Fortigate.Service.FQDN | String | Fully Qualified Domain Name address. |
| Fortigate.Service.StartIP | String | Start of the IP range associated with the service. |
| Fortigate.Service.EndIP | String | End of the IP range associated with the service. |
| Fortigate.Service.ICMPCode | Number | ICMP code. |
| Fortigate.Service.ICMPType | Number | ICMP type. |
| Fortigate.Service.ProtocolNumber | Number | IP protocol number. |
| Fortigate.Service.Name | String | The service name. |

#### Command example
```!fortigate-create-firewall-service serviceName=playbook-service tcpRange=1-2 udpRange=3-4 sctpRange=5-6```
#### Context Example
```json
{
    "Fortigate": {
        "Service": {
            "Name": "playbook-service",
            "Ports": {
                "SCTP": "5-6",
                "TCP": "1-2",
                "UDP": "3-4"
            }
        }
    }
}
```

#### Human Readable Output

>## The firewall service 'playbook-service' was successfully created.

### fortigate-update-firewall-service

***
Update firewall services. A service is the combination of network protocols and port numbers that define traffic sources or destinations. The command parameters can be used only in the following combinations: All-[vdom,name,comment,category], TCP/UDP/SCTP-[(start_ip,end_ip or fqdn),tcpRange,udpRange,sctpRange], IP-[ip_protocol], ICMP/ICMP6-[icmp_version,icmp_code,icmp_type].

#### Base Command

`fortigate-update-firewall-service`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| name | Name of the service to update. Names can be retrieved with the command `fortigate-list-firewall-services`. | Required |
| comment | A comment for the service. | Optional |
| category | Service category. | Optional |
| start_ip | Start of the IP range associated with the service. | Optional |
| end_ip | End of the IP range associated with the service. | Optional |
| fqdn | Fully Qualified Domain Name address. | Optional |
| tcpRange | Comma-separated list of TCP ports. Must be in the following template: {single} for example 5, {start}-{end} for example 1-50 or {start_source}-{end_source}:{start_destination}-{end_destinatinon} for example 1-3:6-9. | Optional |
| udpRange | Comma-separated list of TCP ports. Must be in the following template: {single} for example 5, {start}-{end} for example 1-50 or {start_source}-{end_source}:{start_destination}-{end_destinatinon} for example 1-3:6-9. | Optional |
| sctpRange | Comma-separated list of TCP ports. Must be in the following template: {single} for example 5, {start}-{end} for example 1-50 or {start_source}-{end_source}:{start_destination}-{end_destinatinon} for example 1-3:6-9. | Optional |
| action | Whether to add or remove destination and source ports from TCP/UDP/SCTP. Possible values are: add, remove. | Optional |
| icmp_type | Specifies the ICMP message type, defining the purpose or condition of the message. | Optional |
| icmp_code | Identifies the variant or additional information for the corresponding ICMP message type. | Optional |
| icmp_version | Determines the version of the Internet Control Message Protocol, either ICMPv4 or ICMPv6. Possible values are: icmp4, icmp6. | Optional |
| ip_protocol | IP protocol number. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Service.Ports.SCTP | String | Multiple SCTP port ranges. |
| Fortigate.Service.Ports.UDP | String | Multiple UDP port ranges. |
| Fortigate.Service.Ports.TCP | String | Multiple TCP port ranges. |
| Fortigate.Service.FQDN | String | Fully Qualified Domain Name address. |
| Fortigate.Service.IPRange | String | Start and end of the IP range associated with the service. |
| Fortigate.Service.ICMPCode | Number | ICMP code. |
| Fortigate.Service.ICMPType | Number | ICMP type. |
| Fortigate.Service.ProtocolNumber | Number | IP protocol number. |
| Fortigate.Service.Name | String | The service name. |

#### Command example
```!fortigate-update-firewall-service name=playbook-service comment=helloworld```
#### Context Example
```json
{
    "Fortigate": {
        "Service": {
            "Name": "playbook-service",
            "Ports": {
                "SCTP": "",
                "TCP": "",
                "UDP": ""
            }
        }
    }
}
```

#### Human Readable Output

>## The firewall service 'playbook-service' was successfully updated.

### fortigate-delete-firewall-service

***
Delete firewall services. A service is the combination of network protocols and port numbers that define traffic sources or destinations.

#### Base Command

`fortigate-delete-firewall-service`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the service to delete. Names can be retrieved with the command `fortigate-list-firewall-services`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Service.Name | String | The name of the deleted service. |
| Fortigate.Service.Deleted | Boolean | Whether the service was deleted. |

#### Command example
```!fortigate-delete-firewall-service name=playbook-service```
#### Context Example
```json
{
    "Fortigate": {
        "Service": {
            "Deleted": true,
            "Name": "playbook-service"
        }
    }
}
```

#### Human Readable Output

>## The firewall service 'playbook-service' was successfully deleted.

### fortigate-list-firewall-service-groups

***
Retrieve firewall service groups. Service groups are collections of predefined services. Service groups can be used as the source and destination of the policy.

#### Base Command

`fortigate-list-firewall-service-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of a specific service group to return. | Optional |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/232620/config-firewall-service-group`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/232620/config-firewall-service-group`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.ServiceGroup.FabricObject | String | Security Fabric global object setting. Can be \`enable\` or \`disable\`. If \`enable\`, the object is set as a security fabric-wide global object, otherwise the object is local to this security fabric member. |
| Fortigate.ServiceGroup.Comment | String | The object\`s comment. |
| Fortigate.ServiceGroup.Proxy | String | Enable/disable web proxy service. |
| Fortigate.ServiceGroup.Name | String | The service group name. |
| Frotigate.ServiceGroup.Member.Name | String | Service objects contained within the group. |
| Fortigate.ServiceGroup.VDOM | String | Virtual domains \(VDOMs\) enable you to partition and use your FortiGate unit as if it were multiple units. |

#### Command example
```!fortigate-list-firewall-service-groups name=playbook-service-group```
#### Context Example
```json
{
    "Fortigate": {
        "ServiceGroup": {
            "Comment": "",
            "FabricObject": "disable",
            "Member": {
                "Name": [
                    "playbook-service-1"
                ]
            },
            "Name": "playbook-service-group",
            "Proxy": "disable",
            "VDOM": "root"
        }
    }
}
```

#### Human Readable Output

>### Firewall Service Groups
>|Name|Members|
>|---|---|
>| playbook-service-group | playbook-service-1 |


### fortigate-create-firewall-service-group

***
Create firewall service groups. Service groups are collections of predefined services. Service groups can be used as the source and destination of the policy.

#### Base Command

`fortigate-create-firewall-service-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| name | Name of the service group to create. | Required |
| comment | A comment for the service group. | Optional |
| members | Comma-separated list of service and service group names. Names can be retrieved with the commands `fortigate-list-firewall-services` and `fortigate-list-firewall-service-groups`. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.ServiceGroup.Name | String | The service group name. |
| Fortigate.ServiceGroup.Members | String | Service objects contained within the group. |

#### Command example
```!fortigate-create-firewall-service-group name=playbook-service-group members=playbook-service-1```
#### Context Example
```json
{
    "Fortigate": {
        "ServiceGroup": {
            "Members": "playbook-service-1",
            "Name": "playbook-service-group"
        }
    }
}
```

#### Human Readable Output

>## The firewall service group 'playbook-service-group' was successfully created.

### fortigate-update-firewall-service-group

***
Update firewall service groups. Service groups are collections of predefined services. Service groups can be used as the source and destination of the policy. New members will override the existing members within the group incase of a conflict.

#### Base Command

`fortigate-update-firewall-service-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| groupName | Name of the service group to update. Names can be retrieved with the command `fortigate-list-firewall-service-groups`. | Required |
| comment | A comment for the service group. | Optional |
| serviceName | Comma-separated list of service and service group names. Names can be retrieved with the commands `fortigate-list-firewall-services` and `fortigate-list-firewall-service-groups`. | Optional |
| action | Whether to add or remove members from the service group. Possible values are: add, remove. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.ServiceGroup.Name | String | The service group name. |
| Fortigate.ServiceGroup.Service.Name | String | Service objects contained within the group. |

#### Command example
```!fortigate-update-firewall-service-group groupName=playbook-service-group comment=helloworld```
#### Context Example
```json
{
    "Fortigate": {
        "ServiceGroup": {
            "Name": "playbook-service-group",
            "Service": {
                "Name": [
                    "playbook-service-1"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>## The firewall service group 'playbook-service-group' was successfully updated.

### fortigate-delete-firewall-service-group

***
Delete firewall service groups. Service groups are collections of predefined services. Service groups can be used as the source and destination of the policy.

#### Base Command

`fortigate-delete-firewall-service-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupName | Name of the service group to delete. Names can be retrieved with the command `fortigate-list-firewall-service-groups`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.ServiceGroup.Name | String | The name of the deleted service group. |
| Fortigate.ServiceGroup.Deleted | Boolean | Whether the service group was deleted. |

#### Command example
```!fortigate-delete-firewall-service-group groupName=playbook-service-group```
#### Context Example
```json
{
    "Fortigate": {
        "ServiceGroup": {
            "Deleted": true,
            "Name": "playbook-service-group"
        }
    }
}
```

#### Human Readable Output

>## The firewall service group 'playbook-service-group' was successfully deleted.

### fortigate-list-firewall-policies

***
Retrieve firewall policies. Firewall policies dictate the traffic flow and its processing. They are integral to most of the firewall functions, ensuring that every piece of traffic passing through the unit adheres to a specific policy. These policies determine the direction of the traffic, processing method, and its permission to traverse the firewall.

#### Base Command

`fortigate-list-firewall-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyID | ID of a specific policy to return. | Optional |
| policyName | Name of a specific policy to return. | Optional |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/287620/config-firewall-policy`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/287620/config-firewall-policy`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Policy.ServiceNegate | String | When enabled specifies what the service must not be. |
| Fortigate.Policy.Destination6Negate | String | When enabled, specifies what the destination IPv6 address must not be. |
| Fortigate.Policy.DestinationNegate | String | When enabled, specifies what the destination IPv4 address must not be. |
| Fortigate.Policy.Source6Negate | String | When enabled, specifies what the source IPv6 address must not be. |
| Fortigate.Policy.SourceNegate | String | When enabled, specifies what the source IPv4 address must not be. |
| Fortigate.Policy.NAT | String | Whether the source NAT is enabled or disabled. |
| Fortigate.Policy.LogStart | String | Whether recording logs when a session starts is enabled or disabled. |
| Fortigate.Policy.Log | String | All log sessions or security profile sessions. |
| Fortigate.Policy.Service | String | Service and service group names. |
| Fortigate.Policy.Source6 | String | Source IPv6 address name and address group names. |
| Fortigate.Policy.Destination6 | String | Destination IPv6 address name and address group names. |
| Fortigate.Policy.Destination | String | Destination IPv4 address and address group names. |
| Fortigate.Policy.Source | String | Source IPv4 address and address group names. |
| Fortigate.Policy.Action | String | Policy action \(accept/deny/ipsec\). |
| Fortigate.Policy.DestinationInterface | String | Outgoing \(egress\) interface. |
| Fortigate.Policy.SourceInterface | String | Incoming \(ingress\) interface. |
| Fortigate.Policy.UUID | String | Universally Unique Identifier. |
| Fortigate.Policy.Name | String | The policy name. |
| Fortigate.Policy.Status | String | Whether this policy is enabled or disabled. |
| Fortigate.Policy.ID | Number | The policy ID. |
| Fortigate.Policy.Description | String | The policy description. |
| Fortigate.Policy.Security | String | Policy attached security profile. |
| Fortigate.Policy.VDOM | String | Virtual domains \(VDOMs\) enable you to partition and use your FortiGate unit as if it were multiple units. |
| Fortigate.Policy.Schedule | String | The name of the schedule. |

#### Command example
```!fortigate-list-firewall-policies policyName=playbook-policy-123456789```
#### Context Example
```json
{
    "Fortigate": {
        "Policy": {
            "Action": "accept",
            "Description": "",
            "Destination": "playbook-address-ipv4-1",
            "Destination6Negate": "disable",
            "DestinationInterface": [
                "port2"
            ],
            "DestinationNegate": "disable",
            "ID": 18,
            "Log": "utm",
            "LogStart": "disable",
            "NAT": "enable",
            "Name": "playbook-policy-123456789",
            "Schedule": "always",
            "Security": [
                "no-inspection",
                "default",
                "single"
            ],
            "Service": [
                "playbook-service-1"
            ],
            "ServiceNegate": "disable",
            "Source": "playbook-address-ipv4-1",
            "Source6Negate": "disable",
            "SourceInterface": [
                "port1"
            ],
            "SourceNegate": "disable",
            "Status": "enable",
            "UUID": "cb72f302-aa22-51ee-eef0-cce9ba5b7ad3",
            "VDOM": "root"
        }
    }
}
```

#### Human Readable Output

>### Firewall Policies
>|ID|Name|From|To|Source|Destination|Schedule|Service|Action|NAT|Security Profiles|Log|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 18 | playbook-policy-123456789 | port1 | port2 | playbook-address-ipv4-1 | playbook-address-ipv4-1 | always | playbook-service-1 | accept | enable | no-inspection,<br/>default,<br/>single | utm |


### fortigate-create-firewall-policy

***
Create firewall policies. Firewall policies dictate the traffic flow and its processing. They are integral to most of the firewall functions, ensuring that every piece of traffic passing through the unit adheres to a specific policy. These policies determine the direction of the traffic, processing method, and its permission to traverse the firewall.

#### Base Command

`fortigate-create-firewall-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| policyName | Name of the policy to create. | Required |
| description | The policy description. | Optional |
| sourceIntf | Comma-separated list of incoming (ingress) interfaces. | Required |
| dstIntf | Comma-separated list of outgoing (egress) interfaces. | Required |
| source | Comma-separated list of source IPv4 address and address group names. Names can be retrieved with the commands `fortigate-list-firewall-address-ipv4s`, `fortigate-list-firewall-address-ipv4-multicasts` and `fortigate-list-firewall-address-ipv4-groups`. | Optional |
| source6 | Comma-separated list of source IPv6 address name and address group names. Names can be retrieved with the commands `fortigate-list-firewall-address-ipv6s`, `fortigate-list-firewall-address-ipv6-multicasts` and `fortigate-list-firewall-address-ipv6-groups`. | Optional |
| destination | Comma-separated list of destination IPv4 address and address group names. Names can be retrieved with the commands `fortigate-list-firewall-address-ipv4s`, `fortigate-list-firewall-address-ipv4-multicasts` and `fortigate-list-firewall-address-ipv4-groups`. | Optional |
| destination6 | Comma-separated list of destination IPv6 address name and address group names. Names can be retrieved with the commands `fortigate-list-firewall-address-ipv6s`, `fortigate-list-firewall-address-ipv6-multicasts` and `fortigate-list-firewall-address-ipv6-groups`. | Optional |
| negate_source_address | When enabled, the source address specifies what the source address must not be. Possible values are: enable, disable. | Optional |
| negate_destination_address | When enabled, the destination address specifies what the destination address must not be. Possible values are: enable, disable. | Optional |
| service | Comma-separated list of service and service group names. Names can be retrieved with the commands `fortigate-list-firewall-services` and `fortigate-list-firewall-service-groups`. | Required |
| negate_service | When enabled, the service specifies what the service must not be. Possible values are: enable, disable. | Optional |
| action | Whether to accept or deny sessions that match the firewall policy. Possible values are: accept, block. | Required |
| status | Enable or disable this policy. Possible values are: enable, disable. Default is enable. | Optional |
| log | Enable or disable logging. Log all sessions or security profile sessions. Possible values are: all, utm, disable. Default is enable. | Optional |
| schedule | The schedule name. This is a time frame that is applied to the policy. Default is always. | Optional |
| nat | Enable/disable source Network Address Translation. Possible values are: enable, disable. Default is enable. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Policy.NAT | String | Whether the source NAT is enabled or disabled. |
| Fortigate.Policy.Log | String | All log sessions or security profile sessions. |
| Fortigate.Policy.Service | String | Service and service group names. |
| Fortigate.Policy.Source.Address6.name | String | Source IPv6 address name and address group names. |
| Fortigate.Policy.Destination.Address6.name | String | Destination IPv6 address name and address group names. |
| Fortigate.Policy.Destination.Address.name | String | Destination IPv4 address and address group names. |
| Fortigate.Policy.Source.Address.name | String | Source IPv4 address and address group names. |
| Fortigate.Policy.Action | String | Policy action \(accept/deny/ipsec\). |
| Fortigate.Policy.Destination.Interface | String | Outgoing \(egress\) interface. |
| Fortigate.Policy.Source.Interface | String | Incoming \(ingress\) interface. |
| Fortigate.Policy.Name | String | The policy name. |
| Fortigate.Policy.Status | String | Whether this policy is enabled or disabled. |
| Fortigate.Policy.Description | String | The policy description. |

#### Command example
```!fortigate-create-firewall-policy policyName=playbook-policy sourceIntf=port1 dstIntf=port2 action=accept service=playbook-service-1 source=playbook-address-ipv4-1 destination=playbook-address-ipv4-2```
#### Context Example
```json
{
    "Fortigate": {
        "Policy": {
            "Action": "accept",
            "Description": null,
            "Destination": {
                "Address": [
                    {
                        "name": "playbook-address-ipv4-2"
                    }
                ],
                "Address6": [
                    {
                        "name": ""
                    }
                ],
                "Interface": "port2"
            },
            "Log": "enable",
            "NAT": "enable",
            "Name": "playbook-policy",
            "Service": "playbook-service-1",
            "Source": {
                "Address": [
                    {
                        "name": "playbook-address-ipv4-1"
                    }
                ],
                "Address6": [
                    {
                        "name": ""
                    }
                ],
                "Interface": "port1"
            },
            "Status": "enable"
        }
    }
}
```

#### Human Readable Output

>## The firewall policy 'playbook-policy' was successfully created.

### fortigate-update-firewall-policy

***
Update firewall policies. Firewall policies dictate the traffic flow and its processing. They are integral to most of the firewall functions, ensuring that every piece of traffic passing through the unit adheres to a specific policy. These policies determine the direction of the traffic, processing method, and its permission to traverse the firewall.

#### Base Command

`fortigate-update-firewall-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyID | ID of the policy to update. IDs can be retrieved with the command `fortigate-list-firewall-policies`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| field | Field parameter to update. Possible values are: source_interface, destination_interface, description, status, source, destination, service, schedule, action, log, nat, source6, destination6, negate_source, negate_destination, negate_source6, negate_destination6, negate_service. | Required |
| value | Value of the field parameter to update. | Required |
| keep_original_data | Whether to keep the original data or not. Only relevant if the updated field is "source" or "destination". If the supplied value is `True`, the current data will not be replaced. Instead, the supplied addresses will be added / removed from the existing data. Possible values are: true, false. | Optional |
| add_or_remove | Whether to add or remove the supplied addresses from the existing data. Only relevant in case the field to update is "source" or "destination", and keep_original_data is specified to `True`. Possible values are: add, remove. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Policy.ServiceNegate | String | When enabled, specifies what the service must not be. |
| Fortigate.Policy.Destination6Negate | String | When enabled, specifies what the destination IPv6 address must not be. |
| Fortigate.Policy.DestinationNegate | String | When enabled, specifies what the destination IPv4 address must not be. |
| Fortigate.Policy.Source6Negate | String | When enabled, specifies what the source IPv6 address must not be. |
| Fortigate.Policy.SourceNegate | String | When enabled, specifies what the source IPv4 address must not be. |
| Fortigate.Policy.NAT | String | Whether the source NAT is enabled or disabled. |
| Fortigate.Policy.LogStart | String | Whether recording logs when a session starts is enabled or disabled. |
| Fortigate.Policy.Log | String | All log sessions or security profile sessions. |
| Fortigate.Policy.Service | String | Service and service group names. |
| Fortigate.Policy.Source6 | String | Source IPv6 address name and address group names. |
| Fortigate.Policy.Destination6 | String | Destination IPv6 address name and address group names. |
| Fortigate.Policy.Destination | String | Destination IPv4 address and address group names. |
| Fortigate.Policy.Source | String | Source IPv4 address and address group names. |
| Fortigate.Policy.Action | String | Policy action \(accept/deny/ipsec\). |
| Fortigate.Policy.DestinationInterface | String | Outgoing \(egress\) interface. |
| Fortigate.Policy.SourceInterface | String | Incoming \(ingress\) interface. |
| Fortigate.Policy.UUID | String | Universally Unique Identifier. |
| Fortigate.Policy.Name | String | The policy name. |
| Fortigate.Policy.Status | String | Whether this policy is enabled or disabled. |
| Fortigate.Policy.ID | Number | The policy ID. |
| Fortigate.Policy.Description | String | The policy description. |
| Fortigate.Policy.Security | String | Policy attached security profile. |
| Fortigate.Policy.Schedule | String | The name of the schedule. |

#### Command example
```!fortigate-update-firewall-policy policyID=123456789 field=description value=helloworld```
#### Context Example
```json
{
    "Fortigate": {
        "Policy": {
            "Action": "accept",
            "Description": "helloworld",
            "Destination": "playbook-address-ipv4-2",
            "Destination6Negate": "disable",
            "DestinationInterface": [
                "port2"
            ],
            "DestinationNegate": "disable",
            "ID": 123456789,
            "Log": "utm",
            "LogStart": "disable",
            "NAT": "enable",
            "Name": "playbook-policy-222",
            "Schedule": "always",
            "Security": [
                "no-inspection",
                "default",
                "single"
            ],
            "Service": [
                "playbook-service-1"
            ],
            "ServiceNegate": "disable",
            "Source": "playbook-address-ipv4-1",
            "Source6Negate": "disable",
            "SourceInterface": [
                "port1"
            ],
            "SourceNegate": "disable",
            "Status": "enable",
            "UUID": "8aaa8c5e-aa22-51ee-b28a-472e6447ac59"
        }
    }
}
```

#### Human Readable Output

>## The firewall policy '123456789' was successfully updated.

### fortigate-move-firewall-policy

***
Move the position of firewall policies. Firewall policies dictate the traffic flow and its processing. They are integral to most of the firewall functions, ensuring that every piece of traffic passing through the unit adheres to a specific policy. These policies determine the direction of the traffic, processing method, and its permission to traverse the firewall.

#### Base Command

`fortigate-move-firewall-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyID | ID of the policy to move. IDs can be retrieved with the command `fortigate-list-firewall-policies`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| position | Whether to position the policy before or after its neighbor. Possible values are: before, after. | Required |
| neighbor | The ID of the neighbor policy. IDs can be retrieved with the command `fortigate-list-firewall-policies`. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Policy.ID | Number | The policy ID. |
| Fortigate.Policy.Moved | Boolean | Whether the policy was moved. |

#### Command example
```!fortigate-move-firewall-policy policyID=123456789 position=after neighbor=1010101```
#### Context Example
```json
{
    "Fortigate": {
        "Policy": {
            "ID": "123456789",
            "Moved": true
        }
    }
}
```

#### Human Readable Output

>## The firewall policy '123456789' was successfully moved.

### fortigate-delete-firewall-policy

***
Delete firewall policies. Firewall policies dictate the traffic flow and its processing. They are integral to most of the firewall functions, ensuring that every piece of traffic passing through the unit adheres to a specific policy. These policies determine the direction of the traffic, processing method, and its permission to traverse the firewall.

#### Base Command

`fortigate-delete-firewall-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyID | ID of the policy to delete. IDs can be retrieved with the command `fortigate-list-firewall-policies`. | Required |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.Policy.ID | Number | The policy ID. |
| Fortigate.Policy.Deleted | Boolean | Whether the policy was deleted. |

#### Command example
```!fortigate-delete-firewall-policy policyID=123456789```
#### Context Example
```json
{
    "Fortigate": {
        "Policy": {
            "Deleted": true,
            "ID": "123456789"
        }
    }
}
```

#### Human Readable Output

>## The firewall policy '123456789' was successfully deleted.

### fortigate-list-system-vdoms

***
Retrieve system VDOMs. Virtual Domains (VDOMs) are used to divide a FortiGate into two or more virtual units that function independently. VDOMs can provide separate security policies and, in NAT mode, completely separate configurations for routing and VPN services for each connected network. Multiple VDOMs can be created and managed as independent units in multi VDOM mode.

#### Base Command

`fortigate-list-system-vdoms`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/620/config-system-vdom`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. Reference to possible fields: `https://docs.fortinet.com/document/fortigate/7.2.5/cli-reference/620/config-system-vdom`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.VDOM.VClusterID | Number | Virtual cluster ID. |
| Fortigate.VDOM.ShortName | String | The virtual domain short name. |
| Fortigate.VDOM.Name | String | The virtual domain name. |

#### Command example
```!fortigate-list-system-vdoms```
#### Context Example
```json
{
    "Fortigate": {
        "VDOM": {
            "Name": "root",
            "ShortName": "root",
            "VClusterID": 0,
            "VDOM": "root"
        }
    }
}
```

#### Human Readable Output

>### Virtual Domains
>|Name|ShortName|VClusterID|
>|---|---|---|
>| root | root | 0 |


### fortigate-list-banned-ips

***
Retrieve Banned IPs. Banned IPs are IP addresses that have been quarantined for a variety of reasons, such as administrative decisions or due to security alerts from services like intrusion prevention systems (IPS), antivirus (AV), and denial-of-service (DoS) mitigation.

#### Base Command

`fortigate-list-banned-ips`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| filter_field | Specifies the field to be searched, such as `name` or `comment`, to narrow down the search criteria within the objects. Fields must be written as they are in the `raw_response`. | Optional |
| filter_value | Indicates the value or partial value, for example `Sales`, that the API should look for within the specified field to find matching objects. | Optional |
| format_fields | Comma-separated fields to format the API call to display certain information. Fields must be written as they are in the `raw_response`, for example: `name` or `comment`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortigate.BannedIP.IsV6 | Number | Whether the IP is IPv4 \(0\) or IPv6 \(1\). |
| Fortigate.BannedIP.Source | String | Source of the ban. |
| Fortigate.BannedIP.IP | String | The IPv4 address. |
| Fortigate.BannedIP.Created | Number | Date/time the IP address was added to the banned list. |
| Fortigate.BannedIP.Expires | Number | Date/time the IP address expires from the banned list. |
| Fortigate.BannedIP.VDOM | String | Virtual domains \(VDOMs\) enable you to partition and use your FortiGate unit as if it were multiple units. |

#### Command example
```!fortigate-list-banned-ips```
#### Context Example
```json
{
    "Fortigate": {
        "BannedIP": [
            {
                "Created": "2023-12-06 17:44:09",
                "Expires": "1970-01-01 00:00:00",
                "IP": "0.0.0.0",
                "IsV6": 0,
                "Source": "Administrative",
                "VDOM": "root"
            },
            {
                "Created": "2023-11-27 05:33:32",
                "Expires": "1970-01-01 00:00:00",
                "IP": "2.2.2.2",
                "IsV6": 0,
                "Source": "IPS",
                "VDOM": "root"
            },
            {
                "Created": "2023-11-27 05:33:41",
                "Expires": "1970-01-01 00:00:00",
                "IP": "3.3.3.3",
                "IsV6": 0,
                "Source": "AV",
                "VDOM": "root"
            },
            {
                "Created": "2023-11-27 05:33:49",
                "Expires": "1970-01-01 00:00:00",
                "IP": "4.4.4.4",
                "IsV6": 0,
                "Source": "DOS",
                "VDOM": "root"
            },
            {
                "Created": "2023-11-27 05:34:00",
                "Expires": "1970-01-01 00:00:00",
                "IP": "5.5.5.5",
                "IsV6": 0,
                "Source": "Administrative",
                "VDOM": "root"
            }
        ]
    }
}
```

#### Human Readable Output

>### Banned IPs
>|IP|IsV6|Created|Expires|Source|
>|---|---|---|---|---|
>| 0.0.0.0 | 0 | 2023-12-06 17:44:09 | 1970-01-01 00:00:00 | Administrative |
>| 2.2.2.2 | 0 | 2023-11-27 05:33:32 | 1970-01-01 00:00:00 | IPS |
>| 3.3.3.3 | 0 | 2023-11-27 05:33:41 | 1970-01-01 00:00:00 | AV |
>| 4.4.4.4 | 0 | 2023-11-27 05:33:49 | 1970-01-01 00:00:00 | DOS |
>| 5.5.5.5 | 0 | 2023-11-27 05:34:00 | 1970-01-01 00:00:00 | Administrative |


### fortigate-ban-ip

***
Ban IPs. Banned IPs are IP addresses that have been quarantined for a variety of reasons, such as administrative decisions or due to security alerts from services like intrusion prevention systems (IPS), antivirus (AV), and denial-of-service (DoS) mitigations.

#### Base Command

`fortigate-ban-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| ip_address | Comma-separated list of IPs to ban. Both IPv4 and IPv6 addresses are supported. | Required |
| expiry | Time until the ban expires in seconds. `0` for indefinite ban. Default is 0. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortigate-ban-ip ip_address=0.0.0.0 expiry=0```
#### Human Readable Output

>## The IPs '0.0.0.0' were successfully banned.

### fortigate-unban-ip

***
Unban IPs. Banned IPs are IP addresses that have been quarantined for a variety of reasons, such as administrative decisions or due to security alerts from services like intrusion prevention systems (IPS), antivirus (AV), and denial-of-service (DoS) mitigations.

#### Base Command

`fortigate-unban-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vdom | Virtual domains (VDOMs) enable you to partition and use your FortiGate unit as if it were multiple units. Use `*` to retrieve all virtual domains. VDOMs can be retrieved with the command `fortigate-list-system-vdoms`. Default is root. | Optional |
| ip_address | Comma-separated list of IPs to unban. Both IPv4 and IPv6 addresses are supported. IPs can be retrieved with the command `fortigate-list-banned-ips`. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortigate-unban-ip ip_address=0.0.0.0```
#### Human Readable Output

>## The IPs '0.0.0.0' were successfully unbanned.