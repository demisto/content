Infoblox enables you to receive metadata about IPs in your network and manages the DNS Firewall by configuring RPZs. It defines RPZ rules to block DNS resolution for malicious or unauthorized hostnames, or redirect clients to a walled garden by substituting responses. This integration was integrated and tested with version V2 of Infoblox

Configure Infoblox on XSOAR
---------------------------

##### Required Permissions

The API supports only HTTP Basic Authentication. Every user must have permissions that grants them access to the API.

1.  Navigate to **Settings** > **Integrations**  > **Servers & Services**.
2.  Search for Infoblox.
3.  Click **Add instance** to create and configure a new integration instance.
    * **Name**: a textual name for the integration instance.
    * **Server URL (e.g.,, https://example.net)**
    * **User Name**
    * **Password**
    * **Trust any certificate (not secure)**
    * **Use system proxy settings**
4.  Click **Test** to validate the new instance.

Commands
--------

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1.  [Get IP info: infoblox-get-ip](#infoblox-get-ip).
2.  [Searches IP related objects by a given IP: infoblox-search-related-objects-by-ip](#infoblox-search-related-objects-by-ip).
3.  [Lists all response policy rules that belong to the.g.,ven response policy zone: infoblox-list-response-policy-zone-rules](#infoblox-list-response-policy-zone-rules).
4.  [List all response policy zones: infoblox-list-response-policy-zones](#infoblox-list-response-policy-zones).
5.  [Creates a response policy zone: infoblox-create-response-policy-zone](#infoblox-create-response-policy-zone).
6.  [Creates a response policy rule: infoblox-create-rpz-rule](#infoblox-create-rpz-rule).
7.  [Creates a substitute record rule: infoblox-create-a-substitute-record-rule](#infoblox-create-a-substitute-record-rule).
8.  [Creates a substitute rule for an AAAA record: infoblox-create-aaaa-substitute-record-rule](#infoblox-create-aaaa-substitute-record-rule).
9.  [Creates a substitute rule for the MX record: infoblox-create-mx-substitute-record-rule](#infoblox-create-mx-substitute-record-rule).
10. [Creates a substitute rule for a NAPTR record: infoblox-create-naptr-substitute-record-rule](#infoblox-create-naptr-substitute-record-rule).
11. [Creates a substitute rule of the PTR record: infoblox-create-ptr-substitute-record-rule](#infoblox-create-ptr-substitute-record-rule).
12. [Creates a substitute rule of a SRV record: infoblox-create-srv-substitute-record-rule](#infoblox-create-srv-substitute-record-rule).
13. [Create a substitute rule for a txt record: infoblox-create-txt-substitute-record-rule](#infoblox-create-txt-substitute-record-rule).
14. [Create a substitute rule for an IPv4 rule: infoblox-create-ipv4-substitute-record-rule](#infoblox-create-ipv4-substitute-record-rule).
15. [Creates a substitute of the IPv6 record rule: infoblox-create-ipv6-substitute-record-rule](#infoblox-create-ipv6-substitute-record-rule).
16. [Disables a rule by its reference ID (reference ID can be extracted by running the search rules command): infoblox-enable-rule](#infoblox-enable-rule).
17. [Disable a rule by its reference ID (reference ID can be extracted by running the 'infoblox-search-rule' command): infoblox-disable-rule](#infoblox-disable-rule).
18. [Returns the object fields names which can be used in the search rules command: infoblox-get-object-fields](#infoblox-get-object-fields).
19. [Searches a specific rule by its name: infoblox-search-rule](#infoblox-search-rule).
20. [Deletes a rule: infoblox-delete-rpz-rule](#infoblox-delete-rpz-rule).
21. [Deletes a given response policy zone: infoblox-delete-response-policy-zone](#infoblox-delete-response-policy-zone).
22. [List host information: infoblox-list-host-info](#infoblox-list-host-info).
23. [List network information: infoblox-list-network-info](#infoblox-list-network-info).

### infoblox-get-ip

* * *

Get IP information.

##### Base Command

`infoblox-get-ip`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip  | The IP address for which to retrieve information, e.g.,, "192.168.1.1". Cannot be used in conjunction with `network` or `from/to_ip` arguments. | Optional |
| network  | The network that the IP belongs in FQDN/CIDR format, e.g.,, "192.168.1.0/24". Cannot be used in conjunction with `ip` or `from/to_ip` arguments. | Optional |
| from_ip  | The beginning of the IP range, e.g.,, "192.168.1.0". Must be used in conjunction with `to_ip`. | Optional |
| to_ip  | The end of the IP range, e.g.,, "192.168.1.254". Must be used in conjunction with `from_ip`. | Optional |
| status  | The status of the IP device. Used in conjunction with the `network` or `ip` argument. Possible values are `ACTIVE`, `UNUSED` and `USED`. | Optional |
| extended_attrs  | Comma-separated key/value formatted filter for extended attributes, e.g.,, "Site=New York,OtherProp=MyValue". | Optional |
| max_results  | The maximum results to return. Maximum is 1000. Default is 50. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.IP.ReferenceID | number | Reference ID of the object. |
| Infoblox.IP.MacAddress | string | The Mac address of the IP. |
| Infoblox.IP.Network | string | The network that the IP belongs (in FQDN/CIDR format.) |
| Infoblox.IP.NetworkView | string | The name of the network view. |
| Infoblox.IP.Status | string | The current status of the address. |
| Infoblox.IP.IsConflict | string | Whether the IP address has either a MAC address conflict or a DHCP lease conflict detected through a network discovery (if set to true). |
| Infoblox.IP.Objects | string | The objects associated with the IP address. |
| Infoblox.IP.Types | string | The current status of the address. |
| Infoblox.IP.Names | string | The DNS names. For example, if the IP address belongs to a host record, this field contains the hostname. |
| Infoblox.IP.Extattrs | string | Extra attributes relevant for this object. |
| Infoblox.IP.IpAddress | string | The IP address. |
| Infoblox.IP.Usage | string | Indicates whether the IP address is configured for DNS or DHCP. |

##### Command Example

`!infoblox-get-ip ip="172.0.0.0"`

##### Context Example

```json
{
    "Infoblox.IP": [
        "Extattrs": {},
        "IpAddress": "172.0.0.0",
        "IsConflict": false,
        "MacAddress": "",
        "Names": [],
        "Network": "172.0.0.0/24",
        "NetworkView": "default",
        "Objects": [],
        "ReferenceID": "ipv4address/Li5pcHY0X2FkZHJlc3MkMTcyLjAuMC4wLzA:172.0.0.0",
        "Status": "USED",
        "Types": [
            "NETWORK"
        ],
        "Usage": []
    ]
}
```

##### Human Readable Output

### Infoblox Integration

| **Extattrs** | **Ip Address** | **Is Conflict** | **Mac Address** | **Names** | **Network** | **Network View** | **Objects** | **Reference ID** | **Status** | **Types** | **Usage** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
|     | 172.0.0.0 | false |     |     | 172.0.0.0/24 | default |     | ipv4address/Li5pcHY0X2FkZHJlc3MkMTcyLjAuMC4wLzA:172.0.0.0 | USED | NETWORK |     |

### infoblox-search-related-objects-by-ip

* * *

Searches IP related objects by a given IP.

##### Base Command

`infoblox-search-related-objects-by-ip`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip  | The IP address for which to search. | Required |
| max_results | The maximum results to return. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.IPRelatedObjects.ReferenceID | Unknown | The reference ID of the related object. |

##### Command Example

`!infoblox-search-related-objects-by-ip ip="172.0.0.0"`

##### Context Example

```json
{
    "Infoblox.IPRelatedObjects": [
        {
            "Network": "172.0.0.0/24",
            "NetworkView": "default",
            "ReferenceID": "network/ZG5zLm5ldHdvcmskMTcyLjAuMC4wLzI0LzA:172.0.0.0/24/default"
        }
    ]
}
```

##### Human Readable Output

### Infoblox Integration - IP: 172.0.0.0 search results.

| **Network** | **Network View** | **Reference ID** |
| --- | --- | --- |
| 172.0.0.0/24 | default | network/ZG5zLm5ldHdvcmskMTcyLjAuMC4wLzI0LzA:172.0.0.0/24/default |

### infoblox-list-response-policy-zone-rules

* * *

Lists all response policy rules that belong to the.g.,ven response policy zone.

##### Base Command

`infoblox-list-response-policy-zone-rules`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| response\_policy\_zone_name | The response policy zone name to list the rules (FQDN). | Optional |
| page_size | The number of results in each page. | Optional |
| next\_page\_id | The next page ID that was returned when last running this command. | Optional |
| view | The DNS view in which the records are located. By default, the 'default' DNS view is searched. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ResponsePolicyZoneRulesList.Name | string | Rule name. |
| Infoblox.ResponsePolicyZoneRulesList.Disable | boolean | Whether the rule is disabled. |
| Infoblox.ResponsePolicyZoneRulesList.Comment | string | The comment for this rule. |
| Infoblox.ResponsePolicyZoneRulesList.Type | string | The object type as used in Infoblox. |
| Infoblox.ResponsePolicyZoneRulesList.View | string | View of the definition. |
| Infoblox.ResponsePolicyZoneRulesList.Zone | string | The zone to which this rule belongs. |
| Infoblox.RulesNextPage.NextPageID | string | Retrieves the next page of the search. The last NextpageID corresponds to the last search performed. |

##### Command Example

`!infoblox-list-response-policy-zone-rules response_policy_zone_name=infoblow.com page_size="8"`

##### Context Example

```json
{
    "Infoblox.ResponsePolicyZoneRulesList": [
        {
            "Comment": "",
            "Disable": false,
            "Name": "4.4.4.5",
            "Type": "record:rpz:cname",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "1.1.1.1",
            "Type": "record:rpz:cname:ipaddressdn",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "2.2.2.2",
            "Type": "record:rpz:a:ipaddress",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "5.5.5.111",
            "Type": "record:rpz:cname:ipaddress",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "moshe",
            "Type": "record:rpz:cname",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "moshe2",
            "Type": "record:rpz:cname",
            "View": "default",
            "Zone": "infoblow.com"
        },
        {
            "Comment": "",
            "Disable": false,
            "Name": "moshe3",
            "Type": "record:rpz:cname",
            "View": "default",
            "Zone": "infoblow.com"
        }
    ],
    "Infoblox.RulesNextPage": {
        "NextPageID": "789c9d525b4ec33010fcf739905a89cacaa3a5ed11fa83101cc0726c2735385ecb7668cbe9d935a1503e51a4489edd9d997d2c75a8d9cb02a2c953f4a2b7c6e92446d069c1428391fb054b2f8b111344908321b86587aa2654c681de6bb6d46183b91fe00dbe1fd8d2852dbeadefa17370e20a46c4774c26e29267110bd19e1d76c443c4829211ab2ba614840ba60c0c7f0a7cca71521922066bb65433eb99a31aef6432ec09eb0f886242c39410dd645db65e0806ddab5119f1963de6e75017ab3579ed219e64d4a4f8f0dd4fca326642b68810e0ec680bb09b9d0e90410448365bf002fa3e9912dfcf055a664983ab48a7a1c9f636a65cfa885abc990b4569ae34137e6d45fbc43bebb5505e8ee68e0b6d7a39b9fc3bebc4377c4d1f51b4c59e44eaa34cc29b33d968d6df9d1c8dd4242a14c09ba5a5341b36fca90ad1bc5384faafae915babdb7f5a1d211d4d4b0c38b7d42139ae225f42b1b24752e95c0c1f5f62e5a88a83db3b24b8a6636a696224b7a2135ba1d2687c5e699b64e7cc6ae66d5b3c30dce2d4fd949785b71be22e9b206cee977f02207ef4bc-1cbe432a6c562d903bd34ea2dd75f482330d98e249c3359e4e258b9"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Zone: Infoblow.com rule list.

| **Comment** | **Disable** | **Name** | **Type** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- |
|     | false | 4.4.4.5 | record:rpz:cname | default | infoblow.com |
|     | false | 1.1.1.1 | record:rpz:cname:ipaddressdn | default | infoblow.com |
|     | false | 2.2.2.2 | record:rpz:a:ipaddress | default | infoblow.com |
|     | false | 5.5.5.111 | record:rpz:cname:ipaddress | default | infoblow.com |
|     | false | moshe | record:rpz:cname | default | infoblow.com |
|     | false | moshe2 | record:rpz:cname | default | infoblow.com |
|     | false | moshe3 | record:rpz:cname | default | infoblow.com |

### infoblox-list-response-policy-zones

* * *

List all response policy zones.

##### Base Command

`infoblox-list-response-policy-zones`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_results | Maximum results to return. (Default is 50) | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ResponsePolicyZones.Disable | boolean | Whether this zone is disabled. |
| Infoblox.ResponsePolicyZones.FQDN | string | The fully qualified domain name. |
| Infoblox.ResponsePolicyZones.ReferenceID | string | The reference ID of the object. |
| Infoblox.ResponsePolicyZones.RpzPolicy | string | The response policy zone override policy. |
| Infoblox.ResponsePolicyZones.RpzSeverity | string | The severity of this response policy zone. |
| Infoblox.ResponsePolicyZones.RpzType | string | The type of response policy zone. |
| Infoblox.ResponsePolicyZones.View | string | The view of the definition. |

##### Command Example

`!infoblox-list-response-policy-zones`

##### Context Example

```json
{
    "Infoblox.ResponsePolicyZones": [
        {
            "Disable": false,
            "FQDN": "local.rpz",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LnJwei5sb2NhbA:local.rpz/default",
            "RpzPolicy": "GIVEN",
            "RpzSeverity": "MAJOR",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "infoblow.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdw:infoblow.com/default",
            "RpzPolicy": "SUBSTITUTE",
            "RpzSeverity": "WARNING",
            "RpzType": "LOCAL",
            "SubstituteName": "infoblox.com",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGU:google.com/default",
            "RpzPolicy": "DISABLED",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "SubstituteName": "sdfdsf",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google2.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUy:google2.com/default",
            "RpzPolicy": "DISABLED",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "SubstituteName": "sdfdsf",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google3.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUz:google3.com/default",
            "RpzPolicy": "DISABLED",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "SubstituteName": "sdfdsf",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google4.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGU0:google4.com/default",
            "RpzPolicy": "DISABLED",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "SubstituteName": "sdfdsf",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google33.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUzMw:google33.com/default",
            "RpzPolicy": "GIVEN",
            "RpzSeverity": "WARNING",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google.test.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0Lmdvb2dsZQ:google.test.com/default",
            "RpzPolicy": "NXDOMAIN",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google.test2.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0Mi5nb29nbGU:google.test2.com/default",
            "RpzPolicy": "NXDOMAIN",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "google.test4.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0NC5nb29nbGU:google.test4.com/default",
            "RpzPolicy": "NXDOMAIN",
            "RpzSeverity": "INFORMATIONAL",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "test.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0:test.com/default",
            "RpzPolicy": "GIVEN",
            "RpzSeverity": "WARNING",
            "RpzType": "LOCAL",
            "View": "default"
        },
        {
            "Disable": false,
            "FQDN": "test123.com",
            "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0MTIz:test123.com/default",
            "RpzPolicy": "GIVEN",
            "RpzSeverity": "WARNING",
            "RpzType": "LOCAL",
            "View": "default"
        }
    ]
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zones list (first 50 results):

| **Disable** | **FQDN** | **Reference ID** | **Rpz Policy** | **Rpz Severity** | **Rpz Type** | **View** |
| --- | --- | --- | --- | --- | --- | --- |
| false | local.rpz | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LnJwei5sb2NhbA:local.rpz/default | GIVEN | MAJOR | LOCAL | default |
| false | infoblow.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdw:infoblow.com/default | SUBSTITUTE | WARNING | LOCAL | default |
| false | google.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGU:google.com/default | DISABLED | INFORMATIONAL | LOCAL | default |
| false | google2.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUy:google2.com/default | DISABLED | INFORMATIONAL | LOCAL | default |
| false | google3.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUz:google3.com/default | DISABLED | INFORMATIONAL | LOCAL | default |
| false | google4.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGU0:google4.com/default | DISABLED | INFORMATIONAL | LOCAL | default |
| false | google33.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS5nb29nbGUzMw:google33.com/default | GIVEN | WARNING | LOCAL | default |
| false | google.test.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0Lmdvb2dsZQ:google.test.com/default | NXDOMAIN | INFORMATIONAL | LOCAL | default |
| false | google.test2.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0Mi5nb29nbGU:google.test2.com/default | NXDOMAIN | INFORMATIONAL | LOCAL | default |
| false | google.test4.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0NC5nb29nbGU:google.test4.com/default | NXDOMAIN | INFORMATIONAL | LOCAL | default |
| false | test.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0:test.com/default | GIVEN | WARNING | LOCAL | default |
| false | test123.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0MTIz:test123.com/default | GIVEN | WARNING | LOCAL | default |

### 5\. infoblox-create-response-policy-zone

* * *

Creates a response policy zone.

##### Base Command

`infoblox-create-response-policy-zone`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| FQDN | The name of this DNS zone in FQDN format. | Required |
| rpz_policy | The override policy of the response policy zone. Can be: "DISABLED", "GIVEN", "NODATA", "NXDOMAIN", "PASSTHRU", or "SUBSTITUTE". | Required |
| rpz_severity | The severity of the response policy zone. Can be: "CRITICAL", "MAJOR", "WARNING", or "INFORMATIONAL". | Required |
| substitute_name | The alternative name of the redirect target in a substitute response policy. policy zone. | Optional |
| rpz_type | The type of the RPZ. Can be: "FEED", "FIREEYE", or "LOCAL". | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ResponsePolicyZones.Disable | boolean | Whether this zone is disabled. |
| Infoblox.ResponsePolicyZones.FQDN | string | A fully qualified domain name. |
| Infoblox.ResponsePolicyZones.ReferenceID | string | The reference ID of the object. |
| Infoblox.ResponsePolicyZones.RpzPolicy | string | The response policy zone override policy. |
| Infoblox.ResponsePolicyZones.RpzSeverity | string | The severity of the response policy zone. |
| Infoblox.ResponsePolicyZones.RpzType | string | The type of RPZ. |
| Infoblox.ResponsePolicyZones.View | string | The view of the definition. |

##### Command Example

`!infoblox-create-response-policy-zone FQDN="infonlox.nightly.tpb.com" rpz_policy="DISABLED" rpz_severity="INFORMATIONAL" rpz_type="FEED"`

##### Context Example

```json
{
    "Infoblox.ResponsePolicyZones": {
        "Disable": false,
        "FQDN": "infonlox.nightly.tpb.com",
        "ReferenceID": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50cGIubmlnaHRseS5pbmZvbmxveA:infonlox.nightly.tpb.com/default",
        "RpzPolicy": "DISABLED",
        "RpzSeverity": "INFORMATIONAL",
        "RpzType": "LOCAL",
        "View": "default"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone: infonlox.nightly.tpb.com has been created

| **Disable** | **FQDN** | **Reference ID** | **Rpz Policy** | **Rpz Severity** | **Rpz Type** | **View** |
| --- | --- | --- | --- | --- | --- | --- |
| false | infonlox.nightly.tpb.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50cGIubmlnaHRseS5pbmZvbmxveA:infonlox.nightly.tpb.com/default | DISABLED | INFORMATIONAL | LOCAL | default |

### infoblox-create-rpz-rule

* * *

Creates a response policy rule.

##### Base Command

`infoblox-create-rpz-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_type | The type of the rule to create. Can be: "Passthru", "Block" (No such domain), "Block" (No data), or "Substitute" (domain name). | Required |
| object_type | The type of the object for which to assign the rule. Can be: "Domain Name", "IP address", or "Client IP address". | Required |
| name | The rule name in a FQDN format. | Required |
| rp_zone | The zone to assign the rule to. | Required |
| comment | Comment for this rule. | Optional |
| substitute_name | The substitute name to assign (substitute domain only). | Optional |
| view | The DNS view in which the records are located. By default, the 'default' DNS view is searched. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The rule name. |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The comment for this rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Type | string | The object type as used in Infoblox. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |

##### Command Example

`!infoblox-create-rpz-rule rule_type="Passthru" object_type="Domain Name" name="nightly-test-rpz-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-rpz-sub"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Canonical": "nightly-test-rpz-sub.infoblow.com",
        "Disable": false,
        "Name": "nightly-test-rpz-sub.infoblow.com",
        "ReferenceID": "record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy5uaWdodGx5LXRlc3QtcnB6LXN1Yg:nightly-test-rpz-sub.infoblow.com/default",
        "Type": "record:rpz:cname",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: nightly-test-rpz-sub.infoblow.com has been created:

| **Canonical** | **Disable** | **Name** | **Reference ID** | **Type** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- |
| nightly-test-rpz-sub.infoblow.com | false | nightly-test-rpz-sub.infoblow.com | record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy5uaWdodGx5LXRlc3QtcnB6LXN1Yg:nightly-test-rpz-sub.infoblow.com/default | record:rpz:cname | default | infoblow.com |

### infoblox-create-a-substitute-record-rule

* * *

Creates a substitute record rule.

##### Base Command

`infoblox-create-a-substitute-record-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for a record in FQDN format. | Required |
| rp_zone | The zone to assign the rule to to. | Required |
| comment | Comment for this rule. | Optional |
| ipv4addr | The IPv4 address of the substitute rule. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The name of the rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The comment for this rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Type | string | The object type as used in Infoblox. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |

##### Command Example

`!infoblox-create-a-substitute-record-rule name="nightly-test-a-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-a-sub" ipv4addr="0.0.0.0"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-a-sub",
        "Disable": false,
        "Ipv4addr": "0.0.0.0",
        "Name": "nightly-test-a-sub.infoblow.com",
        "ReferenceID": "record:rpz:a/ZG5zLmJpbmRfYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LG5pZ2h0bHktdGVzdC1hLXN1YiwwLjAuMC4w:nightly-test-a-sub.infoblow.com/default",
        "Type": "record:rpz:a",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: nightly-test-a-sub.infoblow.com has been created:

| **Comment** | **Disable** | **Ipv 4 Addr** | **Name** | **Reference ID** | **Type** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| nightly-test-a-sub | false | 0.0.0.0 | nightly-test-a-sub.infoblow.com | record:rpz:a/ZG5zLmJpbmRfYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LG5pZ2h0bHktdGVzdC1hLXN1YiwwLjAuMC4w:nightly-test-a-sub.infoblow.com/default | record:rpz:a | default | infoblow.com |

### infoblox-create-aaaa-substitute-record-rule

* * *

Creates a substitute rule for an AAAA record.

##### Base Command

`infoblox-create-aaaa-substitute-record-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for a record in FQDN format. | Required |
| rp_zone | The zone to assign the rule to to. | Required |
| comment | Comment for this rule. | Optional |
| ipv6addr | The IPv6 address of the substitute rule. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The name of the rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The comment for this rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Type | string | The object type as used in Infoblox. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |

##### Command Example

`!infoblox-create-aaaa-substitute-record-rule name="nightly-test-aaaa-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-aaaa-sub" ipv6addr="fd60:e32:f1b9::2"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-aaaa-sub",
        "Disable": false,
        "Ipv6addr": "fd60:e32:f1b9::2",
        "Name": "nightly-test-aaaa-sub.infoblow.com",
        "ReferenceID": "record:rpz:aaaa/ZG5zLmJpbmRfYWFhYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LG5pZ2h0bHktdGVzdC1hYWFhLXN1YixmZDYwOmUzMjpmMWI5Ojoy:nightly-test-aaaa-sub.infoblow.com/default",
        "Type": "record:rpz:aaaa",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: nightly-test-aaaa-sub.infoblow.com has been created:

| **Comment** | **Disable** | **Ipv 6 Addr** | **Name** | **Reference ID** | **Type** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| nightly-test-aaaa-sub | false | fd60:e32:f1b9::2 | nightly-test-aaaa-sub.infoblow.com | record:rpz:aaaa/ZG5zLmJpbmRfYWFhYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LG5pZ2h0bHktdGVzdC1hYWFhLXN1YixmZDYwOmUzMjpmMWI5Ojoy:nightly-test-aaaa-sub.infoblow.com/default | record:rpz:aaaa | default | infoblow.com |

### infoblox-create-mx-substitute-record-rule

* * *

Creates a substitute rule for the MX record.

##### Base Command

`infoblox-create-mx-substitute-record-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for a record in FQDN format. | Required |
| rp_zone | The zone to assign the rule to to. | Required |
| comment | Comment for this rule. | Optional |
| mail_exchanger | The mail exchanger name in FQDN format. This value can be in unicode format. | Required |
| preference | Preference value, 0 to 65535 (inclusive). | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The name of the rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The comment for this rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Type | string | The object type as used in Infoblox. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |

##### Command Example

`!infoblox-create-mx-substitute-record-rule name="nightly-test-mx-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-mx-sub" mail_exchanger="0.0.0.0" preference="5"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-mx-sub",
        "Disable": false,
        "MailExchanger": "0.0.0.0",
        "Name": "nightly-test-mx-sub.infoblow.com",
        "Preference": 5,
        "ReferenceID": "record:rpz:mx/ZG5zLmJpbmRfbXgkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy5uaWdodGx5LXRlc3QtbXgtc3ViLjAuMC4wLjAuNQ:nightly-test-mx-sub.infoblow.com/default",
        "Type": "record:rpz:mx",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: nightly-test-mx-sub.infoblow.com has been created:

| **Comment** | **Disable** | **Mail Exchanger** | **Name** | **Preference** | **Reference ID** | **Type** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| nightly-test-mx-sub | false | 0.0.0.0 | nightly-test-mx-sub.infoblow.com | 5   | record:rpz:mx/ZG5zLmJpbmRfbXgkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy5uaWdodGx5LXRlc3QtbXgtc3ViLjAuMC4wLjAuNQ:nightly-test-mx-sub.infoblow.com/default | record:rpz:mx | default | infoblow.com |

### infoblox-create-naptr-substitute-record-rule

* * *

Creates a substitute rule for a NAPTR record.

##### Base Command

`infoblox-create-naptr-substitute-record-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for a record in FQDN format. | Required |
| rp_zone | The zone to assign the rule to to. | Required |
| comment | Comment for this rule. | Optional |
| order | The order parameter of the substitute rule of the NAPTR record. This parameter specifies the order in which the NAPTR rules are applied when multiple rules are present. Can be from 0 to 65535 (inclusive). | Required |
| preference | Preference value, 0 to 65535 (inclusive). | Required |
| replacement | The substitute rule object replacement field of the NAPTR record. For non-terminal NAPTR records, this field specifies the next domain name to look up. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The name of the rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The comment for this rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Type | string | The object type as used in Infoblox. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |

##### Command Example

`!infoblox-create-naptr-substitute-record-rule name="nightly-test-naptr-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-naptr-sub" order="0" preference="1" replacement="infoblow.com"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-naptr-sub",
        "Disable": false,
        "Name": "nightly-test-naptr-sub.infoblow.com",
        "Order": 0,
        "Preference": 1,
        "ReferenceID": "record:rpz:naptr/ZG5zLmJpbmRfbmFwdHIkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdyxuaWdodGx5LXRlc3QtbmFwdHItc3ViLDAsMSwsLCxpbmZvYmxvdy5jb20:nightly-test-naptr-sub.infoblow.com/default",
        "Regexp": "",
        "Replacement": "infoblow.com",
        "Services": "",
        "Type": "record:rpz:naptr",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: nightly-test-naptr-sub.infoblow.com has been created:

| **Comment** | **Disable** | **Name** | **Order** | **Preference** | **Reference ID** | **Regexp** | **Replacement** | **Services** | **Type** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| nightly-test-naptr-sub | false | nightly-test-naptr-sub.infoblow.com | 0   | 1   | record:rpz:naptr/ZG5zLmJpbmRfbmFwdHIkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdyxuaWdodGx5LXRlc3QtbmFwdHItc3ViLDAsMSwsLCxpbmZvYmxvdy5jb20:nightly-test-naptr-sub.infoblow.com/default |     | infoblow.com |     | record:rpz:naptr | default | infoblow.com |

### infoblox-create-ptr-substitute-record-rule

* * *

Creates a substitute rule of the PTR record.

##### Base Command

`infoblox-create-ptr-substitute-record-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rp_zone | The zone to assign the rule to to. | Required |
| comment | Comment for this rule. | Optional |
| ptrdname | The domain name of the RPZ substitute rule object of the PTR record in FQDN format. | Required |
| name | The name of the RPZ Substitute rule object of the PTR record in FQDN format. | Optional |
| ipv4addr | The IPv4 address of the substitute rule. | Optional |
| ipv6addr | The IPv6 address of the substitute rule. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The name of the rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The Comment for this rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Type | string | The object type as used in Infoblox. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |

##### Command Example

`!infoblox-create-ptr-substitute-record-rule rp_zone="infoblow.com" comment="nightly-test-ptr-sub" ptrdname="infoblow.com" ipv4addr="0.0.0.0"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-ptr-sub",
        "Disable": false,
        "Ipv4addr": "0.0.0.0",
        "Name": "0.0.0.0.in-addr.arpa.infoblow.com",
        "Ptrdname": "infoblow.com",
        "ReferenceID": "record:rpz:ptr/ZG5zLmJpbmRfcHRyJC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cuYXJwYS5pbi1hZGRyLjAuMC4wLjAuaW5mb2Jsb3cuY29t:0.0.0.0.in-addr.arpa.infoblow.com/default",
        "Type": "record:rpz:ptr",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: None has been created:

| **Comment** | **Disable** | **Ipv 4 Addr** | **Name** | **Ptrdname** | **Reference ID** | **Type** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| nightly-test-ptr-sub | false | 0.0.0.0 | 0.0.0.0.in-addr.arpa.infoblow.com | infoblow.com | record:rpz:ptr/ZG5zLmJpbmRfcHRyJC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cuYXJwYS5pbi1hZGRyLjAuMC4wLjAuaW5mb2Jsb3cuY29t:0.0.0.0.in-addr.arpa.infoblow.com/default | record:rpz:ptr | default | infoblow.com |

### infoblox-create-srv-substitute-record-rule

* * *

Creates a substitute rule of a SRV record.

##### Base Command

`infoblox-create-srv-substitute-record-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for a record in FQDN format. | Required |
| rp_zone | The zone to assign the rule to. | Required |
| comment | Comment for this rule. | Optional |
| port | The port of the substitute rule of the SRV record. Can be 0 to 65535 (inclusive). | Required |
| priority | The priority of the substitute rule for the SRV Record. Can be 0 to 65535 (inclusive). | Required |
| target | The target of the substitute rule of the SRV record in FQDN format. This value can be in unicode format. | Required |
| we.g.,t | The we.g.,t of the substitute rule of the SRV record. Can be 0 to 65535 (inclusive). | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The rule name. |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The comment for this rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Type | string | The object type as used in Infoblox. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |

##### Command Example

`!infoblox-create-srv-substitute-record-rule name="nightly-test-srv-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-srv-sub" port="22" priority="10" target="infoblow.com" we.g.,t="10"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-srv-sub",
        "Disable": false,
        "Name": "nightly-test-srv-sub.infoblow.com",
        "Port": 22,
        "Priority": 10,
        "ReferenceID": "record:rpz:srv/ZG5zLmJpbmRfc3J2JC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cvbmlnaHRseS10ZXN0LXNydi1zdWIvMTAvMTAvMjIvaW5mb2Jsb3cuY29t:nightly-test-srv-sub.infoblow.com/default",
        "Target": "infoblow.com",
        "Type": "record:rpz:srv",
        "View": "default",
        "We.g.,t": 10,
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: nightly-test-srv-sub.infoblow.com has been created:

| **Comment** | **Disable** | **Name** | **Port** | **Priority** | **Reference ID** | **Target** | **Type** | **View** | **We.g.,t** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| nightly-test-srv-sub | false | nightly-test-srv-sub.infoblow.com | 22  | 10  | record:rpz:srv/ZG5zLmJpbmRfc3J2JC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cvbmlnaHRseS10ZXN0LXNydi1zdWIvMTAvMTAvMjIvaW5mb2Jsb3cuY29t:nightly-test-srv-sub.infoblow.com/default | infoblow.com | record:rpz:srv | default | 10  | infoblow.com |

### infoblox-create-txt-substitute-record-rule

* * *

Create a substitute rule for a txt record.

##### Base Command

`infoblox-create-txt-substitute-record-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for a record in FQDN format. | Required |
| rp_zone | The zone to assign the rule to. | Required |
| comment | Comment for this rule. | Optional |
| text | Text associated with the record. To enter leading, trailing, or embedded spaces in the text, add quotes around the text to preserve the spaces. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The rule name. |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The comment for this rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Type | string | The object type as used in Infoblox. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |

##### Command Example

`!infoblox-create-txt-substitute-record-rule name="nightly-test-txt-sub.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-txt-sub" text="nightly-test-txt-sub"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-txt-sub",
        "Disable": false,
        "Name": "nightly-test-txt-sub.infoblow.com",
        "ReferenceID": "record:rpz:txt/ZG5zLmJpbmRfdHh0JC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cubmlnaHRseS10ZXN0LXR4dC1zdWIuIm5pZ2h0bHktdGVzdC10eHQtc3ViIg:nightly-test-txt-sub.infoblow.com/default",
        "Text": "nightly-test-txt-sub",
        "Type": "record:rpz:txt",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: nightly-test-txt-sub.infoblow.com has been created:

| **Comment** | **Disable** | **Name** | **Reference ID** | **Text** | **Type** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| nightly-test-txt-sub | false | nightly-test-txt-sub.infoblow.com | record:rpz:txt/ZG5zLmJpbmRfdHh0JC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cubmlnaHRseS10ZXN0LXR4dC1zdWIuIm5pZ2h0bHktdGVzdC10eHQtc3ViIg:nightly-test-txt-sub.infoblow.com/default | nightly-test-txt-sub | record:rpz:txt | default | infoblow.com |

### infoblox-create-ipv4-substitute-record-rule

* * *

Create a substitute rule for an IPv4 rule.

##### Base Command

`infoblox-create-ipv4-substitute-record-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for a record in FQDN format. | Required |
| rp_zone | The zone to assign the rule to. | Required |
| comment | Comment for this rule. | Optional |
| ipv4addr | The IPv4 Address of the substitute rule. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The rule name. |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The comment for this rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Type | string | The object type as used in Infoblox. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |

##### Command Example

`!infoblox-create-ipv4-substitute-record-rule name="3.3.3.3.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-ipv4-sub" ipv4addr="3.3.3.4"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-ipv4-sub",
        "Disable": false,
        "Ipv4addr": "3.3.3.4",
        "Name": "3.3.3.3.infoblow.com",
        "ReferenceID": "record:rpz:a:ipaddress/ZG5zLmJpbmRfYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LHJwei1pcC4zLjMuMy4zLjMyLDMuMy4zLjQ:3.3.3.3.infoblow.com/default",
        "Type": "record:rpz:a:ipaddress",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: 3.3.3.3.infoblow.com has been created:

| **Comment** | **Disable** | **Ipv 4 Addr** | **Name** | **Reference ID** | **Type** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| nightly-test-ipv4-sub | false | 3.3.3.4 | 3.3.3.3.infoblow.com | record:rpz:a:ipaddress/ZG5zLmJpbmRfYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LHJwei1pcC4zLjMuMy4zLjMyLDMuMy4zLjQ:3.3.3.3.infoblow.com/default | record:rpz:a:ipaddress | default | infoblow.com |

### infoblox-create-ipv6-substitute-record-rule

* * *

Creates a substitute of the IPv6 record rule.

##### Base Command

`infoblox-create-ipv6-substitute-record-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for a record in FQDN format. | Required |
| rp_zone | The zone to assign the rule to. | Required |
| comment | Comment for this rule. | Optional |
| ipv6addr | The IPv6 Address of the substitute rule. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The rule name. |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The comment for this rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Type | string | The object type as used in Infoblox. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |

##### Command Example

`!infoblox-create-ipv6-substitute-record-rule name="000:000:000::1.infoblow.com" rp_zone="infoblow.com" comment="nightly-test-ipv6-sub" ipv6addr="fd60:e22:f1b9::2"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Comment": "nightly-test-ipv6-sub",
        "Disable": false,
        "Ipv6addr": "fd60:e22:f1b9::2",
        "Name": "::1.infoblow.com",
        "ReferenceID": "record:rpz:aaaa:ipaddress/ZG5zLmJpbmRfYWFhYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LHJwei1pcC56ei4xLjEyOCxmZDYwOmUyMjpmMWI5Ojoy:%3A%3A1.infoblow.com/default",
        "Type": "record:rpz:aaaa:ipaddress",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: 000:000:000::1.infoblow.com has been created:

| **Comment** | **Disable** | **Ipv 6 Addr** | **Name** | **Reference ID** | **Type** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| nightly-test-ipv6-sub | false | fd60:e22:f1b9::2 | ::1.infoblow.com | record:rpz:aaaa:ipaddress/ZG5zLmJpbmRfYWFhYSQuX2RlZmF1bHQuY29tLmluZm9ibG93LHJwei1pcC56ei4xLjEyOCxmZDYwOmUyMjpmMWI5Ojoy:%3A%3A1.infoblow.com/default | record:rpz:aaaa:ipaddress | default | infoblow.com |

### infoblox-enable-rule

* * *

Disables a rule by its reference ID (reference ID can be extracted by running the search rules command).

##### Base Command

`infoblox-enable-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reference_id | The ID of the rule reference (can be extracted by running the search rules command). | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The rule comment. |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The rule name. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The reference ID of the rule. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The response policy zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |

##### Command Example

`!infoblox-enable-rule reference_id="record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Canonical": "4.4.4.5.infoblow.com",
        "Disable": false,
        "Name": "4.4.4.5.infoblow.com",
        "ReferenceID": "record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: 4.4.4.5.infoblow.com has been enabled

| **Canonical** | **Disable** | **Name** | **Reference ID** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- |
| 4.4.4.5.infoblow.com | false | 4.4.4.5.infoblow.com | record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default | default | infoblow.com |

### infoblox-disable-rule

* * *

Disable a rule by its reference ID (reference ID can be extracted by running the 'infoblox-search-rule' command).

##### Base Command

`infoblox-disable-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reference_id | The ID of the rule reference (reference ID can be extracted by running the 'infoblox-search-rule' command). | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ModifiedResponsePolicyZoneRules.Disable | boolean | Whether this rule is disabled. |
| Infoblox.ModifiedResponsePolicyZoneRules.Comment | string | The rule comment. |
| Infoblox.ModifiedResponsePolicyZoneRules.Name | string | The rule name. |
| Infoblox.ModifiedResponsePolicyZoneRules.ReferenceID | string | The ID of the rule reference. |
| Infoblox.ModifiedResponsePolicyZoneRules.Zone | string | The response policy zone to which this rule belongs. |
| Infoblox.ModifiedResponsePolicyZoneRules.View | string | The view of the definition. |

##### Command Example

`!infoblox-disable-rule reference_id="record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default"`

##### Context Example

```json
{
    "Infoblox.ModifiedResponsePolicyZoneRules": {
        "Canonical": "4.4.4.5.infoblow.com",
        "Disable": true,
        "Name": "4.4.4.5.infoblow.com",
        "ReferenceID": "record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default",
        "View": "default",
        "Zone": "infoblow.com"
    }
}
```

##### Human Readable Output

### Infoblox Integration - Response Policy Zone rule: 4.4.4.5.infoblow.com has been disabled

| **Canonical** | **Disable** | **Name** | **Reference ID** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- |
| 4.4.4.5.infoblow.com | true | 4.4.4.5.infoblow.com | record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default | default | infoblow.com |

### infoblox-get-object-fields

* * *

Returns the object fields names which can be used in the search rules command.

##### Base Command

`infoblox-get-object-fields`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The Infoblox object type (can be retrieved by running the 'infoblox-list-response-policy-zone-rules' command). | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.ObjectFields.ObjectType | string | The Infoblox object type. |
| Infoblox.ObjectFields.SupportedFields | string | The list of supported fields for this object. |

##### Command Example

`!infoblox-get-object-fields object_type="record:rpz:cname"`

##### Context Example

```json
{
    "Infoblox.ObjectFields": {
        "ObjectType": "record:rpz:cname",
        "SupportedFields": [
            "canonical",
            "comment",
            "disable",
            "extattrs",
            "name",
            "rp_zone",
            "ttl",
            "use_ttl",
            "view",
            "zone"
        ]
    }
}
```

##### Human Readable Output

### Infoblox Integration - Object record:rpz:cname supported fields:

| **Field Names** |
| --- |
| canonical |
| comment |
| disable |
| extattrs |
| name |
| rp_zone |
| ttl |
| use_ttl |
| view |
| zone |

### infoblox-search-rule

* * *

Searches a specific rule by its name.

##### Base Command

`infoblox-search-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The Infoblox object type (can be retrieved by running the 'infoblox-list-response-policy-zone-rules' command). | Required |
| rule_name | The full rule name (usually the rule name followed by its zone. Example: name.domain.com) | Required |
| output_fields | The fields to include in the return object (supported object fields can be retrieved by running the \*infoblox-get-object-fields\* command). | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.RulesSearchResults.Name | string | The rule name. |
| Infoblox.RulesSearchResults.ReferenceID | string | The reference ID of the rule. |
| Infoblox.RulesSearchResults.View | string | The view of the definition. |

##### Command Example

`!infoblox-search-rule object_type="record:rpz:cname" rule_name="4.4.4.5.infoblow.com" output_fields="canonical,comment,disable,extattrs,name,rp_zone,ttl,use_ttl,view,zone"`

##### Context Example

```json
{
    "Infoblox.RulesSearchResults": [
        {
            "Canonical": "4.4.4.5.infoblow.com",
            "Disable": false,
            "Extattrs": {},
            "Name": "4.4.4.5.infoblow.com",
            "ReferenceID": "record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default",
            "UseTtl": false,
            "View": "default",
            "Zone": "infoblow.com"
        }
    ]
}
```

##### Human Readable Output

### Infoblox Integration - Search result for: 4.4.4.5.infoblow.com:

| **Canonical** | **Disable** | **Extattrs** | **Name** | **Reference ID** | **Use Ttl** | **View** | **Zone** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 4.4.4.5.infoblow.com | false |     | 4.4.4.5.infoblow.com | record:rpz:cname/ZG5zLmJpbmRfY25hbWUkLl9kZWZhdWx0LmNvbS5pbmZvYmxvdy41LjQuNC40:4.4.4.5.infoblow.com/default | false | default | infoblow.com |

### infoblox-delete-rpz-rule

* * *

Deletes a rule.

##### Base Command

`infoblox-delete-rpz-rule`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reference_id | The reference ID of the rule (reference ID can be retrieved by running the 'infoblox-search-rule' command). | Required |

##### Context Output

There are no context output for this command.

##### Command Example

`!infoblox-delete-rpz-rule reference_id=record:rpz:ptr/ZG5zLmJpbmRfcHRyJC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cuYXJwYS5pbi1hZGRyLjAuMC4wLjAuaW5mb2Jsb3cuY29t:0.0.0.0.in-addr.arpa.infoblow.com/default`

##### Context Example

```json
{}
```

##### Human Readable Output

Infoblox Integration - A rule with the following id was deleted: record:rpz:ptr/ZG5zLmJpbmRfcHRyJC5fZGVmYXVsdC5jb20uaW5mb2Jsb3cuYXJwYS5pbi1hZGRyLjAuMC4wLjAuaW5mb2Jsb3cuY29t:0.0.0.0.in-addr.arpa.infoblow.com/default

### infoblox-delete-response-policy-zone

* * *

Deletes a given response policy zone.

##### Base Command

`infoblox-delete-response-policy-zone`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| reference_id | The reference ID of the rule (can be extracted by running the search rules command). | Required |

##### Context Output

There are no context output for this command.

##### Command Example

`!infoblox-delete-response-policy-zone reference_id="zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50cGIubmlnaHRseS5pbmZvbmxveA:infonlox.nightly.tpb.com/default\"`

##### Context Example

```json
{}
```

##### Human Readable Output

Infoblox Integration - Response Policy Zone with the following id was deleted: zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50cGIubmlnaHRseS5pbmZvbmxveA:infonlox.nightly.tpb.com/default

Additional Information
----------------------

In order to create new rule for a response policy zone for all rules different from substitute record use the command 'create-rpz-rule'. For substitute record rules use the designated command for each use case.

Known Limitations
-----------------

Troubleshooting
---------------
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!infoblox-delete-response-policy-zone reference_id="zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50cGIubmlnaHRseS5pbmZvbmxveA:infonlox.nightly.tpb.com/default\"</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
Infoblox Integration - Response Policy Zone with the following id was deleted: 
 zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50cGIubmlnaHRseS5pbmZvbmxveA:infonlox.nightly.tpb.com/default
</p>
</p>
<h2>Additional Information</h2>
<p>
    In order to create new rule for a response policy zone for all rules different from substitute record use the command 'create-rpz-rule'. For substitute record rules use the designated command for each use case.
</p>
<h2>Known Limitations</h2><h2>Troubleshooting</h2>

### infoblox-list-host-info

***
Get all host records.

#### Base Command

`infoblox-list-host-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_name | The hostname to retrieve records for, e.g., localhost.test. | Optional | 
| extattrs | Comma-separated key/value formatted filter for extended attributes, e.g., "Site=New York,OtherProp=MyValue". | Optional | 
| max_results | The maximum number of records to return. Default is 50, maximum is 1000. | Optional | 
| additional_return_fields | Comma-separated list of additional fields to return for each host, e.g., extattrs,aliases. Default is extattrs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.Host.Reference | String | The host record reference ID. | 
| Infoblox.Host.IPv4Address | String | The host first IPv4 address. | 
| Infoblox.Host.ConfigureForDHCP | Boolean | Whether the host is configured for DHCP. | 
| Infoblox.Host.Name | String | The host record name. | 
| Infoblox.Host.ExtendedAttributes | Unknown | The network extended attributes. | 
| Infoblox.Host.AdditionalFields | Unknown | The additional fields for network. | 

#### Command example
```!infoblox-list-host-info```
#### Context Example
```json
{
    "Infoblox": {
        "Host": [
            {
                "ConfigureForDHCP": false,
                "ExtendedAttributes": {},
                "IPv4Address": "192.168.10.10",
                "Name": "localhost.test",
                "Reference": "record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5sb2NhbGhvc3QuMTkyLjE2OC4xMC4xMC4:192.168.10.10/localhost.test/default"
            },
            {
                "ConfigureForDHCP": false,
                "ExtendedAttributes": {
                    "IB Discovery Owned": "EMEA",
                    "Site": "Tel-Aviv"
                },
                "IPv4Address": "192.168.100.100",
                "Name": "localdoman.localhost.test",
                "Reference": "record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5sb2NhbGhvc3QubG9jYWxkb21hbi4xOTIuMTY4LjEwMC4xMDAu:192.168.100.100/localdoman.localhost.test/default"
            },
            {
                "ConfigureForDHCP": false,
                "ExtendedAttributes": {
                    "Site": "Local"
                },
                "IPv4Address": "255.255.255.192",
                "Name": "test",
                "Reference": "record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC4uMjU1LjI1NS4yNTUuMTkyLg:255.255.255.192/test/default"
            },
            {
                "ConfigureForDHCP": false,
                "ExtendedAttributes": {
                    "IB Discovery Owned": "dummy value",
                    "Site": "ciac-5843"
                },
                "IPv4Address": "192.168.1.0",
                "Name": "ciac-3607.test",
                "Reference": "record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5jaWFjLTM2MDcuMTkyLjE2OC4xLjAu:192.168.1.0/ciac-3607.test/default"
            }
        ]
    }
}
```

#### Human Readable Output

>### Host records (first 50)
>|ConfigureForDHCP|ExtendedAttributes|IPv4Address|Name|Reference|
>|---|---|---|---|---|
>| false |  | 192.168.10.10 | localhost.test | record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5sb2NhbGhvc3QuMTkyLjE2OC4xMC4xMC4:192.168.10.10/localhost.test/default |
>| false | IB Discovery Owned: EMEA<br/>Site: Tel-Aviv | 192.168.100.100 | localdoman.localhost.test | record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5sb2NhbGhvc3QubG9jYWxkb21hbi4xOTIuMTY4LjEwMC4xMDAu:192.168.100.100/localdoman.localhost.test/default |
>| false | Site: Local | 255.255.255.192 | test | record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC4uMjU1LjI1NS4yNTUuMTkyLg:255.255.255.192/test/default |
>| false | IB Discovery Owned: dummy value<br/>Site: ciac-5843 | 192.168.1.0 | ciac-3607.test | record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5jaWFjLTM2MDcuMTkyLjE2OC4xLjAu:192.168.1.0/ciac-3607.test/default |


#### Command example
```!infoblox-list-host-info additional_return_fields=extattrs,aliases```
#### Context Example
```json
{
    "Infoblox": {
        "Host": [
            {
                "ConfigureForDHCP": false,
                "ExtendedAttributes": {},
                "IPv4Address": "192.168.10.10",
                "Name": "localhost.test",
                "Reference": "record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5sb2NhbGhvc3QuMTkyLjE2OC4xMC4xMC4:192.168.10.10/localhost.test/default"
            },
            {
                "ConfigureForDHCP": false,
                "ExtendedAttributes": {
                    "IB Discovery Owned": "EMEA",
                    "Site": "Tel-Aviv"
                },
                "IPv4Address": "192.168.100.100",
                "Name": "localdoman.localhost.test",
                "Reference": "record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5sb2NhbGhvc3QubG9jYWxkb21hbi4xOTIuMTY4LjEwMC4xMDAu:192.168.100.100/localdoman.localhost.test/default"
            },
            {
                "ConfigureForDHCP": false,
                "ExtendedAttributes": {
                    "Site": "Local"
                },
                "IPv4Address": "255.255.255.192",
                "Name": "test",
                "Reference": "record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC4uMjU1LjI1NS4yNTUuMTkyLg:255.255.255.192/test/default"
            },
            {
                "AdditionalFields": [
                    {
                        "Aliases": [
                            "test_host.test"
                        ]
                    }
                ],
                "ConfigureForDHCP": false,
                "ExtendedAttributes": {
                    "IB Discovery Owned": "dummy value",
                    "Site": "ciac-5843"
                },
                "IPv4Address": "192.168.1.0",
                "Name": "ciac-3607.test",
                "Reference": "record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5jaWFjLTM2MDcuMTkyLjE2OC4xLjAu:192.168.1.0/ciac-3607.test/default"
            }
        ]
    }
}
```

#### Human Readable Output

>### Host records (first 50)
>|ConfigureForDHCP|ExtendedAttributes|IPv4Address|Name|Reference|
>|---|---|---|---|---|
>| false |  | 192.168.10.10 | localhost.test | record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5sb2NhbGhvc3QuMTkyLjE2OC4xMC4xMC4:192.168.10.10/localhost.test/default |
>| false | IB Discovery Owned: EMEA<br/>Site: Tel-Aviv | 192.168.100.100 | localdoman.localhost.test | record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5sb2NhbGhvc3QubG9jYWxkb21hbi4xOTIuMTY4LjEwMC4xMDAu:192.168.100.100/localdoman.localhost.test/default |
>| false | Site: Local | 255.255.255.192 | test | record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC4uMjU1LjI1NS4yNTUuMTkyLg:255.255.255.192/test/default |
>| false | IB Discovery Owned: dummy value<br/>Site: ciac-5843 | 192.168.1.0 | ciac-3607.test | record:host_ipv4addr/ZG5zLmhvc3RfYWRkcmVzcyQuX2RlZmF1bHQudGVzdC5jaWFjLTM2MDcuMTkyLjE2OC4xLjAu:192.168.1.0/ciac-3607.test/default |


### infoblox-list-network-info

***
List network information.

#### Base Command

`infoblox-list-network-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pattern | Filter networks by pattern, e.g., '.0/24' for netmask, '192.168' for subnet. | Optional | 
| extattrs | comma-separated key/value formatted filter for extended attributes, e.g., "Site=New York,OtherProp=MyValue". | Optional | 
| max_results | The maximum number of records to return. Maximum is 1000. Default is 50. | Optional | 
| additional_return_fields | Comma separated list of additional fields to return for each host, e.g., extattrs,aliases. Default is extattrs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infoblox.NetworkInfo.Reference | String | The network reference. | 
| Infoblox.NetworkInfo.Name | String | The network name. | 
| Infoblox.NetworkInfo.NetworkView | String | The network view name. | 
| Infoblox.NetworkInfo.ExtendedAttributes | Unknown | The network extended attributes. | 
| Infoblox.NetworkInfo.AdditionalFields | Unknown | The additional fields for network. | 

#### Command example
```!infoblox-list-network-info```
#### Context Example
```json
{
    "Infoblox": {
        "NetworkInfo": [
            {
                "ExtendedAttributes": {},
                "Name": "192.168.1.0/24",
                "NetworkView": "default",
                "Reference": "network/ZG5zLm5ldHdvcmskMTkyLjE2OC4xLjAvMjQvMA:192.168.1.0/24/default"
            },
            {
                "ExtendedAttributes": {
                    "Region": "EMEA"
                },
                "Name": "255.255.255.192/26",
                "NetworkView": "default",
                "Reference": "network/ZG5zLm5ldHdvcmskMjU1LjI1NS4yNTUuMTkyLzI2LzA:255.255.255.192/26/default"
            }
        ]
    }
}
```

#### Human Readable Output

>### Network information found (50 limit)
>|ExtendedAttributes|Name|NetworkView|Reference|
>|---|---|---|---|
>|  | 192.168.1.0/24 | default | network/ZG5zLm5ldHdvcmskMTkyLjE2OC4xLjAvMjQvMA:192.168.1.0/24/default |
>| Region: EMEA | 255.255.255.192/26 | default | network/ZG5zLm5ldHdvcmskMjU1LjI1NS4yNTUuMTkyLzI2LzA:255.255.255.192/26/default |


#### Command example
```!infoblox-list-network-info pattern=255.255 extattrs="Region=EMEA"```
#### Context Example
```json
{
    "Infoblox": {
        "NetworkInfo": [
            {
                "ExtendedAttributes": {
                    "Region": "EMEA"
                },
                "Name": "255.255.255.192/26",
                "NetworkView": "default",
                "Reference": "network/ZG5zLm5ldHdvcmskMjU1LjI1NS4yNTUuMTkyLzI2LzA:255.255.255.192/26/default"
            }
        ]
    }
}
```

#### Human Readable Output

>### Network information found (50 limit)
>|ExtendedAttributes|Name|NetworkView|Reference|
>|---|---|---|---|
>| Region: EMEA | 255.255.255.192/26 | default | network/ZG5zLm5ldHdvcmskMjU1LjI1NS4yNTUuMTkyLzI2LzA:255.255.255.192/26/default |


