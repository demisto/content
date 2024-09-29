Cisco Meraki is a cloud-managed IT company that simplifies networking, security, communications, and endpoint management. Its platform offers centralized management for devices, networks, and security through an intuitive web interface. Key functionalities include managing organizations, networks, devices, and their licenses, as well as monitoring device statuses and client activities.
This integration was integrated and tested with version MR 30.7 and MX 18.211.2 of Cisco Meraki v2.

Some changes have been made that might affect your existing content.
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration---cisco-meraki-v2).

## Configure Cisco Meraki v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | The API base URL. | True |
| API Key | An API key can be generated through 'My Profile' in 'API access'. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Organization ID | A default ID to be used in all commands that require an organization. | False |
| Network ID | A default ID to be used in all commands that require a network. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### meraki-organization-list

***
List the organizations that the user has privileges on.

#### Base Command

`meraki-organization-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of a specific organization to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| page_size | The maximum number of records to return per page. To receive additional pages after the first call, use `next_token`. Acceptable range is 3 - 9000. Default is 50. | Optional |
| next_token | Insert 'OrganizationLinkTokens.Next' value received from a previous pagination command's context to further paginate through records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.OrganizationLinkTokens.Prev | String | Pagination token used to retrieve the previous batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.OrganizationLinkTokens.Next | String | Pagination token used to retrieve the next batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.OrganizationLinkTokens.First | String | Pagination token used to retrieve the first batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.OrganizationLinkTokens.Last | String | Pagination token used to retrieve the last batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.Organization.id | String | Organization ID. |
| CiscoMeraki.Organization.name | String | Organization name. |
| CiscoMeraki.Organization.url | String | Organization URL. |
| CiscoMeraki.Organization.api.enabled | Boolean | Enable API access. |
| CiscoMeraki.Organization.cloud.region.name | String | Cloud region name. |
| CiscoMeraki.Organization.cloud.region.host.name | String | Name of location where organization data is hosted. |
| CiscoMeraki.Organization.licensing.model | String | Organization licensing model. Can be 'co-term', 'per-device', or 'subscription'. |
| CiscoMeraki.Organization.management.details.name | String | Name of management data. Details may be named 'MSP ID', 'customer number', 'IP restriction mode for API', or 'IP restriction mode for dashboard', if the organization admin has configured any. |
| CiscoMeraki.Organization.management.details.value | String | Value of management data. |

#### Command example
```!meraki-organization-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "Organization": [
            {
                "api": {
                    "enabled": true
                },
                "cloud": {
                    "region": {
                        "host": {
                            "name": "Europe"
                        },
                        "name": "Europe"
                    }
                },
                "id": "1565046",
                "licensing": {
                    "model": "co-term"
                },
                "management": {
                    "details": [
                        {
                            "name": "customer number",
                            "value": "29392676"
                        }
                    ]
                },
                "name": "Qmasters",
                "url": "https://www.example.com"
            },
            {
                "api": {
                    "enabled": true
                },
                "cloud": {
                    "region": {
                        "host": {
                            "name": "Europe"
                        },
                        "name": "Europe"
                    }
                },
                "id": "0000000003807418",
                "licensing": {
                    "model": "co-term"
                },
                "management": {
                    "details": [
                        {
                            "name": "customer number",
                            "value": "29392676"
                        }
                    ]
                },
                "name": "lior test org",
                "url": "https://www.example.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Organization(s)
>|ID|Name|URL|Cloud Region Name|Cloud Region Host Name|
>|---|---|---|---|---|
>| 1565046 | Qmasters | https:<span>//</span>www.example.com/o/4WI3pa/manage/organization/overview | Europe | Europe |
>| 0000000003807418 | lior test org | https:<span>//</span>www.example.com/o/x-L8jc4wb/manage/organization/overview | Europe | Europe |


### meraki-network-list

***
List the networks that the user has privileges on in an organization.

#### Base Command

`meraki-network-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of a specific network to retrieve. | Optional |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |
| config_template_id | ID of a configuration template. Will return all networks bound to that template. | Optional |
| is_bound_to_config_template | Whether to filter configuration template bound networks. If config_template_id is set, this cannot be false. Possible values are: false, true. | Optional |
| tags | Comma-separated list of tags to filter networks by. The filtering is case-sensitive. If tags are included, 'tags_filter_type' should also be included. | Optional |
| tags_filter_type | Indicate whether to return networks that contain ANY or ALL of the included tags. If no type is included, 'withAnyTags' will be selected. Possible values are: withAnyTags, withAllTags. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| page_size | The maximum number of records to return per page. To receive additional pages after the first call, use `next_token`. Acceptable range is 3 - 100000. Default is 50. | Optional |
| next_token | Insert 'NetworkLinkTokens' value received from a previous pagination command's context to further paginate through records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.NetworkLinkTokens | String | Pagination token used to retrieve the next batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.Network.enrollmentString | String | Enrollment string for the network. |
| CiscoMeraki.Network.id | String | Network ID. |
| CiscoMeraki.Network.name | String | Network name. |
| CiscoMeraki.Network.notes | String | Notes for the network. |
| CiscoMeraki.Network.organizationId | String | Organization ID. |
| CiscoMeraki.Network.timeZone | String | Timezone of the network. |
| CiscoMeraki.Network.url | String | URL to the network dashboard UI. |
| CiscoMeraki.Network.isBoundToConfigTemplate | Boolean | If the network is bound to a configuration template. |
| CiscoMeraki.Network.productTypes | String | List of the product types that the network supports. |
| CiscoMeraki.Network.tags | String | Network tags. |

#### Command example
```!meraki-network-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "Network": [
            {
                "enrollmentString": null,
                "id": "L_0000",
                "isBoundToConfigTemplate": false,
                "name": "QMDEV",
                "notes": "",
                "organizationId": "1565046",
                "productTypes": [
                    "systemsManager",
                    "wireless"
                ],
                "tags": [],
                "timeZone": "Israel",
                "url": "https://www.example.com"
            },
            {
                "enrollmentString": null,
                "id": "L_0000000003808704",
                "isBoundToConfigTemplate": false,
                "name": "Main Office",
                "notes": "Additional description of the network",
                "organizationId": "1565046",
                "productTypes": [
                    "appliance",
                    "switch",
                    "wireless"
                ],
                "tags": [
                    "tag1",
                    "tag2"
                ],
                "timeZone": "America/Los_Angeles",
                "url": "https://www.example.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Network(s)
>|ID|Name|Organization ID|URL|
>|---|---|---|---|
>| L_0000 | QMDEV | 1565046 | https:<span>//</span>www.example.com/QMDEV-systems-ma/n/Vxca_d4wb/manage/usage/list |
>| L_0000000003808704 | Main Office | 1565046 | https:<span>//</span>www.example.com/Main-Office-swit/n/NWZMpc4wb/manage/usage/list |
>| L_0000000003808705 | test1 | 1565046 | https:<span>//</span>www.example.com/test1-appliance/n/gDo-Yd4wb/manage/usage/list |
>| L_0000000003808706 | test2 | 1565046 | https:<span>//</span>www.example.com/test2-switch/n/ggolja4wb/manage/usage/list |
>| L_0000000003808707 | test3 | 1565046 | https:<span>//</span>www.example.com/test3-appliance/n/lJMwdc4wb/manage/usage/list |
>| L_0000000003808708 | test4 | 1565046 | https:<span>//</span>www.example.com/test4-switch/n/rYPDda4wb/manage/usage/list |
>| L_0000000003808709 | test5 | 1565046 | https:<span>//</span>www.example.com/test5-wireless/n/BFATjb4wb/manage/usage/list |
>| N_0000000003819799 | wirless | 1565046 | https:<span>//</span>www.example.com/wirless/n/sbB7ib4wb/manage/usage/list |
>| N_0000000003823457 | TLV | 1565046 | https:<span>//</span>www.example.com/TLV/n/sAHLtb4wb/manage/usage/list |
>| N_0000000003823513 | test6 | 1565046 | https:<span>//</span>www.example.com/test6/n/Snzpjb4wb/manage/usage/list |


### meraki-organization-license-state-list

***
List the license states overview of an organization.

#### Base Command

`meraki-organization-license-state-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.LicenseState.organizationId | String | The organization the license state belongs to. |
| CiscoMeraki.LicenseState.licenseCount | Number | Total number of licenses \(per-device licensing only\). |
| CiscoMeraki.LicenseState.expirationDate | String | License expiration date \(co-termination licensing only\). |
| CiscoMeraki.LicenseState.status | String | License status \(co-termination licensing only\). |
| CiscoMeraki.LicenseState.licensedDeviceCounts | Number | License counts \(co-termination licensing only\). |
| CiscoMeraki.LicenseState.states.active.count | Number | The number of active licenses. |
| CiscoMeraki.LicenseState.states.expired.count | Number | The number of expired licenses. |
| CiscoMeraki.LicenseState.states.expiring.count | Number | The number of expiring licenses. |
| CiscoMeraki.LicenseState.states.expiring.critical.expiringCount | Number | The number of licenses that will expire in this window. |
| CiscoMeraki.LicenseState.states.expiring.critical.thresholdInDays | Number | The number of days from now denoting the critical threshold for an expiring license. |
| CiscoMeraki.LicenseState.states.expiring.warning.expiringCount | Number | The number of licenses that will expire in this window. |
| CiscoMeraki.LicenseState.states.expiring.warning.thresholdInDays | Number | The number of days from now denoting the warning threshold for an expiring license. |
| CiscoMeraki.LicenseState.states.recentlyQueued.count | Number | The number of recently queued licenses. |
| CiscoMeraki.LicenseState.states.unused.count | Number | The number of unused licenses. |
| CiscoMeraki.LicenseState.states.unused.soonestActivation.toActivateCount | Number | The number of licenses that will activate on this date. |
| CiscoMeraki.LicenseState.states.unused.soonestActivation.activationDate | Date | The soonest license activation date. |
| CiscoMeraki.LicenseState.states.unusedActive.count | Number | The number of unused, active licenses. |
| CiscoMeraki.LicenseState.states.unusedActive.oldestActivation.activeCount | Number | The number of licenses that activated on this date. |
| CiscoMeraki.LicenseState.states.unusedActive.oldestActivation.activationDate | Date | The oldest license activation date. |
| CiscoMeraki.LicenseState.systemsManager.counts.activeSeats | Number | The number of systems manager seats in use. |
| CiscoMeraki.LicenseState.systemsManager.counts.orgwideEnrolledDevices | Number | The total number of enrolled systems manager devices. |
| CiscoMeraki.LicenseState.systemsManager.counts.totalSeats | Number | The total number of systems manager seats. |
| CiscoMeraki.LicenseState.systemsManager.counts.unassignedSeats | Number | The number of unused systems manager seats. |
| CiscoMeraki.LicenseState.licenseTypes.licenseType | String | License type. |
| CiscoMeraki.LicenseState.licenseTypes.counts.unassigned | Number | The number of unassigned licenses. |

#### Command example
```!meraki-organization-license-state-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "LicenseState": {
            "expirationDate": "Jul 4, 2025 UTC",
            "licensedDeviceCounts": {
                "wireless": 1
            },
            "organizationId": "1565046",
            "status": "License Required"
        }
    }
}
```

#### Human Readable Output

>### License State(s)
>|Expiration Date|Status|
>|---|---|
>| Jul 4, 2025 UTC | License Required |


### meraki-organization-inventory-list

***
List the device inventories for an organization.

#### Base Command

`meraki-organization-inventory-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |
| serial | Serial number of a specific device to retrieve. Use `meraki-device-list` or `meraki-organization-device-search` to fetch serial numbers. | Optional |
| used_state | Filter results by used or unused inventory. Possible values are: used, unused. | Optional |
| search | Search for devices in inventory based on serial number, MAC address, or model. | Optional |
| macs | Comma-separated list of MAC addresses to search for in inventory. | Optional |
| network_ids | Comma-separated list of network IDs to search for in inventory. Use explicit 'null' value to get available devices only. Use `meraki-network-list` to fetch all network IDs. | Optional |
| serials | Comma-separated list of serial numbers to search for in inventory. Use `meraki-device-list` or `meraki-organization-device-search` to fetch serial numbers. | Optional |
| models | Comma-separated list of models to search for in inventory. | Optional |
| order_numbers | Comma-separated list of order numbers to search for in inventory. | Optional |
| tags | Comma-separated list of tags to filter networks by. The filtering is case-sensitive. If tags are included, 'tags_filter_type' should also be included. | Optional |
| tags_filter_type | Indicate whether to return networks that contain ANY or ALL of the included tags. If no type is included, 'withAnyTags' will be selected. Possible values are: withAnyTags, withAllTags. | Optional |
| product_types | Comma-separated list of product types to search for in inventory. Possible values are: appliance, camera, cellularGateway, sensor, switch, systemsManager, wireless. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| page_size | The maximum number of records to return per page. To receive additional pages after the first call, use `next_token`. Acceptable range is 3 - 1000. Default is 50. | Optional |
| next_token | Insert 'InventoryLinkTokens' value received from a previous pagination command's context to further paginate through records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.InventoryLinkTokens.Prev | String | Pagination token used to retrieve the previous batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.InventoryLinkTokens.Next | String | Pagination token used to retrieve the next batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.InventoryLinkTokens.First | String | Pagination token used to retrieve the first batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.InventoryLinkTokens.Last | String | Pagination token used to retrieve the last batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.Inventory.claimedAt | Date | Claimed time of the device. |
| CiscoMeraki.Inventory.countryCode | String | Country/region code from device, network, or store order. |
| CiscoMeraki.Inventory.licenseExpirationDate | Date | License expiration date of the device. |
| CiscoMeraki.Inventory.mac | String | MAC address of the device. |
| CiscoMeraki.Inventory.model | String | Model type of the device. |
| CiscoMeraki.Inventory.name | String | Name of the device. |
| CiscoMeraki.Inventory.networkId | String | Network ID of the device. |
| CiscoMeraki.Inventory.orderNumber | String | Order number of the device. |
| CiscoMeraki.Inventory.productType | String | Product type of the device. |
| CiscoMeraki.Inventory.serial | String | Serial number of the device. |
| CiscoMeraki.Inventory.tags | String | Device tags. |
| CiscoMeraki.Inventory.details.name | String | Additional property name. |
| CiscoMeraki.Inventory.details.value | String | Additional property value. |

#### Command example
```!meraki-organization-inventory-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "Inventory": {
            "claimedAt": "2024-07-08T14:00:47.679658Z",
            "countryCode": "IL",
            "details": [],
            "mac": "00:00:00:00:00:00",
            "model": "MR28",
            "name": "ACCESS POINT",
            "networkId": "L_0000",
            "orderNumber": "5S5479008",
            "productType": "wireless",
            "serial": "0000-0000-0000",
            "tags": [
                "aaa",
                "bbb"
            ]
        }
    }
}
```

#### Human Readable Output

>### Inventory Device(s)
>|Serial|Name|Network ID|MAC|Model|Claimed At|Product Type|
>|---|---|---|---|---|---|---|
>| 0000-0000-0000 | ACCESS POINT | L_0000 | 00:00:00:00:00:00 | MR28 | 2024-07-08T14:00:47.679658Z | wireless |


### meraki-device-claim

***
Claim devices into a network. (Note: For recently claimed devices, it may take a few minutes for API requests against that device to succeed). This operation can be used up to ten times within a single five minute window.

#### Base Command

`meraki-device-claim`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to claim the devices into. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| serials | Comma-separated list of serial numbers of the devices to claim. Use `meraki-device-list` or `meraki-organization-device-search` to fetch serial numbers. | Required |

#### Context Output

There is no context output for this command.

#### Command example
```!meraki-device-claim serials=0000-0000-0000```

#### Human Readable Output

>## The device(s) were successfully claimed into the network 'L_0000':
>- 0000-0000-0000

### meraki-organization-device-search

***
Search for devices in an organization.

#### Base Command

`meraki-organization-device-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |
| configuration_updated_after | Filter results by whether the devices configuration has been updated after the given timestamp. Accepted formats: datetime any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. | Optional |
| network_ids | Comma-separated list of network IDs to retrieve from. Use `meraki-network-list` to fetch all network IDs. | Optional |
| product_types | Comma-separated list of product types to search for in inventory. Possible values are: appliance, camera, cellularGateway, sensor, switch, systemsManager, wireless. | Optional |
| tags | Comma-separated list of tags to filter networks by. The filtering is case-sensitive. If tags are included, 'tags_filter_type' should also be included. | Optional |
| tags_filter_type | Indicate whether to return networks that contain ANY or ALL of the included tags. If no type is included, 'withAnyTags' will be selected. Possible values are: withAnyTags, withAllTags. | Optional |
| name | Filter devices by name. All returned devices will have a name that contains the search term or is an exact match. | Optional |
| mac | Filter devices by MAC address. All returned devices will have a MAC address that contains the search term or is an exact match. | Optional |
| serial | Filter devices by serial number. All returned devices will have a serial number that contains the search term or is an exact match. | Optional |
| model | Filter devices by model. All returned devices will have a model that contains the search term or is an exact match. | Optional |
| macs | Comma-separated list of MAC addresses to search. All returned devices will have a MAC address that is an exact match. | Optional |
| serials | Comma-separated list of serial numbers to search. All returned devices will have a serial number that is an exact match. | Optional |
| sensor_metrics | Comma-separated list of metrics that they provide. Only applies to sensor devices. | Optional |
| sensor_alert_profile_ids | Comma-separated list of alert profiles that are bound to them. Only applies to sensor devices. | Optional |
| models | Comma-separated list of models to search. All returned devices will have a model that is an exact match. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| page_size | The maximum number of records to return per page. To receive additional pages after the first call, use `next_token`. Acceptable range is 3 - 1000. Default is 50. | Optional |
| next_token | Insert 'DeviceLinkTokens' value received from a previous pagination command's context to further paginate through records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.DeviceLinkTokens.Prev | String | Pagination token used to retrieve the previous batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.DeviceLinkTokens.Next | String | Pagination token used to retrieve the next batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.DeviceLinkTokens.First | String | Pagination token used to retrieve the first batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.DeviceLinkTokens.Last | String | Pagination token used to retrieve the last batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.Device.address | String | Physical address of the device. |
| CiscoMeraki.Device.firmware | String | Firmware version of the device. |
| CiscoMeraki.Device.floorPlanId | String | The floor plan to associate to this device. |
| CiscoMeraki.Device.imei | String | IMEI of the device, if applicable. |
| CiscoMeraki.Device.lanIp | String | LAN IP address of the device. |
| CiscoMeraki.Device.mac | String | MAC address of the device. |
| CiscoMeraki.Device.model | String | Model of the device. |
| CiscoMeraki.Device.name | String | Name of the device. |
| CiscoMeraki.Device.networkId | String | ID of the network the device belongs to. |
| CiscoMeraki.Device.notes | String | Notes for the device, limited to 255 characters. |
| CiscoMeraki.Device.productType | String | Product type of the device. |
| CiscoMeraki.Device.serial | String | Serial number of the device. |
| CiscoMeraki.Device.lat | Number | Latitude of the device. |
| CiscoMeraki.Device.lng | Number | Longitude of the device. |
| CiscoMeraki.Device.tags | String | List of tags assigned to the device. |
| CiscoMeraki.Device.configurationUpdatedAt | Date | The last time the device's configuration has been updated. |
| CiscoMeraki.Device.beaconIdParams.major | Number | The major number to be used in the beacon identifier. |
| CiscoMeraki.Device.beaconIdParams.minor | Number | The minor number to be used in the beacon identifier. |
| CiscoMeraki.Device.beaconIdParams.uuid | String | The UUID to be used in the beacon identifier. |
| CiscoMeraki.Device.details.name | String | Additional property name. |
| CiscoMeraki.Device.details.value | String | Additional property value. |

#### Command example
```!meraki-organization-device-search```
#### Context Example
```json
{
    "CiscoMeraki": {
        "Device": {
            "address": "Tel Aviv",
            "configurationUpdatedAt": "2024-07-18T14:13:33Z",
            "details": [],
            "firmware": "wireless-30-7",
            "lanIp": "0.0.0.0",
            "lat": 32.0853,
            "lng": 34.78177,
            "mac": "00:00:00:00:00:00",
            "model": "MR28",
            "name": "ACCESS POINT",
            "networkId": "L_0000",
            "notes": "chchch",
            "productType": "wireless",
            "serial": "0000-0000-0000",
            "tags": [
                "aaa",
                "bbb"
            ],
            "url": "https://www.example.com"
        }
    }
}
```

#### Human Readable Output

>### Device(s)
>|Serial|Name|Network ID|Address|Model|Firmware|Lan IP|
>|---|---|---|---|---|---|---|
>| 0000-0000-0000 | ACCESS POINT | L_0000 | Tel Aviv | MR28 | wireless-30-7 | 0.0.0.0 |


### meraki-device-list

***
List the devices in an network or fetch a specific device with a serial number. Input must contain 1 parameter.

#### Base Command

`meraki-device-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of a specific network to retrieve from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| serial | Serial number of a specific device to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.Device.address | String | Physical address of the device. |
| CiscoMeraki.Device.firmware | String | Firmware version of the device. |
| CiscoMeraki.Device.floorPlanId | String | The floor plan to associate to this device. |
| CiscoMeraki.Device.lanIp | String | LAN IP address of the device. |
| CiscoMeraki.Device.mac | String | MAC address of the device. |
| CiscoMeraki.Device.model | String | Model of the device. |
| CiscoMeraki.Device.name | String | Name of the device. |
| CiscoMeraki.Device.networkId | String | ID of the network the device belongs to. |
| CiscoMeraki.Device.notes | String | Notes for the device, limited to 255 characters. |
| CiscoMeraki.Device.serial | String | Serial number of the device. |
| CiscoMeraki.Device.lat | Number | Latitude of the device. |
| CiscoMeraki.Device.lng | Number | Longitude of the device. |
| CiscoMeraki.Device.tags | String | List of tags assigned to the device. |
| CiscoMeraki.Device.beaconIdParams.major | Number | The major number to be used in the beacon identifier. |
| CiscoMeraki.Device.beaconIdParams.minor | Number | The minor number to be used in the beacon identifier. |
| CiscoMeraki.Device.beaconIdParams.uuid | String | The UUID to be used in the beacon identifier. |
| CiscoMeraki.Device.details.name | String | Additional property name. |
| CiscoMeraki.Device.details.value | String | Additional property value. |

#### Command example
```!meraki-device-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "Device": {
            "address": "Tel Aviv",
            "details": [],
            "firmware": "wireless-30-7",
            "floorPlanId": null,
            "lanIp": "0.0.0.0",
            "lat": 32.0853,
            "lng": 34.78177,
            "mac": "00:00:00:00:00:00",
            "model": "MR28",
            "name": "ACCESS POINT",
            "networkId": "L_0000",
            "notes": "chchch",
            "serial": "0000-0000-0000",
            "tags": [
                "aaa",
                "bbb"
            ],
            "url": "https://www.example.com"
        }
    }
}
```

#### Human Readable Output

>### Device(s)
>|Serial|Name|Network ID|Address|Model|Firmware|Lan IP|
>|---|---|---|---|---|---|---|
>| 0000-0000-0000 | ACCESS POINT | L_0000 | Tel Aviv | MR28 | wireless-30-7 | 0.0.0.0 |


### meraki-device-update

***
Update the attributes of a device.

#### Base Command

`meraki-device-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Serial number of the device to update. Use `meraki-device-list` or `meraki-organization-device-search` to fetch serial numbers. | Required |
| address | The address of a device. | Optional |
| floor_plan_id | The floor plan to associate to this device. Use explicit 'null' value to disassociate the device from the floor plan. | Optional |
| name | The name of a device. | Optional |
| notes | The notes for the device. Limited to 255 characters. | Optional |
| switch_profile_id | The ID of a switch template to bind to the device (for available switch templates, see the 'Switch Templates' endpoint). Use explicit 'null' value to unbind the switch device from the current profile. For a device to be bindable to a switch template, it must (1) be a switch, and (2) belong to a network that is bound to a configuration template. | Optional |
| move_map_marker | Whether to set the latitude and longitude of a device based on the new address. Only applies when lat and lng are not specified. Possible values are: false, true. | Optional |
| lat | The latitude of a device. | Optional |
| lng | The longitude of a device. | Optional |
| tags | Comma-separated list of tags for the device. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.Device.address | String | Physical address of the device. |
| CiscoMeraki.Device.firmware | String | Firmware version of the device. |
| CiscoMeraki.Device.floorPlanId | String | The floor plan to associate to this device. Use explicit 'null' value to disassociate the device from the floor plan. |
| CiscoMeraki.Device.imei | String | IMEI of the device, if applicable. |
| CiscoMeraki.Device.lanIp | String | LAN IP address of the device. |
| CiscoMeraki.Device.mac | String | MAC address of the device. |
| CiscoMeraki.Device.model | String | Model of the device. |
| CiscoMeraki.Device.name | String | Name of the device. |
| CiscoMeraki.Device.networkId | String | ID of the network the device belongs to. |
| CiscoMeraki.Device.notes | String | Notes for the device, limited to 255 characters. |
| CiscoMeraki.Device.productType | String | Product type of the device. |
| CiscoMeraki.Device.serial | String | Serial number of the device. |
| CiscoMeraki.Device.lat | Number | Latitude of the device. |
| CiscoMeraki.Device.lng | Number | Longitude of the device. |
| CiscoMeraki.Device.tags | String | List of tags assigned to the device. |
| CiscoMeraki.Device.beaconIdParams.major | Number | The major number to be used in the beacon identifier. |
| CiscoMeraki.Device.beaconIdParams.minor | Number | The minor number to be used in the beacon identifier. |
| CiscoMeraki.Device.beaconIdParams.uuid | String | The UUID to be used in the beacon identifier. |
| CiscoMeraki.Device.details.name | String | Additional property name. |
| CiscoMeraki.Device.details.value | String | Additional property value. |

#### Command example
```!meraki-device-update serial=0000-0000-0000 tags="aaa,bbb"```
#### Context Example
```json
{
    "CiscoMeraki": {
        "Device": {
            "address": "Tel Aviv",
            "details": [],
            "firmware": "wireless-30-7",
            "floorPlanId": null,
            "lanIp": "0.0.0.0",
            "lat": 32.0853,
            "lng": 34.78177,
            "mac": "00:00:00:00:00:00",
            "model": "MR28",
            "name": "ACCESS POINT",
            "networkId": "L_0000",
            "notes": "chchch",
            "serial": "0000-0000-0000",
            "tags": [
                "aaa",
                "bbb"
            ],
            "url": "https://www.example.com"
        }
    }
}
```

#### Human Readable Output

>### The device '0000-0000-0000' was successfully updated.
>|Serial|Name|Network ID|Address|Model|Firmware|Lan IP|
>|---|---|---|---|---|---|---|
>| 0000-0000-0000 | ACCESS POINT | L_0000 | Tel Aviv | MR28 | wireless-30-7 | 0.0.0.0 |


### meraki-device-remove

***
Remove a single device from a network.

#### Base Command

`meraki-device-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to remove the device from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| serial | Serial number of the device to remove. Use `meraki-device-list` or `meraki-organization-device-search` to fetch serial numbers. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!meraki-device-remove serial=0000-0000-0000```
#### Human Readable Output

>## The device with the serial number: '0000-0000-0000' was successfully removed from the network 'L_0000'.

### meraki-device-status-list

***
List the status of every Meraki device in the organization.

#### Base Command

`meraki-device-status-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |
| network_ids | Comma-separated list of network IDs to search for. Use `meraki-network-list` to fetch all network IDs. | Optional |
| serials | Comma-separated list of serial numbers to search for. Use `meraki-device-list` or `meraki-organization-device-search` to fetch serial numbers. | Optional |
| statuses | Comma-separated list of statuses to search for. Possible values are: online, alerting, offline, dormant. | Optional |
| product_types | Comma-separated list of product types to search for. Possible values are: appliance, camera, cellularGateway, sensor, switch, systemsManager, wireless. | Optional |
| models | Comma-separated list of models to search for. | Optional |
| tags | Comma-separated list of tags to filter networks by. The filtering is case-sensitive. If tags are included, 'tags_filter_type' should also be included. | Optional |
| tags_filter_type | Indicate whether to return networks that contain ANY or ALL of the included tags. If no type is included, 'withAnyTags' will be selected. Possible values are: withAnyTags, withAllTags. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| page_size | The maximum number of records to return per page. To receive additional pages after the first call, use `next_token`. Acceptable range is 3 - 1000. Default is 50. | Optional |
| next_token | Insert 'DeviceStatusLinkTokens' value received from a previous pagination command's context to further paginate through records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.DeviceStatusLinkTokens.Prev | String | Pagination token used to retrieve the previous batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.DeviceStatusLinkTokens.Next | String | Pagination token used to retrieve the next batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.DeviceStatusLinkTokens.First | String | Pagination token used to retrieve the first batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.DeviceStatusLinkTokens.Last | String | Pagination token used to retrieve the last batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.DeviceStatus.gateway | String | IP gateway. |
| CiscoMeraki.DeviceStatus.ipType | String | IP type. |
| CiscoMeraki.DeviceStatus.lanIp | String | LAN IP address. |
| CiscoMeraki.DeviceStatus.lastReportedAt | Date | Device last reported location. |
| CiscoMeraki.DeviceStatus.mac | String | MAC address. |
| CiscoMeraki.DeviceStatus.model | String | Model. |
| CiscoMeraki.DeviceStatus.name | String | Device name. |
| CiscoMeraki.DeviceStatus.networkId | String | Network ID. |
| CiscoMeraki.DeviceStatus.primaryDns | String | Primary DNS. |
| CiscoMeraki.DeviceStatus.productType | String | Product type. |
| CiscoMeraki.DeviceStatus.publicIp | String | Public IP address. |
| CiscoMeraki.DeviceStatus.secondaryDns | String | Secondary DNS. |
| CiscoMeraki.DeviceStatus.serial | String | Device serial number. |
| CiscoMeraki.DeviceStatus.status | String | Device status. |
| CiscoMeraki.DeviceStatus.tags | String | List of tags assigned to the device. |
| CiscoMeraki.DeviceStatus.components.powerSupplies.slot | Number | Slot the power supply is in. |
| CiscoMeraki.DeviceStatus.components.powerSupplies.model | String | Model of the power supply. |
| CiscoMeraki.DeviceStatus.components.powerSupplies.serial | String | Serial number of the power supply. |
| CiscoMeraki.DeviceStatus.components.powerSupplies.status | String | Status of the power supply. |
| CiscoMeraki.DeviceStatus.components.powerSupplies.poe.maximum | Number | Maximum PoE this power supply can provide when connected to the current switch model. |
| CiscoMeraki.DeviceStatus.components.powerSupplies.poe.unit | String | Unit of the PoE maximum. |

#### Command example
```!meraki-device-status-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "DeviceStatus": {
            "gateway": "0.0.0.0",
            "ipType": "dhcp",
            "lanIp": "0.0.0.0",
            "lastReportedAt": "2024-07-18T13:54:26.364000Z",
            "mac": "00:00:00:00:00:00",
            "model": "MR28",
            "name": "ACCESS POINT",
            "networkId": "L_0000",
            "primaryDns": "0.0.0.0",
            "productType": "wireless",
            "publicIp": "0.0.0.0",
            "secondaryDns": null,
            "serial": "0000-0000-0000",
            "status": "offline",
            "tags": [
                "aaa",
                "bbb"
            ]
        }
    }
}
```

#### Human Readable Output

>### Device Status(es)
>|Serial|Name|Network ID|Status|Model|IP Type|Gateway|Public IP|Lan IP|Last Reported At|
>|---|---|---|---|---|---|---|---|---|---|
>| 0000-0000-0000 | ACCESS POINT | L_0000 | offline | MR28 | dhcp | 0.0.0.0 | 0.0.0.0 | 0.0.0.0 | 2024-07-18T13:54:26.364000Z |


### meraki-organization-uplink-status-list

***
List the uplink status of every Meraki MX, MG and Z series devices in the organization.

#### Base Command

`meraki-organization-uplink-status-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |
| network_ids | Comma-separated list of network IDs to search for. Use `meraki-network-list` to fetch all network IDs. | Optional |
| serials | Comma-separated list of serial numbers to search for. Use `meraki-device-list` or `meraki-organization-device-search` to fetch serial numbers. | Optional |
| iccids | Comma-separated list of ICCIDs to search for. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| page_size | The maximum number of records to return per page. To receive additional pages after the first call, use `next_token`. Acceptable range is 3 - 1000. Default is 50. | Optional |
| next_token | Insert 'UplinkStatusLinkTokens' value received from a previous pagination command's context to further paginate through records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.UplinkStatusLinkTokens.Prev | String | Pagination token used to retrieve the previous batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.UplinkStatusLinkTokens.Next | String | Pagination token used to retrieve the next batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.UplinkStatusLinkTokens.First | String | Pagination token used to retrieve the first batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.UplinkStatusLinkTokens.Last | String | Pagination token used to retrieve the last batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.UplinkStatus.lastReportedAt | Date | Last reported time for the device. |
| CiscoMeraki.UplinkStatus.model | String | The uplink model. |
| CiscoMeraki.UplinkStatus.networkId | String | Network identifier. |
| CiscoMeraki.UplinkStatus.serial | String | The uplink serial number. |
| CiscoMeraki.UplinkStatus.highAvailability.role | String | The High Availability role of the device on the network. For devices that do not support HA, this will be 'primary'. |
| CiscoMeraki.UplinkStatus.highAvailability.enabled | Boolean | Indicates whether High Availability is enabled for the device. For devices that do not support HA, this will be 'false'. |
| CiscoMeraki.UplinkStatus.uplinks.apn | String | Access Point Name. |
| CiscoMeraki.UplinkStatus.uplinks.connectionType | String | Connection type. |
| CiscoMeraki.UplinkStatus.uplinks.dns1 | String | Primary DNS IP. |
| CiscoMeraki.UplinkStatus.uplinks.dns2 | String | Secondary DNS IP. |
| CiscoMeraki.UplinkStatus.uplinks.gateway | String | Gateway IP. |
| CiscoMeraki.UplinkStatus.uplinks.iccid | String | Integrated Circuit Card Identification number. |
| CiscoMeraki.UplinkStatus.uplinks.interface | String | Uplink interface enum = \[cellular, wan1, wan2, wan3\]. |
| CiscoMeraki.UplinkStatus.uplinks.ip | String | Uplink IP address. |
| CiscoMeraki.UplinkStatus.uplinks.ipAssignedBy | String | The way in which the IP address is assigned. |
| CiscoMeraki.UplinkStatus.uplinks.primaryDns | String | Primary DNS IP address. |
| CiscoMeraki.UplinkStatus.uplinks.provider | String | Network provider. |
| CiscoMeraki.UplinkStatus.uplinks.publicIp | String | Public IP address. |
| CiscoMeraki.UplinkStatus.uplinks.secondaryDns | String | Secondary DNS IP address. |
| CiscoMeraki.UplinkStatus.uplinks.signalType | String | Signal type. |
| CiscoMeraki.UplinkStatus.uplinks.status | String | Uplink status enum = \[active, connecting, failed, not connected, ready\]. |
| CiscoMeraki.UplinkStatus.uplinks.signalStat.rsrp | String | Reference Signal Received Power. |
| CiscoMeraki.UplinkStatus.uplinks.signalStat.rsrq | String | Reference Signal Received Quality. |

#### Command example
```!meraki-organization-uplink-status-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "UplinkStatus": {
            "highAvailability": {
                "enabled": true,
                "role": "primary"
            },
            "lastReportedAt": "2018-02-11T00:00:00Z",
            "model": "MX68C",
            "networkId": "N_24329156",
            "serial": "0000-0000-0000",
            "uplinks": [
                {
                    "apn": "internet",
                    "connectionType": "4g",
                    "dns1": "0.0.0.0",
                    "dns2": "0.0.0.0",
                    "gateway": "0.0.0.0",
                    "iccid": "123456789",
                    "interface": "wan1",
                    "ip": "0.0.0.0",
                    "ipAssignedBy": "static",
                    "primaryDns": "0.0.0.0",
                    "provider": "at&t",
                    "publicIp": "0.0.0.0",
                    "secondaryDns": "0.0.0.0",
                    "signalStat": {
                        "rsrp": "-120",
                        "rsrq": "-13"
                    },
                    "signalType": "4G",
                    "status": "active"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Uplink Status(es)
>|Serial|Network ID|Model|Last Reported At|Uplink ICCID|Uplink Interface|Uplink IP|Uplink Public IP|Uplink Signal Type|Uplink Status|
>|---|---|---|---|---|---|---|---|---|---|
>| 0000-0000-0000 | N_24329156 | MX68C | 2018-02-11T00:00:00Z | 123456789 | wan1 | 0.0.0.0 | 0.0.0.0 | 4G | active |


### meraki-organization-client-list

***
Return the client details in an organization.

#### Base Command

`meraki-organization-client-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |
| mac | The MAC address of the client. | Optional |
| limit | The maximum number of records to return. Default is 5. | Optional |
| page_size | The maximum number of records to return per page. To receive additional pages after the first call, use `next_token`. Acceptable range is 3 - 5. Default is 5. | Optional |
| next_token | Insert 'ClientLinkTokens' value received from a previous pagination command's context to further paginate through records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.ClientLinkTokens.Prev | String | Pagination token used to retrieve the previous batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.ClientLinkTokens.Next | String | Pagination token used to retrieve the next batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.ClientLinkTokens.First | String | Pagination token used to retrieve the first batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.ClientLinkTokens.Last | String | Pagination token used to retrieve the last batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.Client.clientId | String | The ID of the client. |
| CiscoMeraki.Client.mac | String | The MAC address of the client. |
| CiscoMeraki.Client.manufacturer | String | Manufacturer of the client. |
| CiscoMeraki.Client.records.firstSeen | Number | Timestamp client was first seen in the network. |
| CiscoMeraki.Client.records.lastSeen | Number | Timestamp client was last seen in the network. |
| CiscoMeraki.Client.records.description | String | Short description of the client. |
| CiscoMeraki.Client.records.ip | String | The IP address of the client. |
| CiscoMeraki.Client.records.ip6 | String | The IPv6 address of the client. |
| CiscoMeraki.Client.records.os | String | The operating system of the client. |
| CiscoMeraki.Client.records.recentDeviceMac | String | The MAC address of the node that the device was last connected to. |
| CiscoMeraki.Client.records.ssid | String | The name of the SSID that the client is connected to. |
| CiscoMeraki.Client.records.status | String | The connection status of the client enum = \[Offline, Online\]. |
| CiscoMeraki.Client.records.switchport | String | The switch port the client is connected to. |
| CiscoMeraki.Client.records.user | String | The username of the user of the client. |
| CiscoMeraki.Client.records.vlan | String | The name of the VLAN that the client is connected to. |
| CiscoMeraki.Client.records.wirelessCapabilities | String | Wireless capabilities of the client. |
| CiscoMeraki.Client.records.smInstalled | Boolean | Whether the system manager for the client is installed. |
| CiscoMeraki.Client.records.cdp | String | The Cisco discover protocol settings for the client. |
| CiscoMeraki.Client.records.lldp | String | The link layer discover protocol settings for the client. |
| CiscoMeraki.Client.records.network.enrollmentString | String | The network enrollment string. |
| CiscoMeraki.Client.records.network.id | String | The network identifier. |
| CiscoMeraki.Client.records.network.name | String | The network name. |
| CiscoMeraki.Client.records.network.notes | String | The notes for the network. |
| CiscoMeraki.Client.records.network.organizationId | String | The organization identifier. |
| CiscoMeraki.Client.records.network.timeZone | String | The network's timezone. |
| CiscoMeraki.Client.records.network.url | String | The network URL. |
| CiscoMeraki.Client.records.network.isBoundToConfigTemplate | Boolean | If the network is bound to a configuration template. |
| CiscoMeraki.Client.records.network.productTypes | String | The product types of the network. |
| CiscoMeraki.Client.records.network.tags | String | The network tags. |
| CiscoMeraki.Client.records.clientVpnConnections.connectedAt | Number | The time the client last connected to the VPN. |
| CiscoMeraki.Client.records.clientVpnConnections.disconnectedAt | Number | The time the client last disconnected from the VPN. |
| CiscoMeraki.Client.records.clientVpnConnections.remoteIp | String | The IP address of the VPN the client last connected to. |

#### Command example
```!meraki-organization-client-list mac=00:00:00:00:00:00```
#### Context Example
```json
{
    "CiscoMeraki": {
        "Client": {
            "clientId": "0000000",
            "mac": "00:00:00:00:00:00",
            "manufacturer": "Hon Hai/Foxconn",
            "records": [
                {
                    "cdp": null,
                    "clientVpnConnections": null,
                    "description": "DESKTOP-000000",
                    "firstSeen": 1720703981,
                    "ip": "0.0.0.0",
                    "ip6": "",
                    "lastSeen": 1720703981,
                    "lldp": null,
                    "network": {
                        "enrollmentString": null,
                        "id": "N_0000000003823457",
                        "isBoundToConfigTemplate": false,
                        "name": "TLV",
                        "notes": null,
                        "organizationId": "1565046",
                        "productTypes": [
                            "wireless"
                        ],
                        "tags": [],
                        "timeZone": "America/Los_Angeles",
                        "url": "https://www.example.com"
                    },
                    "os": null,
                    "recentDeviceMac": null,
                    "smInstalled": false,
                    "ssid": "TLV WiFi",
                    "status": "Offline",
                    "switchport": null,
                    "user": null,
                    "vlan": "",
                    "wirelessCapabilities": "802.11ac - 2.4 and 5 GHz"
                },
                {
                    "cdp": null,
                    "clientVpnConnections": null,
                    "description": "Lior pc",
                    "firstSeen": 1720509642,
                    "ip": "0.0.0.0",
                    "ip6": "",
                    "lastSeen": 1721310714,
                    "lldp": null,
                    "network": {
                        "enrollmentString": null,
                        "id": "L_0000",
                        "isBoundToConfigTemplate": false,
                        "name": "QMDEV",
                        "notes": null,
                        "organizationId": "1565046",
                        "productTypes": [
                            "systemsManager",
                            "wireless"
                        ],
                        "tags": [],
                        "timeZone": "Israel",
                        "url": "https://www.example.com"
                    },
                    "os": null,
                    "recentDeviceMac": "00:00:00:00:00:00",
                    "smInstalled": false,
                    "ssid": "QMDEV-temp WiFi",
                    "status": "Offline",
                    "switchport": null,
                    "user": null,
                    "vlan": "",
                    "wirelessCapabilities": "802.11ac - 2.4 and 5 GHz"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Client 0000000 MAC 00:00:00:00:00:00 Record(s)
>|Description|IP|Status|Network ID|Network Name|
>|---|---|---|---|---|
>| DESKTOP-000000 | 0.0.0.0 | Offline | N_0000000003823457 | TLV |
>| Lior pc | 0.0.0.0 | Offline | L_0000 | QMDEV |
>| DESKTOP-000000 | 0.0.0.0 | Offline | L_0000000003808704 | Main Office |
>| DESKTOP-000000 | 0.0.0.0 | Offline | L_0000000003808705 | test1 |


### meraki-network-client-list

***
List the clients that have used this network in the time span. The data is updated at most once every five minutes.

#### Base Command

`meraki-network-client-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to retrieve from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| client_id | ID of a specific client to retrieve. Clients can be identified by a client key or either the MAC or IP address depending on whether the network uses Track-by-IP. | Optional |
| t0 | The time span in days for which the information will be fetched. The maximum lookback period is 31 days from today. Accepted formats: datetime any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. | Optional |
| time_span | The time span number in seconds for which the information will be fetched. If specifying time span, do not specify parameter t0. The value must be in seconds and be less than or equal to 31 days (2678400 seconds). The default is 1 day. | Optional |
| statuses | Comma-separated list of statuses. Possible values are: online, offline. | Optional |
| ip | Filters clients based on a partial or full match for the IP address field. | Optional |
| ip6 | Filters clients based on a partial or full match for the IPv6 address field. | Optional |
| ip6_local | Filters clients based on a partial or full match for the local IPv6 address field. | Optional |
| mac | Filters clients based on a partial or full match for the MAC address field. | Optional |
| os | Filters clients based on a partial or full match for the operating system field. | Optional |
| psk_group | Filters clients based on partial or full match for the IPSK name field. | Optional |
| description | Filters clients based on a partial or full match for the description field. | Optional |
| vlan | Filters clients based on the full match for the VLAN field. | Optional |
| named_vlan | Filters clients based on the partial or full match for the named VLAN field. | Optional |
| recent_device_connections | Comma-separated list of recent connection types. Possible values are: Wired, Wireless. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| page_size | The maximum number of records to return per page. To receive additional pages after the first call, use `next_token`. Acceptable range is 3 - 5000. Default is 50. | Optional |
| next_token | Insert 'NetworkClientLinkTokens' value received from a previous pagination command's context to further paginate through records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.NetworkClientLinkTokens.Prev | String | Pagination token used to retrieve the previous batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.NetworkClientLinkTokens.Next | String | Pagination token used to retrieve the next batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.NetworkClientLinkTokens.First | String | Pagination token used to retrieve the first batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.NetworkClientLinkTokens.Last | String | Pagination token used to retrieve the last batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.NetworkClient.firstSeen | Number | Timestamp client was first seen in the network. |
| CiscoMeraki.NetworkClient.lastSeen | Number | Timestamp client was last seen in the network. |
| CiscoMeraki.NetworkClient.adaptivePolicyGroup | String | The adaptive policy group of the client. |
| CiscoMeraki.NetworkClient.description | String | Short description of the client. |
| CiscoMeraki.NetworkClient.deviceTypePrediction | String | Prediction of the client's device type. |
| CiscoMeraki.NetworkClient.groupPolicy8021x | String | 802.1x group policy of the client. |
| CiscoMeraki.NetworkClient.id | String | The ID of the client. |
| CiscoMeraki.NetworkClient.ip | String | The IP address of the client. |
| CiscoMeraki.NetworkClient.ip6 | String | The IPv6 address of the client. |
| CiscoMeraki.NetworkClient.ip6Local | String | Local IPv6 address of the client. |
| CiscoMeraki.NetworkClient.mac | String | The MAC address of the client. |
| CiscoMeraki.NetworkClient.manufacturer | String | Manufacturer of the client. |
| CiscoMeraki.NetworkClient.namedVlan | String | Named VLAN of the client. |
| CiscoMeraki.NetworkClient.notes | String | Notes on the client. |
| CiscoMeraki.NetworkClient.os | String | The operating system of the client. |
| CiscoMeraki.NetworkClient.pskGroup | String | IPSK name of the client. |
| CiscoMeraki.NetworkClient.recentDeviceConnection | String | Client's most recent connection type enum = \[Wired, Wireless\]. |
| CiscoMeraki.NetworkClient.recentDeviceMac | String | The MAC address of the node that the device was last connected to. |
| CiscoMeraki.NetworkClient.recentDeviceName | String | The name of the node the device was last connected to. |
| CiscoMeraki.NetworkClient.recentDeviceSerial | String | The serial number of the node the device was last connected to. |
| CiscoMeraki.NetworkClient.ssid | String | The name of the SSID that the client is connected to. |
| CiscoMeraki.NetworkClient.status | String | The connection status of the client enum = \[Offline, Online\]. |
| CiscoMeraki.NetworkClient.switchport | String | The switch port that the client is connected to. |
| CiscoMeraki.NetworkClient.user | String | The username of the user of the client. |
| CiscoMeraki.NetworkClient.vlan | String | The name of the VLAN that the client is connected to. |
| CiscoMeraki.NetworkClient.wirelessCapabilities | String | Wireless capabilities of the client. |
| CiscoMeraki.NetworkClient.smInstalled | Boolean | Whether the service manager for the client is installed. |
| CiscoMeraki.NetworkClient.cdp | String | The Cisco discover protocol settings for the client. |
| CiscoMeraki.NetworkClient.lldp | String | The link layer discover protocol settings for the client. |
| CiscoMeraki.NetworkClient.usage.recv | Number | Usage received by the client. |
| CiscoMeraki.NetworkClient.usage.sent | Number | Usage sent by the client. |
| CiscoMeraki.NetworkClient.clientVpnConnections.connectedAt | Number | The time the client last connected to the VPN. |
| CiscoMeraki.NetworkClient.clientVpnConnections.disconnectedAt | Number | The time the client last disconnected from the VPN. |
| CiscoMeraki.NetworkClient.clientVpnConnections.remoteIp | String | The IP address of the VPN the client last connected to. |

#### Command example
```!meraki-network-client-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "NetworkClient": {
            "adaptivePolicyGroup": null,
            "description": "Lior pc",
            "deviceTypePrediction": null,
            "firstSeen": "2024-07-09T07:20:42Z",
            "groupPolicy8021x": null,
            "id": "0000000",
            "ip": "0.0.0.0",
            "ip6": null,
            "ip6Local": "0000:0:0:0:0000:0000:0000:0000",
            "lastSeen": "2024-07-18T13:51:54Z",
            "mac": "00:00:00:00:00:00",
            "manufacturer": "Hon Hai/Foxconn",
            "namedVlan": null,
            "notes": "client note ",
            "os": null,
            "pskGroup": null,
            "recentDeviceConnection": "Wireless",
            "recentDeviceMac": "00:00:00:00:00:00",
            "recentDeviceName": "ACCESS POINT",
            "recentDeviceSerial": "0000-0000-0000",
            "smInstalled": false,
            "ssid": "QMDEV-temp WiFi",
            "status": "Offline",
            "switchport": null,
            "usage": {
                "recv": 394111,
                "sent": 7479,
                "total": 401590
            },
            "user": null,
            "vlan": "",
            "wirelessCapabilities": "802.11ac - 2.4 and 5 GHz"
        }
    }
}
```

#### Human Readable Output

>### Network Monitor Client(s)
>|ID|Description|IP|Recent Device Name|SSID|Status|Usage Received|Usage Sent|
>|---|---|---|---|---|---|---|---|
>| 0000000 | Lior pc | 0.0.0.0 | ACCESS POINT | QMDEV-temp WiFi | Offline | 394111 | 7479 |


### meraki-device-client-list

***
List the clients of a device, up to a maximum of a month ago. The usage of each client is returned in kilobytes. If the device is a switch, the switchport is returned; otherwise the switchport field is null.

#### Base Command

`meraki-device-client-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Serial number of the device to retrieve from. Use `meraki-device-list` or `meraki-organization-device-search` to fetch serial numbers. | Required |
| t0 | The time span in days for which the information will be fetched. The maximum lookback period is 31 days from today. Accepted formats: datetime any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. | Optional |
| time_span | The time span number in seconds for which the information will be fetched. If specifying time span, do not specify parameter t0. The value must be in seconds and be less than or equal to 31 days (2678400 seconds). The default is 1 day. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.DeviceClient.adaptivePolicyGroup | String | A description of the adaptive policy group. |
| CiscoMeraki.DeviceClient.description | String | Short description of the client. |
| CiscoMeraki.DeviceClient.dhcpHostname | String | The client's DHCP hostname. |
| CiscoMeraki.DeviceClient.id | String | The ID of the client. |
| CiscoMeraki.DeviceClient.ip | String | The IP address of the client. |
| CiscoMeraki.DeviceClient.mac | String | The MAC address of the client. |
| CiscoMeraki.DeviceClient.mdnsName | String | The client's MDNS name. |
| CiscoMeraki.DeviceClient.namedVlan | String | The owner-assigned name of the VLAN the client is connected to. |
| CiscoMeraki.DeviceClient.switchport | String | The name of the switchport with clients on it, if the device is a switch. |
| CiscoMeraki.DeviceClient.user | String | The client user's name. |
| CiscoMeraki.DeviceClient.vlan | String | The client-assigned name of the VLAN the client is connected to. |
| CiscoMeraki.DeviceClient.usage.recv | Number | Usage received by the client. |
| CiscoMeraki.DeviceClient.usage.sent | Number | Usage sent by the client. |

#### Command example
```!meraki-device-client-list serial=0000-0000-0000```
#### Context Example
```json
{
    "CiscoMeraki": {
        "DeviceClient": {
            "adaptivePolicyGroup": null,
            "description": "Lior pc",
            "dhcpHostname": "DESKTOP-000000",
            "id": "0000000",
            "ip": "0.0.0.0",
            "mac": "00:00:00:00:00:00",
            "mdnsName": "DESKTOP-000000.local",
            "namedVlan": "",
            "switchport": null,
            "usage": {
                "recv": 7572.45118874967,
                "sent": 394326.99434949923
            },
            "user": null,
            "vlan": 0
        }
    }
}
```

#### Human Readable Output

>### Device Monitored Client(s)
>|ID|Description|IP|MAC|MDNS Name|Usage Received|Usage Sent|
>|---|---|---|---|---|---|---|
>| 0000000 | Lior pc | 0.0.0.0 | 00:00:00:00:00:00 | DESKTOP-000000.local | 7572.45118874967 | 394326.99434949923 |


### meraki-ssid-appliance-list

***
List the MX SSIDs in a network.

#### Base Command

`meraki-ssid-appliance-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to retrieve from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| number | Number of a specific SSID to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.SSID.Appliance.defaultVlanId | Number | The VLAN ID of the VLAN associated to this SSID. |
| CiscoMeraki.SSID.Appliance.number | Number | The number of the SSID. |
| CiscoMeraki.SSID.Appliance.authMode | String | The association control method for the SSID. |
| CiscoMeraki.SSID.Appliance.encryptionMode | String | The PSK encryption mode for the SSID. |
| CiscoMeraki.SSID.Appliance.name | String | The name of the SSID. |
| CiscoMeraki.SSID.Appliance.wpaEncryptionMode | String | WPA encryption mode for the SSID. |
| CiscoMeraki.SSID.Appliance.enabled | Boolean | Whether the SSID is enabled. |
| CiscoMeraki.SSID.Appliance.visible | Boolean | Whether the MX should advertise or hide this SSID. |
| CiscoMeraki.SSID.Appliance.radiusServers.port | Number | The UDP port your RADIUS servers listens on for Access-requests. |
| CiscoMeraki.SSID.Appliance.radiusServers.host | String | The IP address of your RADIUS server. |

#### Command example
```!meraki-ssid-appliance-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "SSID": {
            "Appliance": {
                "authMode": "8021x-radius",
                "defaultVlanId": 1,
                "enabled": true,
                "encryptionMode": "wpa",
                "name": "My SSID",
                "number": 1,
                "radiusServers": [
                    {
                        "host": "0.0.0.0",
                        "port": 1000
                    }
                ],
                "visible": true,
                "wpaEncryptionMode": "WPA2 only"
            }
        }
    }
}
```

#### Human Readable Output

>### MX SSID(s)
>|Number|Name|Default VLAN ID|SSID Enabled|Visible|
>|---|---|---|---|---|
>| 1 | My SSID | 1 | true | true |


### meraki-ssid-wireless-list

***
List the MR SSIDs in a network.

#### Base Command

`meraki-ssid-wireless-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to retrieve from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| number | Number of a specific SSID to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.SSID.Wireless.minBitrate | Number | The minimum bitrate in Mbps of this SSID in the default indoor RF profile. |
| CiscoMeraki.SSID.Wireless.number | Number | Unique identifier of the SSID. |
| CiscoMeraki.SSID.Wireless.perClientBandwidthLimitDown | Number | The download bandwidth limit in Kbps. \(0 represents no limit.\). |
| CiscoMeraki.SSID.Wireless.perClientBandwidthLimitUp | Number | The upload bandwidth limit in Kbps. \(0 represents no limit.\). |
| CiscoMeraki.SSID.Wireless.perSsidBandwidthLimitDown | Number | The total download bandwidth limit in Kbps \(0 represents no limit\). |
| CiscoMeraki.SSID.Wireless.perSsidBandwidthLimitUp | Number | The total upload bandwidth limit in Kbps \(0 represents no limit\). |
| CiscoMeraki.SSID.Wireless.adminSplashUrl | String | URL for the admin splash page. |
| CiscoMeraki.SSID.Wireless.authMode | String | The association control method for the SSID enum = \[8021x-google, 8021x-localradius, 8021x-meraki, 8021x-nac, 8021x-radius, ipsk-with-nac, ipsk-with-radius, ipsk-without-radius, open, open-enhanced, open-with-nac, open-with-radius, psk\]. |
| CiscoMeraki.SSID.Wireless.bandSelection | String | The client-serving radio frequencies of this SSID in the default indoor RF profile enum = \[5 GHz band only, Dual band operation, Dual band operation with Band Steering\]. |
| CiscoMeraki.SSID.Wireless.encryptionMode | String | The PSK encryption mode for the SSID enum = \[wep, wpa\]. |
| CiscoMeraki.SSID.Wireless.ipAssignmentMode | String | The client IP assignment mode enum = \[Bridge mode, Ethernet over GRE, Layer 3 roaming, Layer 3 roaming with a concentrator, NAT mode, VPN\]. |
| CiscoMeraki.SSID.Wireless.name | String | The name of the SSID. |
| CiscoMeraki.SSID.Wireless.radiusAttributeForGroupPolicies | String | RADIUS attribute used to look up group policies enum = \[Airespace-ACL-Name, Aruba-User-Role, Filter-Id, Reply-Message\]. |
| CiscoMeraki.SSID.Wireless.radiusFailoverPolicy | String | Policy which determines how authentication requests should be handled in the event that all of the configured RADIUS servers are unreachable enum = \[Allow access, Deny access\]. |
| CiscoMeraki.SSID.Wireless.radiusLoadBalancingPolicy | String | Policy which determines which RADIUS server will be contacted first in an authentication attempt, and the ordering of any necessary retry attempts enum = \[Round robin, Strict priority order\]. |
| CiscoMeraki.SSID.Wireless.splashPage | String | The type of splash page for the SSID enum = \[Billing, Cisco ISE, Click-through splash page, Facebook Wi-Fi, Google Apps domain, Google OAuth, None, Password-protected with Active Directory, Password-protected with LDAP, Password-protected with Meraki RADIUS, Password-protected with custom RADIUS, SMS authentication, Sponsored guest, Systems Manager Sentry\]. |
| CiscoMeraki.SSID.Wireless.splashTimeout | Date | Splash page timeout. |
| CiscoMeraki.SSID.Wireless.wpaEncryptionMode | String | The types of WPA encryption enum = \[WPA1 and WPA2, WPA1 only, WPA2 only, WPA3 192-bit Security, WPA3 Transition Mode, WPA3 only\]. |
| CiscoMeraki.SSID.Wireless.availableOnAllAps | Boolean | Whether all APs broadcast the SSID or if it's restricted to APs matching any availability tags. |
| CiscoMeraki.SSID.Wireless.enabled | Boolean | Whether the SSID is enabled. |
| CiscoMeraki.SSID.Wireless.localAuth | Boolean | Extended local auth flag for Enterprise NAC. |
| CiscoMeraki.SSID.Wireless.mandatoryDhcpEnabled | Boolean | Whether clients connecting to this SSID must use the IP address assigned by the DHCP server. |
| CiscoMeraki.SSID.Wireless.radiusAccountingEnabled | Boolean | Whether or not RADIUS accounting is enabled. |
| CiscoMeraki.SSID.Wireless.radiusEnabled | Boolean | Whether RADIUS authentication is enabled. |
| CiscoMeraki.SSID.Wireless.ssidAdminAccessible | Boolean | SSID Administrator access status. |
| CiscoMeraki.SSID.Wireless.visible | Boolean | Whether the SSID is advertised. |
| CiscoMeraki.SSID.Wireless.walledGardenEnabled | Boolean | Whether to allow users to access a configurable list of IP ranges prior to sign-on. |
| CiscoMeraki.SSID.Wireless.availabilityTags | String | List of tags for this SSID. If availableOnAllAps is false, then the SSID is only broadcast by APs with tags matching any of the tags in this list. |
| CiscoMeraki.SSID.Wireless.walledGardenRanges | String | Domain names and IP address ranges available in Walled Garden mode. |
| CiscoMeraki.SSID.Wireless.radiusAccountingServers.openRoamingCertificateId | Number | The ID of the Openroaming Certificate attached to radius server. |
| CiscoMeraki.SSID.Wireless.radiusAccountingServers.port | Number | Port on the RADIUS server that is listening for accounting messages. |
| CiscoMeraki.SSID.Wireless.radiusAccountingServers.caCertificate | String | Certificate used for authorization for the RADSEC Server. |
| CiscoMeraki.SSID.Wireless.radiusAccountingServers.host | String | IP address \(or FQDN\) to which the APs will send RADIUS accounting messages. |
| CiscoMeraki.SSID.Wireless.radiusServers.openRoamingCertificateId | Number | The ID of the Openroaming Certificate attached to radius server. |
| CiscoMeraki.SSID.Wireless.radiusServers.port | Number | UDP port the RADIUS server listens on for Access-requests. |
| CiscoMeraki.SSID.Wireless.radiusServers.caCertificate | String | Certificate used for authorization for the RADSEC Server. |
| CiscoMeraki.SSID.Wireless.radiusServers.host | String | IP address \(or FQDN\) of your RADIUS server. |

#### Command example
```!meraki-ssid-wireless-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "SSID": {
            "Wireless": [
                {
                    "adultContentFilteringEnabled": false,
                    "authMode": "open",
                    "availabilityTags": [],
                    "availableOnAllAps": true,
                    "bandSelection": "Dual band operation",
                    "dnsRewrite": {
                        "dnsCustomNameservers": [],
                        "enabled": false
                    },
                    "enabled": true,
                    "ipAssignmentMode": "NAT mode",
                    "mandatoryDhcpEnabled": false,
                    "minBitrate": 11,
                    "name": "QMDEV-temp WiFi",
                    "number": 0,
                    "perClientBandwidthLimitDown": 0,
                    "perClientBandwidthLimitUp": 0,
                    "perSsidBandwidthLimitDown": 0,
                    "perSsidBandwidthLimitUp": 0,
                    "speedBurst": {
                        "enabled": false
                    },
                    "splashPage": "None",
                    "ssidAdminAccessible": false,
                    "visible": true
                },
                {
                    "adultContentFilteringEnabled": false,
                    "authMode": "open",
                    "availabilityTags": [],
                    "availableOnAllAps": true,
                    "bandSelection": "Dual band operation",
                    "dnsRewrite": {
                        "dnsCustomNameservers": [],
                        "enabled": false
                    },
                    "enabled": false,
                    "ipAssignmentMode": "NAT mode",
                    "mandatoryDhcpEnabled": false,
                    "minBitrate": 11,
                    "name": "Unconfigured SSID 2",
                    "number": 1,
                    "perClientBandwidthLimitDown": 0,
                    "perClientBandwidthLimitUp": 0,
                    "perSsidBandwidthLimitDown": 0,
                    "perSsidBandwidthLimitUp": 0,
                    "speedBurst": {
                        "enabled": false
                    },
                    "splashPage": "None",
                    "ssidAdminAccessible": false,
                    "visible": true
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### MR SSID(s)
>|Number|Name|IP Assignment Mode|Enable|Visible|
>|---|---|---|---|---|
>| 0 | QMDEV-temp WiFi | NAT mode | true | true |
>| 1 | Unconfigured SSID 2 | NAT mode | false | true |
>| 2 | Unconfigured SSID 3 | NAT mode | false | true |
>| 3 | Unconfigured SSID 4 | NAT mode | false | true |
>| 4 | Unconfigured SSID 5 | NAT mode | false | true |
>| 5 | Unconfigured SSID 6 | NAT mode | false | true |
>| 6 | Unconfigured SSID 7 | NAT mode | false | true |
>| 7 | Unconfigured SSID 8 | NAT mode | false | true |
>| 8 | Unconfigured SSID 9 | NAT mode | false | true |
>| 9 | Unconfigured SSID 10 | NAT mode | false | true |
>| 10 | Unconfigured SSID 11 | NAT mode | false | true |
>| 11 | Unconfigured SSID 12 | NAT mode | false | true |
>| 12 | Unconfigured SSID 13 | NAT mode | false | true |
>| 13 | Unconfigured SSID 14 | NAT mode | false | true |
>| 14 | Unconfigured SSID 15 | NAT mode | false | true |


### meraki-network-l3firewall-rule-list

***
List the L3 firewall rules for an MX network.

#### Base Command

`meraki-network-l3firewall-rule-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to retrieve from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.L3FirewallRule.networkId | String | ID of the network. |
| CiscoMeraki.L3FirewallRule.rules.comment | String | Comment for the rule. |
| CiscoMeraki.L3FirewallRule.rules.policy | String | Policy for the rule. |
| CiscoMeraki.L3FirewallRule.rules.protocol | String | Protocol for the rule. |
| CiscoMeraki.L3FirewallRule.rules.destPort | String | Destination port for the rule. |
| CiscoMeraki.L3FirewallRule.rules.destCidr | String | Destination CIDR for the rule. |
| CiscoMeraki.L3FirewallRule.rules.srcPort | String | Source port for the rule. |
| CiscoMeraki.L3FirewallRule.rules.srcCidr | String | Source CIDR for the rule. |
| CiscoMeraki.L3FirewallRule.rules.syslogEnabled | Boolean | Whether syslog is enabled. |

#### Command example
```!meraki-network-l3firewall-rule-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "L3FirewallRule": {
            "networkId": "L_0000",
            "rules": [
                {
                    "comment": "helloworld1",
                    "destCidr": "Any",
                    "destPort": "Any",
                    "ipVer": "ipv4",
                    "policy": "allow",
                    "protocol": "any"
                },
                {
                    "comment": "Wireless clients accessing LAN",
                    "destCidr": "Local LAN",
                    "destPort": "Any",
                    "ipVer": "ipv4",
                    "policy": "deny",
                    "protocol": "Any"
                },
                {
                    "comment": "Default rule",
                    "destCidr": "Any",
                    "destPort": "Any",
                    "ipVer": "ipv4",
                    "policy": "allow",
                    "protocol": "Any"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### L3 Firewall Rule(s)
>|Comment|Policy|Protocol|Destination Port|Destination CIDR|
>|---|---|---|---|---|
>| helloworld1 | allow | any | Any | Any |
>| Wireless clients accessing LAN | deny | Any | Any | Local LAN |
>| Default rule | allow | Any | Any | Any |


### meraki-network-l3firewall-rule-update

***
Update the L3 firewall rules of an MX network.

#### Base Command

`meraki-network-l3firewall-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to update from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| override | Whether to override the current rules. If false, will append to the current rules. Possible values are: false, true. Default is true. | Optional |
| syslog_default_rule | Log the special default rule, enable only if you've configured a syslog server. Possible values are: false, true. | Optional |
| entry_id | An entry ID of a JSON file to pass only rules. The format of a rule can be seen in the following link: https://developer.cisco.com/meraki/api-v1/update-network-appliance-firewall-l-3-firewall-rules/. Example: [{"comment": "Hello World!", "policy": "allow", "protocol": "tcp", "destPort": "443", "destCidr": "0.0.0.0/24", "srcPort": "Any", "srcCidr": "Any", "syslogEnabled": false}]. | Optional |
| comment | Description of the rule. | Optional |
| dest_cidr | Comma-separated list of destination IP address(es) (in IP or CIDR notation), fully-qualified domain names (FQDN) or 'any'. | Optional |
| dest_port | Comma-separated list of destination port(s) (integer in the range 1-65535), or 'any'. | Optional |
| src_cidr | Comma-separated list of source IP address(es) (in IP or CIDR notation), or 'any' (note: FQDN not supported for source addresses). | Optional |
| src_port | Comma-separated list of source port(s) (integer in the range 1-65535), or 'any'. | Optional |
| protocol | Type of protocol for each rule. Possible values are: tcp, udp, icmp, icmp6, any. | Optional |
| policy | Whether to allow or deny traffic specified by this rule. Possible values are: allow, deny. | Optional |
| syslog_enabled | Whether to log this rule to syslog. Only applicable if a syslog has been configured. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.L3FirewallRule.networkId | String | ID of the network. |
| CiscoMeraki.L3FirewallRule.rules.comment | String | Comment for the rule. |
| CiscoMeraki.L3FirewallRule.rules.policy | String | Policy for the rule. |
| CiscoMeraki.L3FirewallRule.rules.protocol | String | Protocol for the rule. |
| CiscoMeraki.L3FirewallRule.rules.destPort | String | Destination port for the rule. |
| CiscoMeraki.L3FirewallRule.rules.destCidr | String | Destination CIDR for the rule. |
| CiscoMeraki.L3FirewallRule.rules.srcPort | String | Source port for the rule. |
| CiscoMeraki.L3FirewallRule.rules.srcCidr | String | Source CIDR for the rule. |
| CiscoMeraki.L3FirewallRule.rules.syslogEnabled | Boolean | Whether syslog is enabled. |

#### Command example
```!meraki-network-l3firewall-rule-update dest_cidr=any policy=allow protocol=any src_cidr="0.0.0.0/24" comment=helloworld1```
#### Context Example
```json
{
    "CiscoMeraki": {
        "L3FirewallRule": {
            "networkId": "L_0000",
            "rules": [
                {
                    "comment": "helloworld1",
                    "destCidr": "Any",
                    "destPort": "Any",
                    "ipVer": "ipv4",
                    "policy": "allow",
                    "protocol": "any"
                },
                {
                    "comment": "Wireless clients accessing LAN",
                    "destCidr": "Local LAN",
                    "destPort": "Any",
                    "ipVer": "ipv4",
                    "policy": "deny",
                    "protocol": "Any"
                },
                {
                    "comment": "Default rule",
                    "destCidr": "Any",
                    "destPort": "Any",
                    "ipVer": "ipv4",
                    "policy": "allow",
                    "protocol": "Any"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### The L3 firewall rules for the network 'L_0000' were successfully updated.
>|Comment|Policy|Protocol|Destination Port|Destination CIDR|
>|---|---|---|---|---|
>| helloworld1 | allow | any | Any | Any |
>| Wireless clients accessing LAN | deny | Any | Any | Local LAN |
>| Default rule | allow | Any | Any | Any |


### meraki-network-l3firewall-rule-delete

***
Delete the L3 firewall rules from an MX network.

#### Base Command

`meraki-network-l3firewall-rule-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to delete all the L3Firewall rules for. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |

#### Context Output

There is no context output for this command.
### meraki-network-l7firewall-rule-list

***
List the MX L7 firewall rules for an MX network.

#### Base Command

`meraki-network-l7firewall-rule-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to retrieve from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.L7FirewallRule.networkId | String | ID of the network. |
| CiscoMeraki.L7FirewallRule.rules.policy | String | Policy for the rule. |
| CiscoMeraki.L7FirewallRule.rules.type | String | Type of the rule. |
| CiscoMeraki.L7FirewallRule.rules.value | String | Value for the chosen type. |

#### Command example
```!meraki-network-l7firewall-rule-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "L7FirewallRule": {
            "networkId": "L_0000",
            "rules": [
                {
                    "policy": "deny",
                    "type": "port",
                    "value": "43"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### L7 Firewall Rule(s)
>|Policy|Type|Value|
>|---|---|---|
>| deny | port | 43 |


### meraki-network-l7firewall-rule-update

***
Update the MX L7 firewall rules for an MX network.

#### Base Command

`meraki-network-l7firewall-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to update from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| override | Whether to override the current rules. If false, will append to the current rules. Possible values are: false, true. Default is true. | Optional |
| entry_id | An entry ID of a JSON file to pass only rules. The format of a rule can be seen in the following link: https://developer.cisco.com/meraki/api-v1/update-network-appliance-firewall-l-7-firewall-rules/. Example: [{"policy": "deny", "type": "host", "value": "http://www.example.com"}]. | Optional |
| value | A value of what needs to get blocked. Format of the value varies depending on the type of the firewall rule selected. | Optional |
| type | The type of the L7 firewall rule. Possible values are: application, applicationCategory, host, port, ipRange. | Optional |
| policy | The traffic specified by this rule. Possible values are: deny. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.L7FirewallRule.networkId | String | ID of the network. |
| CiscoMeraki.L7FirewallRule.rules.policy | String | Policy for the rule. |
| CiscoMeraki.L7FirewallRule.rules.type | String | Type of the rule. |
| CiscoMeraki.L7FirewallRule.rules.value | String | Value for the chosen type. |

#### Command example
```!meraki-network-l7firewall-rule-update policy=deny type=port value=43```
#### Context Example
```json
{
    "CiscoMeraki": {
        "L7FirewallRule": {
            "networkId": "L_0000",
            "rules": [
                {
                    "policy": "deny",
                    "type": "port",
                    "value": "43"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### The L7 firewall rules for the network 'L_0000' were successfully updated.
>|Policy|Type|Value|
>|---|---|---|
>| deny | port | 43 |


### meraki-network-l7firewall-rule-delete

***
Delete the L7 firewall rules from an MX network.

#### Base Command

`meraki-network-l7firewall-rule-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to delete all the L7Firewall rules for. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!meraki-network-l7firewall-rule-delete```
#### Human Readable Output

>## The L7 firewall rules of the network 'L_0000' were successfully deleted.

### meraki-organization-adaptive-policy-acl-list

***
List adaptive policy ACLs in a organization.

#### Base Command

`meraki-organization-adaptive-policy-acl-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |
| acl_id | ID of a specific ACL to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.AdaptivePolicyACL.aclId | String | ID of the adaptive policy ACL. |
| CiscoMeraki.AdaptivePolicyACL.createdAt | Date | When the adaptive policy ACL was created. |
| CiscoMeraki.AdaptivePolicyACL.description | String | Description of the adaptive policy ACL. |
| CiscoMeraki.AdaptivePolicyACL.ipVersion | String | IP version of adaptive policy ACL. |
| CiscoMeraki.AdaptivePolicyACL.name | String | Name of the adaptive policy ACL. |
| CiscoMeraki.AdaptivePolicyACL.updatedAt | Date | When the adaptive policy ACL was last updated. |
| CiscoMeraki.AdaptivePolicyACL.rules.dstPort | String | Destination port. |
| CiscoMeraki.AdaptivePolicyACL.rules.policy | String | Allow or deny traffic specified by this rule. |
| CiscoMeraki.AdaptivePolicyACL.rules.protocol | String | The type of protocol. |
| CiscoMeraki.AdaptivePolicyACL.rules.srcPort | String | Source port. |

#### Command example
```!meraki-organization-adaptive-policy-acl-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "AdaptivePolicyACL": [
            {
                "aclId": "0000000003806821",
                "createdAt": "2024-07-09T12:32:26Z",
                "description": "Blocks sensitive web traffic",
                "ipVersion": "ipv6",
                "name": "Block sensitive web traffic",
                "rules": [
                    {
                        "dstPort": "22-30",
                        "policy": "deny",
                        "protocol": "tcp",
                        "srcPort": "1,33"
                    }
                ],
                "updatedAt": "2024-07-09T12:32:26Z"
            },
            {
                "aclId": "0000000003806822",
                "createdAt": "2024-07-09T12:32:36Z",
                "description": "Blocks sensitive web traffic",
                "ipVersion": "ipv6",
                "name": "Block sensitive web traffic1",
                "rules": [
                    {
                        "dstPort": "22-30",
                        "policy": "deny",
                        "protocol": "tcp",
                        "srcPort": "1,33"
                    }
                ],
                "updatedAt": "2024-07-09T12:32:36Z"
            },
            {
                "aclId": "0000000003806823",
                "createdAt": "2024-07-09T12:32:40Z",
                "description": "Blocks sensitive web traffic",
                "ipVersion": "ipv6",
                "name": "Block sensitive web traffic2",
                "rules": [
                    {
                        "dstPort": "22-30",
                        "policy": "deny",
                        "protocol": "tcp",
                        "srcPort": "1,33"
                    }
                ],
                "updatedAt": "2024-07-09T12:32:40Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Adaptive Policy ACL(s)
>|ACL ID|Name|Description|Created At|Rules Policy|Rules Protocol|Rules Destination Port|Rules Source Port|
>|---|---|---|---|---|---|---|---|
>| 0000000003806821 | Block sensitive web traffic | Blocks sensitive web traffic | 2024-07-09T12:32:26Z | deny | tcp | 22-30 | 1,33 |
>| 0000000003806822 | Block sensitive web traffic1 | Blocks sensitive web traffic | 2024-07-09T12:32:36Z | deny | tcp | 22-30 | 1,33 |
>| 0000000003806823 | Block sensitive web traffic2 | Blocks sensitive web traffic | 2024-07-09T12:32:40Z | deny | tcp | 22-30 | 1,33 |
>| 0000000003806824 | Block sensitive web traffic3 | Blocks sensitive web traffic | 2024-07-09T12:32:43Z | deny | tcp | 22-30 | 1,33 |
>| 0000000003806825 | Block sensitive web traffic4 | Blocks sensitive web traffic | 2024-07-09T12:32:47Z | deny | tcp | 22-30 | 1,33 |


### meraki-organization-adaptive-policy-list

***
List adaptive policies in an organization. An adaptive policy is a dynamic security framework that allows automated policy enforcement across networks based on user and device identity.

#### Base Command

`meraki-organization-adaptive-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |
| adaptive_policy_id | ID of a specific adaptive policy to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.AdaptivePolicy.adaptivePolicyId | String | The ID for the adaptive policy. |
| CiscoMeraki.AdaptivePolicy.createdAt | Date | The created at timestamp for the adaptive policy. |
| CiscoMeraki.AdaptivePolicy.lastEntryRule | String | The rule to apply if there is no matching ACL. enum = \[allow, default, deny\]. |
| CiscoMeraki.AdaptivePolicy.updatedAt | Date | The updated at timestamp for the adaptive policy. |
| CiscoMeraki.AdaptivePolicy.destinationGroup.sgt | Number | The security group tag for the destination group. |
| CiscoMeraki.AdaptivePolicy.destinationGroup.id | String | The ID for the destination group. |
| CiscoMeraki.AdaptivePolicy.destinationGroup.name | String | The name for the destination group. |
| CiscoMeraki.AdaptivePolicy.sourceGroup.sgt | Number | The security group tag for the source group. |
| CiscoMeraki.AdaptivePolicy.sourceGroup.id | String | The ID for the source group. |
| CiscoMeraki.AdaptivePolicy.sourceGroup.name | String | The name for the source group. |
| CiscoMeraki.AdaptivePolicy.acls.id | String | The ID for the access control list. |
| CiscoMeraki.AdaptivePolicy.acls.name | String | The name for the access control list. |

#### Command example
```!meraki-organization-adaptive-policy-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "AdaptivePolicy": [
            {
                "acls": [],
                "adaptivePolicyId": "0000000003806834",
                "createdAt": "2024-07-09T15:48:49Z",
                "destinationGroup": {
                    "id": "0000000003809147",
                    "name": "blah",
                    "sgt": 6
                },
                "lastEntryRule": "allow",
                "sourceGroup": {
                    "id": "0000000003808988",
                    "name": "Infrastructure",
                    "sgt": 2
                },
                "updatedAt": "2024-07-09T15:48:49Z"
            },
            {
                "acls": [],
                "adaptivePolicyId": "0000000003806835",
                "createdAt": "2024-07-09T15:49:00Z",
                "destinationGroup": {
                    "id": "0000000003809149",
                    "name": "blah12",
                    "sgt": 123
                },
                "lastEntryRule": "deny",
                "sourceGroup": {
                    "id": "0000000003809148",
                    "name": "blah1",
                    "sgt": 7
                },
                "updatedAt": "2024-07-09T15:49:00Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Adaptive Policy(ies)
>|Adaptive Policy ID|Destination Group ID|Destination Group Name|Source Group ID|Source Group Name|
>|---|---|---|---|---|
>| 0000000003806834 | 0000000003809147 | blah | 0000000003808988 | Infrastructure |
>| 0000000003806835 | 0000000003809149 | blah12 | 0000000003809148 | blah1 |


### meraki-organization-adaptive-policy-group-list

***
List adaptive policy groups in a organization.

#### Base Command

`meraki-organization-adaptive-policy-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |
| adaptive_policy_group_id | ID of a specific adaptive policy group to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.AdaptivePolicyGroup.sgt | Number | The security group tag for the adaptive policy group. |
| CiscoMeraki.AdaptivePolicyGroup.createdAt | Date | Created at timestamp for the adaptive policy group. |
| CiscoMeraki.AdaptivePolicyGroup.description | String | The description for the adaptive policy group. |
| CiscoMeraki.AdaptivePolicyGroup.groupId | String | The ID of the adaptive policy group. |
| CiscoMeraki.AdaptivePolicyGroup.name | String | The name of the adaptive policy group. |
| CiscoMeraki.AdaptivePolicyGroup.updatedAt | Date | Updated at timestamp for the adaptive policy group. |
| CiscoMeraki.AdaptivePolicyGroup.isDefaultGroup | Boolean | Whether the adaptive policy group is the default group. |
| CiscoMeraki.AdaptivePolicyGroup.requiredIpMappings | String | List of required IP mappings for the adaptive policy group. |
| CiscoMeraki.AdaptivePolicyGroup.policyObjects.id | String | The ID of the policy object. |
| CiscoMeraki.AdaptivePolicyGroup.policyObjects.name | String | The name of the policy object. |

#### Command example
```!meraki-organization-adaptive-policy-group-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "AdaptivePolicyGroup": [
            {
                "createdAt": "2024-06-02T11:28:44Z",
                "description": "Created by Meraki, the Unknown group applies when a policy is specified for unsuccessful group classification",
                "groupId": "0000000003808987",
                "isDefaultGroup": true,
                "name": "Unknown",
                "policyObjects": [],
                "requiredIpMappings": [],
                "sgt": 0,
                "updatedAt": "2024-06-02T11:28:44Z"
            },
            {
                "createdAt": "2024-06-02T11:28:44Z",
                "description": "Created by Meraki, the Infrastructure group is used by Meraki devices for internal and dashboard communication",
                "groupId": "0000000003808988",
                "isDefaultGroup": true,
                "name": "Infrastructure",
                "policyObjects": [],
                "requiredIpMappings": [
                    "0.0.0.0/32",
                    "0.0.0.0/32",
                    "0.0.0.0/32"
                ],
                "sgt": 2,
                "updatedAt": "2024-06-02T11:28:44Z"
            },
            {
                "createdAt": "2024-07-09T15:48:12Z",
                "description": "asdas",
                "groupId": "0000000003809147",
                "isDefaultGroup": false,
                "name": "blah",
                "policyObjects": [],
                "requiredIpMappings": [],
                "sgt": 6,
                "updatedAt": "2024-07-09T15:48:12Z"
            },
            {
                "createdAt": "2024-07-09T15:48:26Z",
                "description": "asdas",
                "groupId": "0000000003809148",
                "isDefaultGroup": false,
                "name": "blah1",
                "policyObjects": [],
                "requiredIpMappings": [],
                "sgt": 7,
                "updatedAt": "2024-07-09T15:48:26Z"
            },
            {
                "createdAt": "2024-07-09T15:48:33Z",
                "description": "asdas",
                "groupId": "0000000003809149",
                "isDefaultGroup": false,
                "name": "blah12",
                "policyObjects": [],
                "requiredIpMappings": [],
                "sgt": 123,
                "updatedAt": "2024-07-09T15:48:33Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Adaptive Policy Group(s)
>|Group ID|Name|Description|Security Group Tag|
>|---|---|---|---|
>| 0000000003808987 | Unknown | Created by Meraki, the Unknown group applies when a policy is specified for unsuccessful group classification | 0 |
>| 0000000003808988 | Infrastructure | Created by Meraki, the Infrastructure group is used by Meraki devices for internal and dashboard communication | 2 |
>| 0000000003809147 | blah | asdas | 6 |
>| 0000000003809148 | blah1 | asdas | 7 |
>| 0000000003809149 | blah12 | asdas | 123 |


### meraki-organization-adaptive-policy-settings-list

***
Returns global adaptive policy settings in an organization.

#### Base Command

`meraki-organization-adaptive-policy-settings-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.AdaptivePolicySettings.organizationId | String | ID of the organization that the settings belong to. |
| CiscoMeraki.AdaptivePolicySettings.enabledNetworks | String | List of network IDs with adaptive policy enabled. |

#### Command example
```!meraki-organization-adaptive-policy-settings-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "AdaptivePolicySettings": {
            "enabledNetworks": [],
            "organizationId": "1565046"
        }
    }
}
```

#### Human Readable Output

>### Adaptive Policy Settings
>**No entries.**


### meraki-organization-branding-policy-list

***
List the branding policies of an organization. This allows MSPs to view and monitor certain aspects of Dashboard for their users and customers.

#### Base Command

`meraki-organization-branding-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | ID of the organization to retrieve from. Use `meraki-organization-list` to fetch all organization IDs. This overrides the organization ID instance parameter. | Optional |
| branding_policy_id | ID of a specific branding policy to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.BrandingPolicy.name | String | Name of the Dashboard branding policy. |
| CiscoMeraki.BrandingPolicy.enabled | Boolean | Boolean indicating whether this policy is enabled. |
| CiscoMeraki.BrandingPolicy.adminSettings.appliesTo | String | Which kinds of admins this policy applies to. Can be one of 'All organization admins', 'All enterprise admins', 'All network admins', 'All admins of networks...', 'All admins of networks tagged...', 'Specific admins...', 'All admins' or 'All SAML admins'. |
| CiscoMeraki.BrandingPolicy.adminSettings.values | String | If 'appliesTo' is set to one of 'Specific admins...', 'All admins of networks...' or 'All admins of networks tagged...', then you must specify this 'values' property to provide the set of entities to apply the branding policy to. For 'Specific admins...', specify an array of admin IDs. For 'All admins of networks...', specify an array of network IDs and/or configuration template IDs. For 'All admins of networks tagged...', specify an array of tag names. |
| CiscoMeraki.BrandingPolicy.customLogo.enabled | Boolean | Whether there is a custom logo enabled. |
| CiscoMeraki.BrandingPolicy.customLogo.image.preview.expiresAt | Date | Timestamp of the preview image. |
| CiscoMeraki.BrandingPolicy.customLogo.image.preview.url | String | URL of the preview image. |
| CiscoMeraki.BrandingPolicy.helpSettings.apiDocsSubtab | String | The 'Help -&gt; API docs' subtab where a detailed description of the Dashboard API is listed. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.casesSubtab | String | The 'Help -&gt; Cases' Dashboard subtab on which Cisco Meraki support cases for this organization can be managed. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.ciscoMerakiProductDocumentation | String | The 'Product Manuals' section of the 'Help -&gt; Get Help' subtab. Can be one of 'default or inherit', 'hide', 'show', or a replacement custom HTML string. |
| CiscoMeraki.BrandingPolicy.helpSettings.communitySubtab | String | The 'Help -&gt; Community' subtab which provides a link to Meraki Community. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.dataProtectionRequestsSubtab | String | The 'Help -&gt; Data protection requests' Dashboard subtab on which requests to delete, restrict, or export end-user data can be audited. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.firewallInfoSubtab | String | The 'Help -&gt; Firewall info' subtab where necessary upstream firewall rules for communication to the Cisco Meraki cloud are listed. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.getHelpSubtab | String | The 'Help -&gt; Get Help' subtab on which Cisco Meraki KB, Product Manuals, and Support/Case Information are displayed. Note that if this subtab is hidden, branding customizations for the KB on 'Get help', Cisco Meraki product documentation, and support contact info will not be visible. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.getHelpSubtabKnowledgeBaseSearch | String | The KB search box which appears on the Help page. Can be one of 'default or inherit', 'hide', 'show', or a replacement custom HTML string. |
| CiscoMeraki.BrandingPolicy.helpSettings.hardwareReplacementsSubtab | String | The 'Help -&gt; Replacement info' subtab where important information regarding device replacements is detailed. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.helpTab | String | The Help tab, under which all support information resides. If this tab is hidden, no other 'Help' branding customizations will be visible. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.helpWidget | String | The 'Help Widget' is a support widget which provides access to live chat, documentation links, Sales contact info, and other contact avenues to reach Meraki Support. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.newFeaturesSubtab | String | The 'Help -&gt; New features' subtab where new Dashboard features are detailed. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.smForums | String | The 'SM Forums' subtab which links to community-based support for Cisco Meraki Systems Manager. Only configurable for organizations that contain Systems Manager networks. Can be one of 'default or inherit', 'hide' or 'show'. |
| CiscoMeraki.BrandingPolicy.helpSettings.supportContactInfo | String | The 'Contact Meraki Support' section of the 'Help -&gt; Get Help' subtab. Can be one of 'default or inherit', 'hide', 'show', or a replacement custom HTML string. |
| CiscoMeraki.BrandingPolicy.helpSettings.universalSearchKnowledgeBaseSearch | String | The universal search box always visible on Dashboard will, by default, present results from the Meraki KB. This configures whether these Meraki KB results should be returned. Can be one of 'default or inherit', 'hide' or 'show'. |

#### Command example
```!meraki-organization-branding-policy-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "BrandingPolicy": {
            "adminSettings": {
                "appliesTo": "All admins of networks...",
                "values": [
                    "N_1234",
                    "L_5678"
                ]
            },
            "customLogo": {
                "enabled": true,
                "image": {
                    "preview": {
                        "expiresAt": "2022-04-06T06:19:27-07:00",
                        "url": "http://www.example.com"
                    }
                }
            },
            "enabled": true,
            "helpSettings": {
                "apiDocsSubtab": "default or inherit",
                "casesSubtab": "hide",
                "ciscoMerakiProductDocumentation": "show",
                "communitySubtab": "show",
                "dataProtectionRequestsSubtab": "default or inherit",
                "firewallInfoSubtab": "hide",
                "getHelpSubtab": "default or inherit",
                "getHelpSubtabKnowledgeBaseSearch": "<h1>Some custom HTML content</h1>",
                "hardwareReplacementsSubtab": "hide",
                "helpTab": "show",
                "helpWidget": "hide",
                "newFeaturesSubtab": "show",
                "smForums": "hide",
                "supportContactInfo": "show",
                "universalSearchKnowledgeBaseSearch": "hide"
            },
            "name": "My Branding Policy"
        }
    }
}
```

#### Human Readable Output

>### Branding Policy(ies)
>|Name|Enabled|Admin Settings Values|
>|---|---|---|
>| My Branding Policy | true | N_1234,<br/>L_5678 |


### meraki-network-group-policy-list

***
List the group policies in a network.

#### Base Command

`meraki-network-group-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to retrieve from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| group_policy_id | ID of a specific group policy to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.GroupPolicy.groupPolicyId | String | The ID of the group policy. |
| CiscoMeraki.GroupPolicy.name | String | The name of the group policy. |
| CiscoMeraki.GroupPolicy.splashAuthSettings | String | Whether clients bound to your policy will bypass splash authorization or behave according to the network's rules. Can be one of 'network default' or 'bypass'. Only available if your network has a wireless configuration. |
| CiscoMeraki.GroupPolicy.bandwidth.settings | String | How bandwidth limits are enforced. Can be 'network default', 'ignore' or 'custom'. |
| CiscoMeraki.GroupPolicy.bandwidth.bandwidthLimits.limitDown | Number | The maximum download limit \(integer, in Kbps\). null indicates no limit. |
| CiscoMeraki.GroupPolicy.bandwidth.bandwidthLimits.limitUp | Number | The maximum upload limit \(integer, in Kbps\). null indicates no limit. |
| CiscoMeraki.GroupPolicy.bonjourForwarding.settings | String | How Bonjour rules are applied. Can be 'network default', 'ignore' or 'custom'. |
| CiscoMeraki.GroupPolicy.bonjourForwarding.rules.description | String | A description for your Bonjour forwarding rule. |
| CiscoMeraki.GroupPolicy.bonjourForwarding.rules.vlanId | String | The ID of the service VLAN. |
| CiscoMeraki.GroupPolicy.bonjourForwarding.rules.services | String | A list of Bonjour services. At least one service must be specified. Available services are 'All Services', 'AirPlay', 'AFP', 'BitTorrent', 'FTP', 'iChat', 'iTunes', 'Printers', 'Samba', 'Scanners' and 'SSH'. |
| CiscoMeraki.GroupPolicy.contentFiltering.allowedUrlPatterns.settings | String | How URL patterns are applied. Can be 'network default', 'append' or 'override'. |
| CiscoMeraki.GroupPolicy.contentFiltering.allowedUrlPatterns.patterns | String | A list of URL patterns that are allowed. |
| CiscoMeraki.GroupPolicy.contentFiltering.blockedUrlCategories.settings | String | How URL categories are applied. Can be 'network default', 'append' or 'override'. |
| CiscoMeraki.GroupPolicy.contentFiltering.blockedUrlCategories.categories | String | A list of URL categories to block. |
| CiscoMeraki.GroupPolicy.contentFiltering.blockedUrlPatterns.settings | String | How URL patterns are applied. Can be 'network default', 'append' or 'override'. |
| CiscoMeraki.GroupPolicy.contentFiltering.blockedUrlPatterns.patterns | String | A list of URL patterns that are blocked. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.settings | String | How firewall and traffic shaping rules are enforced. Can be 'network default', 'ignore' or 'custom'. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.l3FirewallRules.comment | String | Description of the rule. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.l3FirewallRules.destCidr | String | Destination IP address \(in IP or CIDR notation\), a fully-qualified domain name \(FQDN, if your network supports it\) or 'any'. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.l3FirewallRules.destPort | String | Destination port \(integer in the range 1-65535\), a port range \(e.g., 8080-9090\), or 'any'. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.l3FirewallRules.policy | String | Allow or deny traffic specified by this rule. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.l3FirewallRules.protocol | String | The type of protocol \(must be 'tcp', 'udp', 'icmp', 'icmp6' or 'any'\). |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.l7FirewallRules.policy | String | The policy applied to matching traffic. Must be 'deny'. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.l7FirewallRules.type | String | Type of the L7 Rule. Must be 'application', 'applicationCategory', 'host', 'port' or 'ipRange'. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.l7FirewallRules.value | String | The 'value' of what you want to block. If 'type' is 'host', 'port' or 'ipRange', 'value' must be a string matching either a hostname \(e.g. somewhere.com\), a port \(e.g., 8080\), or an IP range \(e.g., 0.0.0.0/16\). If 'type' is 'application' or 'applicationCategory', then 'value' must be an object with an ID for the application. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.trafficShapingRules.dscpTagValue | Number | The DSCP tag applied by your rule. null means 'Do not change DSCP tag'. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.trafficShapingRules.pcpTagValue | Number | The PCP tag applied by your rule. Can be 0 \(lowest priority\) through 7 \(highest priority\). null means 'Do not set PCP tag'. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.trafficShapingRules.priority | String | A string, indicating the priority level for packets bound to your rule. Can be 'low', 'normal' or 'high'. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.trafficShapingRules.perClientBandwidthLimits.settings | String | How bandwidth limits are applied by your rule. Can be one of 'network default', 'ignore' or 'custom'. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.trafficShapingRules.perClientBandwidthLimits.bandwidthLimits.limitDown | Number | The maximum download limit \(integer, in Kbps\). |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.trafficShapingRules.perClientBandwidthLimits.bandwidthLimits.limitUp | Number | The maximum upload limit \(integer, in Kbps\). |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.trafficShapingRules.definitions.type | String | The type of definition. Can be one of 'application', 'applicationCategory', 'host', 'port', 'ipRange' or 'localNet'. |
| CiscoMeraki.GroupPolicy.firewallAndTrafficShaping.trafficShapingRules.definitions.value | String | If "type" is 'host', 'port', 'ipRange' or 'localNet', then "value" must be a string, matching either a hostname \(e.g., "somesite.com"\), a port \(e.g., 8080\), or an IP range \("0.0.0.0", "0.0.0.0/16", or "10.1.0.0/16:80"\). 'localNet' also supports CIDR notation, excluding custom ports. |
| CiscoMeraki.GroupPolicy.scheduling.enabled | Boolean | Whether scheduling is enabled \(true\) or disabled \(false\). Defaults to false. If true, the schedule objects for each day of the week \(monday - sunday\) are parsed. |
| CiscoMeraki.GroupPolicy.scheduling.friday.from | Date | The time, from '00:00' to '24:00'. Must be less than the time specified in 'to'. Defaults to '00:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.friday.to | Date | The time, from '00:00' to '24:00'. Must be greater than the time specified in 'from'. Defaults to '24:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.friday.active | Boolean | Whether the schedule is active \(true\) or inactive \(false\) during the time specified between 'from' and 'to'. Defaults to true. |
| CiscoMeraki.GroupPolicy.scheduling.monday.from | Date | The time, from '00:00' to '24:00'. Must be less than the time specified in 'to'. Defaults to '00:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.monday.to | Date | The time, from '00:00' to '24:00'. Must be greater than the time specified in 'from'. Defaults to '24:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.monday.active | Boolean | Whether the schedule is active \(true\) or inactive \(false\) during the time specified between 'from' and 'to'. Defaults to true. |
| CiscoMeraki.GroupPolicy.scheduling.saturday.from | Date | The time, from '00:00' to '24:00'. Must be less than the time specified in 'to'. Defaults to '00:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.saturday.to | Date | The time, from '00:00' to '24:00'. Must be greater than the time specified in 'from'. Defaults to '24:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.saturday.active | Boolean | Whether the schedule is active \(true\) or inactive \(false\) during the time specified between 'from' and 'to'. Defaults to true. |
| CiscoMeraki.GroupPolicy.scheduling.sunday.from | Date | The time, from '00:00' to '24:00'. Must be less than the time specified in 'to'. Defaults to '00:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.sunday.to | Date | The time, from '00:00' to '24:00'. Must be greater than the time specified in 'from'. Defaults to '24:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.sunday.active | Boolean | Whether the schedule is active \(true\) or inactive \(false\) during the time specified between 'from' and 'to'. Defaults to true. |
| CiscoMeraki.GroupPolicy.scheduling.thursday.from | Date | The time, from '00:00' to '24:00'. Must be less than the time specified in 'to'. Defaults to '00:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.thursday.to | Date | The time, from '00:00' to '24:00'. Must be greater than the time specified in 'from'. Defaults to '24:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.thursday.active | Boolean | Whether the schedule is active \(true\) or inactive \(false\) during the time specified between 'from' and 'to'. Defaults to true. |
| CiscoMeraki.GroupPolicy.scheduling.tuesday.from | Date | The time, from '00:00' to '24:00'. Must be less than the time specified in 'to'. Defaults to '00:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.tuesday.to | Date | The time, from '00:00' to '24:00'. Must be greater than the time specified in 'from'. Defaults to '24:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.tuesday.active | Boolean | Whether the schedule is active \(true\) or inactive \(false\) during the time specified between 'from' and 'to'. Defaults to true. |
| CiscoMeraki.GroupPolicy.scheduling.wednesday.from | Date | The time, from '00:00' to '24:00'. Must be less than the time specified in 'to'. Defaults to '00:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.wednesday.to | Date | The time, from '00:00' to '24:00'. Must be greater than the time specified in 'from'. Defaults to '24:00'. Only 30 minute increments are allowed. |
| CiscoMeraki.GroupPolicy.scheduling.wednesday.active | Boolean | Whether the schedule is active \(true\) or inactive \(false\) during the time specified between 'from' and 'to'. Defaults to true. |
| CiscoMeraki.GroupPolicy.vlanTagging.settings | String | How VLAN tagging is applied. Can be 'network default', 'ignore' or 'custom'. |
| CiscoMeraki.GroupPolicy.vlanTagging.vlanId | String | The ID of the VLAN you want to tag. This only applies if 'settings' is set to 'custom'. |

#### Command example
```!meraki-network-group-policy-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "GroupPolicy": [
            {
                "bandwidth": {
                    "bandwidthLimits": {
                        "limitDown": null,
                        "limitUp": null
                    },
                    "settings": "network default"
                },
                "bonjourForwarding": {
                    "rules": [],
                    "settings": "network default"
                },
                "firewallAndTrafficShaping": {
                    "l3FirewallRules": [],
                    "l7FirewallRules": [],
                    "settings": "network default",
                    "trafficShapingRules": []
                },
                "groupPolicyId": "101",
                "name": "3",
                "scheduling": {
                    "enabled": false,
                    "friday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "monday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "saturday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "sunday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "thursday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "tuesday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "wednesday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    }
                },
                "splashAuthSettings": "network default",
                "vlanTagging": {
                    "settings": "network default"
                }
            },
            {
                "bandwidth": {
                    "bandwidthLimits": {
                        "limitDown": null,
                        "limitUp": null
                    },
                    "settings": "network default"
                },
                "bonjourForwarding": {
                    "rules": [],
                    "settings": "network default"
                },
                "firewallAndTrafficShaping": {
                    "l3FirewallRules": [],
                    "l7FirewallRules": [],
                    "settings": "network default",
                    "trafficShapingRules": []
                },
                "groupPolicyId": "100",
                "name": "New group",
                "scheduling": {
                    "enabled": true,
                    "friday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "monday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "saturday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "sunday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "thursday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "tuesday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    },
                    "wednesday": {
                        "active": true,
                        "from": "00:00",
                        "to": "24:00"
                    }
                },
                "splashAuthSettings": "network default",
                "vlanTagging": {
                    "settings": "network default"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Group Policy(ies)
>|Group Policy ID|Group Policy Name|Group Splash Auth Settings|
>|---|---|---|
>| 101 | 3 | network default |
>| 100 | New group | network default |


### meraki-network-client-policy-list

***
List all policies owned by each client.

#### Base Command

`meraki-network-client-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to retrieve from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| t0 | The time span in days for which the information will be fetched. The maximum lookback period is 31 days from today. Accepted formats: datetime any substring of yyyy-mm-ddThh:mm:ssZ, epoch 1720617001, relative 1 day 2h 3 minute. | Optional |
| time_span | The time span number in seconds for which the information will be fetched. If specifying time span, do not specify parameter t0. The value must be in seconds and be less than or equal to 31 days (2678400 seconds). The default is 1 day. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| page_size | The maximum number of records to return per page. To receive additional pages after the first call, use `next_token`. Acceptable range is 3 - 1000. Default is 50. | Optional |
| next_token | Insert 'ClientPolicyLinkTokens' value received from a previous pagination command's context to further paginate through records. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.ClientPolicyLinkTokens.Prev | String | Pagination token used to retrieve the previous batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.ClientPolicyLinkTokens.Next | String | Pagination token used to retrieve the next batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.ClientPolicyLinkTokens.First | String | Pagination token used to retrieve the first batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.ClientPolicyLinkTokens.Last | String | Pagination token used to retrieve the last batch of records by inserting the value into 'next_token'. |
| CiscoMeraki.ClientPolicy.clientId | String | ID of client. |
| CiscoMeraki.ClientPolicy.name | String | Name of client. |
| CiscoMeraki.ClientPolicy.mac | String | MAC of client. |
| CiscoMeraki.ClientPolicy.assigned.groupPolicyId | String | ID of policy. |
| CiscoMeraki.ClientPolicy.assigned.name | String | Name of policy. |
| CiscoMeraki.ClientPolicy.assigned.type | String | Type of policy. |
| CiscoMeraki.ClientPolicy.assigned.ssid.ssidNumber | Number | SSID number. |

#### Command example
```!meraki-network-client-policy-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "ClientPolicy": {
            "assigned": [],
            "clientId": "0000000",
            "mac": "00:00:00:00:00:00",
            "name": "Lior pc"
        }
    }
}
```

#### Human Readable Output

>### Client's Policies
>|Client ID|Name|
>|---|---|
>| 0000000 | Lior pc |


### meraki-network-vlan-profile-list

***
List VLAN profiles for a network.

#### Base Command

`meraki-network-vlan-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to retrieve from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| iname | Iname of a specific VLAN profile to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.VlanProfile.iname | String | Iname of the VLAN profile. |
| CiscoMeraki.VlanProfile.name | String | Name of the profile, string length must be from 1 to 255 characters. |
| CiscoMeraki.VlanProfile.isDefault | Boolean | The default VLAN Profile for any device that does not have a profile explicitly assigned. |
| CiscoMeraki.VlanProfile.vlanGroups.name | String | Name of the VLAN, string length must be from 1 to 32 characters. |
| CiscoMeraki.VlanProfile.vlanGroups.vlanIds | String | Comma-separated VLAN IDs or ID ranges. |
| CiscoMeraki.VlanProfile.vlanNames.name | String | Name of the VLAN, string length must be from 1 to 32 characters. |
| CiscoMeraki.VlanProfile.vlanNames.vlanId | String | VLAN ID. |
| CiscoMeraki.VlanProfile.vlanNames.adaptivePolicyGroup.id | String | Adaptive Policy Group ID. |
| CiscoMeraki.VlanProfile.vlanNames.adaptivePolicyGroup.name | String | Adaptive Policy Group name. |

#### Command example
```!meraki-network-vlan-profile-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "VlanProfile": {
            "iname": "Default",
            "isDefault": true,
            "name": "Default Profile",
            "vlanGroups": [],
            "vlanNames": [
                {
                    "name": "default",
                    "vlanId": "1"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### VLAN Profile(s)
>|IName|Name|Is Default|VLAN Names|
>|---|---|---|---|
>| Default | Default Profile | true | default |


### meraki-network-appliance-vlan-list

***
List the VLANs for an MX network.

#### Base Command

`meraki-network-appliance-vlan-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_id | ID of the network to retrieve from. Use `meraki-network-list` to fetch all network IDs. This overrides the network ID instance parameter. | Optional |
| vlan_id | ID of a specific VLAN profile to retrieve. | Optional |
| limit | The maximum number of records to return. Default is 50. | Optional |
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoMeraki.ApplianceVlan.mask | Number | Mask used for the subnet of all bound to the template networks. Applicable only for template network. |
| CiscoMeraki.ApplianceVlan.applianceIp | String | The local IP address of the appliance on the VLAN. |
| CiscoMeraki.ApplianceVlan.cidr | String | CIDR of the pool of subnets. Applicable only for template network. Each network bound to the template will automatically pick a subnet from this pool to build its own VLAN. |
| CiscoMeraki.ApplianceVlan.dhcpBootFilename | String | DHCP boot option for boot filename. |
| CiscoMeraki.ApplianceVlan.dhcpBootNextServer | String | DHCP boot option to direct boot clients to the server to load the boot file from. |
| CiscoMeraki.ApplianceVlan.dhcpHandling | String | The appliance's handling of DHCP requests on this VLAN. One of 'Run a DHCP server', 'Relay DHCP to another server' or 'Do not respond to DHCP requests'. |
| CiscoMeraki.ApplianceVlan.dhcpLeaseTime | String | The term of DHCP leases if the appliance is running a DHCP server on this VLAN. One of '30 minutes', '1 hour', '4 hours', '12 hours', '1 day' or '1 week'. |
| CiscoMeraki.ApplianceVlan.dnsNameservers | String | The DNS nameservers used for DHCP responses, either "upstream_dns", "google_dns", "opendns", or a newline separated string of IP addresses or domain names. |
| CiscoMeraki.ApplianceVlan.groupPolicyId | String | The ID of the desired group policy to apply to the VLAN. |
| CiscoMeraki.ApplianceVlan.id | String | The VLAN ID of the VLAN. |
| CiscoMeraki.ApplianceVlan.interfaceId | String | The interface ID of the VLAN. |
| CiscoMeraki.ApplianceVlan.name | String | The name of the VLAN. |
| CiscoMeraki.ApplianceVlan.subnet | String | The subnet of the VLAN. |
| CiscoMeraki.ApplianceVlan.templateVlanType | String | Type of subnetting of the VLAN. Applicable only for template network. |
| CiscoMeraki.ApplianceVlan.vpnNatSubnet | String | The translated VPN subnet if VPN and VPN subnet translation are enabled on the VLAN. |
| CiscoMeraki.ApplianceVlan.dhcpBootOptionsEnabled | Boolean | Use DHCP boot options specified in other properties. |
| CiscoMeraki.ApplianceVlan.fixedIpAssignments | String | The DHCP fixed IP assignments on the VLAN. This should be an object that contains mappings from MAC addresses to objects that themselves each contain "ip" and "name" string fields. See the sample request/response for more details. |
| CiscoMeraki.ApplianceVlan.dhcpRelayServerIps | String | The IP addresses of the DHCP servers that DHCP requests should be relayed to. |
| CiscoMeraki.ApplianceVlan.ipv6.enabled | Boolean | Whether to enable IPv6 on VLAN. |
| CiscoMeraki.ApplianceVlan.ipv6.prefixAssignments.staticApplianceIp6 | String | Manual configuration of the IPv6 Appliance IP. |
| CiscoMeraki.ApplianceVlan.ipv6.prefixAssignments.staticPrefix | String | Manual configuration of a /64 prefix on the VLAN. |
| CiscoMeraki.ApplianceVlan.ipv6.prefixAssignments.autonomous | Boolean | Whether to auto assign a /64 prefix from the origin to the VLAN. |
| CiscoMeraki.ApplianceVlan.ipv6.prefixAssignments.origin.type | String | Type of the origin enum = \[independent, internet\]. |
| CiscoMeraki.ApplianceVlan.ipv6.prefixAssignments.origin.interfaces | String | Interfaces associated with the prefix. |
| CiscoMeraki.ApplianceVlan.mandatoryDhcp.enabled | Boolean | Whether to enable mandatory DHCP on VLAN. |
| CiscoMeraki.ApplianceVlan.dhcpOptions.code | String | The code for the DHCP option. This should be an integer between 2 and 254. |
| CiscoMeraki.ApplianceVlan.dhcpOptions.type | String | The type for the DHCP option. One of 'text', 'ip', 'hex' or 'integer'. |
| CiscoMeraki.ApplianceVlan.dhcpOptions.value | String | The value for the DHCP option. |
| CiscoMeraki.ApplianceVlan.reservedIpRanges.comment | String | A text comment for the reserved range. |
| CiscoMeraki.ApplianceVlan.reservedIpRanges.end | String | The last IP address in the reserved range. |
| CiscoMeraki.ApplianceVlan.reservedIpRanges.start | String | The first IP address in the reserved range. |

#### Command example
```!meraki-network-appliance-vlan-list```
#### Context Example
```json
{
    "CiscoMeraki": {
        "ApplianceVlan": {
            "applianceIp": "0.0.0.0",
            "cidr": "0.0.0.0/24",
            "dhcpBootFilename": "sample.file",
            "dhcpBootNextServer": "0.0.0.0",
            "dhcpBootOptionsEnabled": false,
            "dhcpHandling": "Run a DHCP server",
            "dhcpLeaseTime": "1 day",
            "dhcpOptions": [
                {
                    "code": "5",
                    "type": "text",
                    "value": "five"
                }
            ],
            "dhcpRelayServerIps": [
                "0.0.0.0/24",
                "0.0.0.0/24"
            ],
            "dnsNameservers": "google_dns",
            "fixedIpAssignments": {
                "00:00:00:00:00:00": {
                    "ip": "0.0.0.0",
                    "name": "My favorite IP"
                }
            },
            "groupPolicyId": "101",
            "id": "1234",
            "interfaceId": "1284392014819",
            "ipv6": {
                "enabled": true,
                "prefixAssignments": [
                    {
                        "autonomous": false,
                        "origin": {
                            "interfaces": [
                                "wan0"
                            ],
                            "type": "internet"
                        },
                        "staticApplianceIp6": "0000:000:0000:00::0",
                        "staticPrefix": "0000:000:0000:00::/64"
                    }
                ]
            },
            "mandatoryDhcp": {
                "enabled": true
            },
            "mask": 28,
            "name": "My VLAN",
            "reservedIpRanges": [
                {
                    "comment": "A reserved IP range",
                    "end": "0.0.0.0",
                    "start": "0.0.0.0"
                }
            ],
            "subnet": "0.0.0.0/24",
            "templateVlanType": "same",
            "vpnNatSubnet": "0.0.0.0/24"
        }
    }
}
```

#### Human Readable Output

>### MX VLAN(s)
>|ID|Name|Group Policy ID|Interface ID|Appliance IP|Mask|CIDR|Subnet|
>|---|---|---|---|---|---|---|---|
>| 1234 | My VLAN | 101 | 1284392014819 | 0.0.0.0 | 28 | 0.0.0.0/24 | 0.0.0.0/24 |


## Breaking changes from the previous version of this integration - Cisco Meraki v2
The following sections list the changes in this version.

### Commands
The following commands were removed in this version:
* ***meraki-fetch-organizations*** - this command was replaced by ***meraki-organization-list***.
* ***meraki-get-organization-license-state*** - this command was replaced by ***meraki-organization-license-state-list***.
* ***meraki-fetch-organization-inventory*** - this command was replaced by ***meraki-organization-inventory-list***.
* ***meraki-fetch-networks*** - this command was replaced by ***meraki-network-list***.
* ***meraki-fetch-devices*** - this command was replaced by ***meraki-device-list***.
* ***meraki-fetch-device-uplink*** - this command was replaced by ***meraki-organization-uplink-status-list***.
* ***meraki-fetch-ssids*** - this command was replaced by ***meraki-network-appliance-ssid-list***.
* ***meraki-fetch-clients*** - this command was replaced by ***meraki-device-client-list***.
* ***meraki-fetch-firewall-rules*** - this command was replaced by ***meraki-network-l3firewall-rule-list***.
* ***meraki-remove-device*** - this command was replaced by ***meraki-device-remove***.
* ***meraki-get-device*** - this command was replaced by ***meraki-device-list***.
* ***meraki-update-device*** - this command was replaced by ***meraki-device-update***.
* ***meraki-claim-device*** - this command was replaced by ***meraki-device-claim***.
* ***meraki-update-firewall-rules*** - this command was replaced by ***meraki-network-l3firewall-rule-update****.