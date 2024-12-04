RiskIQ Digital Footprint integration enables your security team to manage assets outside your firewall, by bringing its details, providing you to add or update assets and analyze your digital footprint from the view of the global adversary with the help of various commands that summarise the activities performed on your assets.
This integration was integrated and tested with enterprise version of RiskIQDigitalFootprint.
## Configure RiskIQDigitalFootprint in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | API URL | True |
| token | API Token | True |
| secret | API Secret | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### df-asset-connections
***
Retrieve the set of assets that are connected to the requested asset.


#### Base Command

`df-asset-connections`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of the asset for which connections are to be fetched.Valid Types: Domain, Host, IP Address, IP Block, ASN, Page, SSL Cert, Contact. This argument supports a single value only. | Required | 
| name | The name of the asset for which connections are to be fetched. For example riskiq.com, 8.8.8.8, mail.net, etc. This argument supports a single value only. | Required | 
| global | Setting this value to true will search all of the global inventory. Setting it to false will search for assets in the workspace associated with the authentication token. The default value for this argument from RiskIQ platform is false. This argument supports a single value only. | Optional | 
| page | The index of the page to retrieve. The index is zero based so the first page is page 0. The default value for this argument from RiskIQ platform is 0. | Optional |
| size | The response contains a page of assets for each related asset type. Size determines the number of associated assets of each type that are returned. The default value for this argument from RiskIQ platform is 20. If a large value is entered for this argument, it might take a while to fetch the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. | 
| Domain.Organization | String | The organization of the domain. | 
| IP.Address | String | IP address. | 
| URL.Data | String | The URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| RiskIQDigitalFootprint.Asset.name | String | Name of the connected asset. | 
| RiskIQDigitalFootprint.Asset.type | String | Type of the connected asset. | 
| RiskIQDigitalFootprint.Asset.state | String | State of the connected asset. | 
| RiskIQDigitalFootprint.Asset.firstSeen | Date | Date and Time when the connected asset was first observed. | 
| RiskIQDigitalFootprint.Asset.lastSeen | Date | Date and Time when the connected asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.uuid | String | UUID of the connected asset. | 
| RiskIQDigitalFootprint.Asset.label | String | Label of the connected asset. | 
| RiskIQDigitalFootprint.Asset.description | String | Description of the connected asset. | 
| RiskIQDigitalFootprint.Asset.confidence | String | Discovery confidence level of the connected asset. | 
| RiskIQDigitalFootprint.Asset.priority | String | Priority of the connected asset. | 
| RiskIQDigitalFootprint.Asset.autoConfirmed | Boolean | Was the connected asset auto\-confirmed. | 
| RiskIQDigitalFootprint.Asset.enterprise | Boolean | Has the connected asset been designated as an enterprise asset. | 
| RiskIQDigitalFootprint.Asset.keystone | Boolean | Was the connected asset designated as a discovery keystone. | 
| RiskIQDigitalFootprint.Asset.organizations.createdAt | Date | Date and Time when the organization applied to the asset was created. | 
| RiskIQDigitalFootprint.Asset.organizations.updatedAt | Date | Date and Time when the organization applied to the asset was updated. | 
| RiskIQDigitalFootprint.Asset.organizations.status | String | Status of the organization applied to the asset. | 
| RiskIQDigitalFootprint.Asset.organizations.workspaceOrganizationID | Number | ID of the organization applied to the asset in the user's workspace. | 
| RiskIQDigitalFootprint.Asset.organizations.workspaceID | Number | ID of the user's workspace. | 
| RiskIQDigitalFootprint.Asset.organizations.name | String | Name of the organization applied to the asset. | 
| RiskIQDigitalFootprint.Asset.organizations.id | Number | ID of the organization applied to the asset. | 
| RiskIQDigitalFootprint.Asset.tags.createdAt | Date | Date and Time when the tag applied to the asset was created. | 
| RiskIQDigitalFootprint.Asset.tags.updatedAt | Date | Date and Time when the tag applied to the asset was updated. | 
| RiskIQDigitalFootprint.Asset.tags.status | String | Status of the tag applied to the asset. | 
| RiskIQDigitalFootprint.Asset.tags.workspaceTagID | Number | ID of the tag applied to the asset in the user's workspace. | 
| RiskIQDigitalFootprint.Asset.tags.workspaceID | Number | ID of the user's workspace. | 
| RiskIQDigitalFootprint.Asset.tags.workspaceTagType | String | Workspace type of the tag applied to the asset. | 
| RiskIQDigitalFootprint.Asset.tags.color | String | Color of the tag applied to the asset. | 
| RiskIQDigitalFootprint.Asset.tags.name | String | Name of the tag applied to the asset. | 
| RiskIQDigitalFootprint.Asset.tags.id | Number | ID of the tag applied to the asset. | 
| RiskIQDigitalFootprint.Asset.brands.createdAt | Date | Date and Time when the brand applied to the asset was created. | 
| RiskIQDigitalFootprint.Asset.brands.updatedAt | Date | Date and Time when the brand applied to the asset was updated. | 
| RiskIQDigitalFootprint.Asset.brands.status | String | Status of the brand applied to the asset. | 
| RiskIQDigitalFootprint.Asset.brands.workspaceBrandID | Number | ID of the brand applied to the asset in the user's workspace. | 
| RiskIQDigitalFootprint.Asset.brands.workspaceID | Number | ID of the user's workspace. | 
| RiskIQDigitalFootprint.Asset.brands.name | String | Name of the brand applied to the asset. | 
| RiskIQDigitalFootprint.Asset.brands.id | Number | ID of the brand applied to the asset. | 
| RiskIQDigitalFootprint.Asset.createdAt | Date | The date that the connected asset was added to inventory. | 
| RiskIQDigitalFootprint.Asset.updatedAt | Date | The date of the most recent update performed by a user action for the connected asset. | 
| RiskIQDigitalFootprint.Asset.hostExcluded | Boolean | If true then only IP Addresses associated with confirmed IP Blocks will be included in the results. Possible Values: True, False. | 
| RiskIQDigitalFootprint.Asset.id | Number | ID of the connected asset. | 
| RiskIQDigitalFootprint.Asset.source | String | If the source of the connected asset is known. | 


#### Command Example
```!df-asset-connections type="Domain" name="dummy.com" size="2"```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "https://dummyurl.com",
            "Score": 0,
            "Type": "url",
            "Vendor": "RiskIQ Digital Footprint"
        },
        {
            "Indicator": "http://dummyurl.com",
            "Score": 0,
            "Type": "url",
            "Vendor": "RiskIQ Digital Footprint"
        }
    ],
    "RiskIQDigitalFootprint": {
        "Asset": [
            {
                "autoConfirmed": true,
                "confidence": "ABSOLUTE",
                "createdAt": 1594469523567,
                "description": "host.dummy.com",
                "enterprise": false,
                "firstSeen": 1594168047000,
                "id": 230123528,
                "keystone": false,
                "label": "host.dummy.com",
                "lastSeen": 1594508906149,
                "name": "host.dummy.com",
                "priority": "NONE",
                "state": "CONFIRMED",
                "type": "HOST",
                "updatedAt": 1594470594948,
                "uuid": "2d9400ec-4572-2b68-2638-9c57364eca91",
                "wildcard": true
            },
            {
                "autoConfirmed": true,
                "confidence": "ABSOLUTE",
                "createdAt": 1594468714807,
                "description": "host1.dummy.com",
                "enterprise": false,
                "firstSeen": 1593899022000,
                "id": 230123266,
                "keystone": false,
                "label": "host1.dummy.com",
                "lastSeen": 1594508906149,
                "name": "host1.dummy.com",
                "priority": "NONE",
                "state": "CONFIRMED",
                "type": "HOST",
                "updatedAt": 1594470594948,
                "uuid": "454cb72a-a1a6-3081-fdfa-d399d4dc823d",
                "wildcard": true
            },
            {
                "autoConfirmed": false,
                "createdAt": 1594456489831,
                "description": "https://dummyurl.com",
                "enterprise": false,
                "firstSeen": 1594301578052,
                "keystone": false,
                "label": "https://dummyurl.com",
                "lastSeen": 1594301578052,
                "name": "https://dummyurl.com",
                "state": "CONFIRMED",
                "type": "PAGE",
                "updatedAt": 1594456489831,
                "uuid": "1ad9db5a-dca3-e0ba-9d13-4d2e0c364b37",
                "wildcard": false
            },
            {
                "autoConfirmed": false,
                "createdAt": 1594456489831,
                "description": "http://dummyurl.com",
                "enterprise": false,
                "firstSeen": 1594301577733,
                "keystone": false,
                "label": "http://dummyurl.com",
                "lastSeen": 1594301577733,
                "name": "http://dummyurl.com",
                "state": "CONFIRMED",
                "type": "PAGE",
                "updatedAt": 1594456489831,
                "uuid": "771cb53a-8c62-aaa3-33bc-c6aceedb0d7a",
                "wildcard": false
            }
        ]
    },
    "URL": [
        {
            "Data": "https://dummyurl.com"
        },
        {
            "Data": "http://dummyurl.com"
        }
    ]
}
```

#### Human Readable Output

>### CONNECTED ASSETS
>### Total Hosts: 20
>### Fetched Hosts: 2
>|Name|State|First Seen (GMT)|Last Seen (GMT)|
>|---|---|---|---|
>| host.dummy.com | CONFIRMED | 2020-07-08 00:27:27 | 2020-07-11 23:08:26 |
>| host1.dummy.com | CONFIRMED | 2020-07-04 21:43:42 | 2020-07-11 23:08:26 |
>### Total Pages: 50
>### Fetched Pages: 2
>|Name|State|First Seen (GMT)|Last Seen (GMT)|
>|---|---|---|---|
>| https://dummyurl.com | CONFIRMED | 2020-07-09 13:32:58 | 2020-07-09 13:32:58 |
>| http://dummyurl.com | CONFIRMED | 2020-07-09 13:32:57 | 2020-07-09 13:32:57 |


### df-asset-changes-summary
***
Retrieve summary information describing counts of confirmed assets that have been added, removed or changed in inventory over the given time period.


#### Base Command

`df-asset-changes-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date | The date of the run in which the changes were identified (YYYY-MM-DD). If not passed it would consider the most recently run date when the discovery was run on RiskIQ Digital Footprint. This argument supports a single value only. | Optional | 
| range | The period of time for which the changes summary is to be fetched. Supported ranges are 1, 7, and 30 days. The default value for this argument from RiskIQ platform is 1. This argument supports a single value only. | Optional | 
| brand | Filter summary of changed assets based on the brand associated with the assets. This argument supports a single value only. | Optional | 
| organization | Filter summary of changed assets based on the organization associated with the assets. This argument supports a single value only. | Optional | 
| tag | Filter summary of changed assets based on the tag associated with the assets. This argument supports a single value only. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RiskIQDigitalFootprint.AssetSummary.runDate | String | The date of the run in which the changes were identified. | 
| RiskIQDigitalFootprint.AssetSummary.deltas.type | String | Type of the asset. | 
| RiskIQDigitalFootprint.AssetSummary.deltas.aggregations.removed | Number | Count of removed assets from Global Inventory in range of 1, 7, and 30 days from the most recently run date. | 
| RiskIQDigitalFootprint.AssetSummary.deltas.aggregations.added | Number | Count of added assets to Global Inventory in range of 1, 7, and 30 days from the most recently run date. | 
| RiskIQDigitalFootprint.AssetSummary.deltas.aggregations.changed | Number | Count of changed assets from Global Inventory in range of 1, 7, and 30 days from the most recently run date. | 
| RiskIQDigitalFootprint.AssetSummary.deltas.aggregations.count | Number | It indicates the number of confirmed assets in inventory | 
| RiskIQDigitalFootprint.AssetSummary.deltas.aggregations.range | Number | The period of time over which the changes were identified. Supported ranges are 1, 7, and 30 days. | 
| RiskIQDigitalFootprint.AssetSummary.deltas.aggregations.difference | Number | It indicates the result of added minus removed assets. | 


#### Command Example
```!df-asset-changes-summary```

#### Context Example
```
{
    "RiskIQDigitalFootprint": {
        "AssetSummary": {
            "deltas": [
                {
                    "aggregations": [
                        {
                            "added": 0,
                            "count": 25,
                            "difference": 0,
                            "range": 1,
                            "removed": 0
                        },
                        {
                            "added": 0,
                            "count": 0,
                            "difference": -2,
                            "range": 7,
                            "removed": 2
                        },
                        {
                            "added": 5,
                            "count": 0,
                            "difference": 2,
                            "range": 30,
                            "removed": 3
                        }
                    ],
                    "type": "DOMAIN"
                },
                {
                    "aggregations": [
                        {
                            "added": 26,
                            "count": 21134,
                            "difference": 26,
                            "range": 1,
                            "removed": 0
                        },
                        {
                            "added": 27,
                            "count": 0,
                            "difference": 27,
                            "range": 7,
                            "removed": 0
                        },
                        {
                            "added": 175,
                            "count": 0,
                            "difference": 175,
                            "range": 30,
                            "removed": 0
                        }
                    ],
                    "type": "HOST"
                },
                {
                    "aggregations": [
                        {
                            "added": 54,
                            "count": 321107,
                            "difference": 54,
                            "range": 1,
                            "removed": 0
                        },
                        {
                            "added": 3477,
                            "count": 0,
                            "difference": 3469,
                            "range": 7,
                            "removed": 8
                        },
                        {
                            "added": 17232,
                            "count": 0,
                            "difference": 17089,
                            "range": 30,
                            "removed": 143
                        }
                    ],
                    "type": "PAGE"
                },
                {
                    "aggregations": [
                        {
                            "added": 14,
                            "count": 305,
                            "difference": 14,
                            "range": 1,
                            "removed": 0
                        },
                        {
                            "added": 14,
                            "count": 0,
                            "difference": 13,
                            "range": 7,
                            "removed": 1
                        },
                        {
                            "added": 20,
                            "count": 0,
                            "difference": 14,
                            "range": 30,
                            "removed": 6
                        }
                    ],
                    "type": "SSL_CERT"
                },
                {
                    "aggregations": [
                        {
                            "added": 0,
                            "count": 6,
                            "difference": 0,
                            "range": 1,
                            "removed": 0
                        },
                        {
                            "added": 0,
                            "count": 0,
                            "difference": 0,
                            "range": 7,
                            "removed": 0
                        },
                        {
                            "added": 6,
                            "count": 0,
                            "difference": 6,
                            "range": 30,
                            "removed": 0
                        }
                    ],
                    "type": "AS"
                },
                {
                    "aggregations": [
                        {
                            "added": 0,
                            "count": 3,
                            "difference": 0,
                            "range": 1,
                            "removed": 0
                        },
                        {
                            "added": 0,
                            "count": 0,
                            "difference": 0,
                            "range": 7,
                            "removed": 0
                        },
                        {
                            "added": 1,
                            "count": 0,
                            "difference": 1,
                            "range": 30,
                            "removed": 0
                        }
                    ],
                    "type": "IP_BLOCK"
                },
                {
                    "aggregations": [
                        {
                            "added": 87,
                            "count": 1744,
                            "difference": 87,
                            "range": 1,
                            "removed": 0
                        },
                        {
                            "added": 87,
                            "count": 0,
                            "difference": 87,
                            "range": 7,
                            "removed": 0
                        },
                        {
                            "added": 92,
                            "count": 0,
                            "difference": 92,
                            "range": 30,
                            "removed": 0
                        }
                    ],
                    "type": "IP_ADDRESS"
                },
                {
                    "aggregations": [
                        {
                            "added": 0,
                            "count": 4,
                            "difference": 0,
                            "range": 1,
                            "removed": 0
                        },
                        {
                            "added": 0,
                            "count": 0,
                            "difference": 0,
                            "range": 7,
                            "removed": 0
                        },
                        {
                            "added": 0,
                            "count": 0,
                            "difference": -1,
                            "range": 30,
                            "removed": 1
                        }
                    ],
                    "type": "CONTACT"
                }
            ],
            "runDate": "2020-07-11"
        }
    }
}
```

#### Human Readable Output

>### [INVENTORY CHANGES](https://app.riskiq.net/a/main/index#/dashboard/inventorychanges/2020-07-11)
>#### Note: If the range argument is specified, a list of tables containing a daily, weekly and monthly changes summary identified over the given period of time will be presented i.e. there will be an individual table for all the dates from the last run date to the date derived from the range.
>### Date of the run in which following changes were identified: 2020-07-11
>|Asset Type|1 Day|7 Days|30 Days|
>|---|---|---|---|
>| **Domain** | **Count:** 25 | **Removed:** 2<br/>**Difference:** -2 | **Added:** 5<br/>**Removed:** 3<br/>**Difference:** 2 |
>| **Host** | **Added:** 26<br/>**Count:** 21134<br/>**Difference:** 26 | **Added:** 27<br/>**Difference:** 27 | **Added:** 175<br/>**Difference:** 175 |
>| **Page** | **Added:** 54<br/>**Count:** 321107<br/>**Difference:** 54 | **Added:** 3477<br/>**Removed:** 8<br/>**Difference:** 3469 | **Added:** 17232<br/>**Removed:** 143<br/>**Difference:** 17089 |
>| **SSL Cert** | **Added:** 14<br/>**Count:** 305<br/>**Difference:** 14 | **Added:** 14<br/>**Removed:** 1<br/>**Difference:** 13 | **Added:** 20<br/>**Removed:** 6<br/>**Difference:** 14 |
>| **ASN** | **Count:** 6 |  | **Added:** 6<br/>**Difference:** 6 |
>| **IP Block** | **Count:** 3 |  | **Added:** 1<br/>**Difference:** 1 |
>| **IP Address** | **Added:** 87<br/>**Count:** 1744<br/>**Difference:** 87 | **Added:** 87<br/>**Difference:** 87 | **Added:** 92<br/>**Difference:** 92 |
>| **Contact** | **Count:** 4 |  | **Removed:** 1<br/>**Difference:** -1 |


### df-asset-changes
***
Retrieve the list of confirmed assets that have been added or removed from inventory over the given time period. Retrieve the list of asset detail changes in inventory over the given time period.


#### Base Command

`df-asset-changes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Either the type of asset or asset detail to retrieve. Valid asset types: Domain, Host, IP Address, IP Block, ASN, Page, SSL Cert,  Contact. Valid asset detail types: Self Hosted Resource, ThirdParty Hosted Resource. This argument supports a single value only. | Required | 
| date | The date of the run in which the changes were identified (YYYY-MM-DD). If not passed it would consider the most recently run date when the discovery was run on RiskIQ Digital Footprint. This argument supports a single value only. | Optional | 
| range | The period of time over which the changes were identified. Supported ranges are 1, 7, and 30 days. The default value for this argument from RiskIQ platform is 1. This argument supports a single value only. | Optional | 
| measure | The type of change. Valid options for asset types are Added or Removed and for asset detail types are Added or Changed. The default value for this argument from RiskIQ platform is Added. This argument supports a single value only. | Optional | 
| brand | Filter changed assets based on the brand associated with the assets. This argument supports a single value only. | Optional | 
| organization | Filter changed assets based on the organization associated with the assets. This argument supports a single value only. | Optional | 
| tag | Filter changed assets based on the tag associated with the assets. This argument supports a single value only. | Optional | 
| page | The index of the page to retrieve. The index is zero based so the first page is page 0. The default value for this argument from RiskIQ platform is 0. | Optional |
| size | The number of matching assets to return per page. The default value for this argument from RiskIQ platform is 20. If a large value is entered for this argument, it might take a while to fetch the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. | 
| IP.Address | String | IP address. | 
| URL.Data | String | The URL. | 
| File.Name | String | The full file name \(including file extension\). | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 
| File.Hostname | String | The name of the host where the file was found. Should match Path. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| RiskIQDigitalFootprint.AssetChanges.name | String | Name of the asset. | 
| RiskIQDigitalFootprint.AssetChanges.runDate | Date | The date of the run in which the changes were identified. | 
| RiskIQDigitalFootprint.AssetChanges.measure | String | The type of change. | 
| RiskIQDigitalFootprint.AssetChanges.autoConfirmed | Boolean | Was the asset auto\-confirmed. | 
| RiskIQDigitalFootprint.AssetChanges.enterprise | Boolean | Has the asset been designated as an enterprise asset. | 
| RiskIQDigitalFootprint.AssetChanges.state | String | State of the asset. | 
| RiskIQDigitalFootprint.AssetChanges.priority | String | Priority of the asset. | 
| RiskIQDigitalFootprint.AssetChanges.keystone | Boolean | Was the asset designated as a discovery keystone. | 
| RiskIQDigitalFootprint.AssetChanges.type | String | Type of the asset. | 
| RiskIQDigitalFootprint.AssetChanges.description | String | Description of the asset. | 
| RiskIQDigitalFootprint.AssetChanges.hostExcluded | Boolean | If true then only IP Addresses associated with confirmed IP Blocks will be included in the results. Possible values: True, False. | 
| RiskIQDigitalFootprint.AssetChanges.id | Number | ID of the asset. | 
| RiskIQDigitalFootprint.AssetChanges.createdAt | Date | The date that the asset was added to inventory. | 
| RiskIQDigitalFootprint.AssetChanges.updatedAt | Date | The date of the most recent update performed by a user action. | 
| RiskIQDigitalFootprint.AssetChanges.confidence | String | Discovery confidence level of the asset. | 
| RiskIQDigitalFootprint.AssetChanges.wildcard | Boolean | Has the asset been designated as a wildcard asset. | 
| RiskIQDigitalFootprint.AssetChanges.discoveryRun | Number | The id of the discovery run in which the asset was discovered. | 
| RiskIQDigitalFootprint.AssetChanges.childUrlFirstSeen | Date | The date and time when the child URl was first observed. | 
| RiskIQDigitalFootprint.AssetChanges.childUrlLastSeen | Date | The date and time when the child URL was most recently observed. | 
| RiskIQDigitalFootprint.AssetChanges.resourceFirstSeen | Date | The date and time when the resource was first observed. | 
| RiskIQDigitalFootprint.AssetChanges.resourceLastSeen | Date | The date and time when the resource was most recently observed. | 
| RiskIQDigitalFootprint.AssetChanges.dynamicScore | Number | The dynamic score of the asset. | 
| RiskIQDigitalFootprint.AssetChanges.originalUrl | String | The original URL of the asset. | 
| RiskIQDigitalFootprint.AssetChanges.firstSeenResourceGuid | String | Resource GUID that was first observed for the asset. | 
| RiskIQDigitalFootprint.AssetChanges.lastSeenResourceGuid | String | Resource GUID that was most recently observed for the asset. | 
| RiskIQDigitalFootprint.AssetChanges.firstSeenCrawlGuid | String | Crawl GUID that was first observed for the asset. | 
| RiskIQDigitalFootprint.AssetChanges.lastSeenCrawlGuid | String | Crawl GUID that was most recently observed for the asset. | 
| RiskIQDigitalFootprint.AssetChanges.firstSeenPageGuid | String | Page GUID that was first observed for the asset. | 
| RiskIQDigitalFootprint.AssetChanges.lastSeenPageGuid | String | Page GUID that was most recently observed for the asset. | 
| RiskIQDigitalFootprint.AssetChanges.contentType | String | The content type of the resource included in the asset. | 
| RiskIQDigitalFootprint.AssetChanges.responseBodySize | String | The response body size of the resource included in the asset. | 
| RiskIQDigitalFootprint.AssetChanges.md5 | String | The md5 hash of the content of the resource included in the asset. | 
| RiskIQDigitalFootprint.AssetChanges.resource | String | The url of the resource included in the asset. | 
| RiskIQDigitalFootprint.AssetChanges.resourceHost | String | The hostname of the resource included in the asset. | 
| RiskIQDigitalFootprint.AssetChanges.microDeltaType | String | The type of the resource included in the asset. | 
| RiskIQDigitalFootprint.AssetChanges.source | String | If the source of the asset is known. | 
| RiskIQDigitalFootprint.AssetChanges.organizations.createdAt | Date | Date and Time when the organization applied to the asset was created. | 
| RiskIQDigitalFootprint.AssetChanges.organizations.updatedAt | Date | Date and Time when the organization applied to the asset was updated. | 
| RiskIQDigitalFootprint.AssetChanges.organizations.status | String | Status of the organization applied to the asset. | 
| RiskIQDigitalFootprint.AssetChanges.organizations.workspaceOrganizationID | Number | ID of the organization applied to the asset in the user's workspace. | 
| RiskIQDigitalFootprint.AssetChanges.organizations.workspaceID | Number | ID of the user's workspace. | 
| RiskIQDigitalFootprint.AssetChanges.organizations.name | String | Name of the organization applied to the asset. | 
| RiskIQDigitalFootprint.AssetChanges.organizations.id | Number | ID of the organization applied to the asset. | 
| RiskIQDigitalFootprint.AssetChanges.tags.createdAt | Date | Date and Time when the tag applied to the asset was created. | 
| RiskIQDigitalFootprint.AssetChanges.tags.updatedAt | Date | Date and Time when the tag applied to the asset was updated. | 
| RiskIQDigitalFootprint.AssetChanges.tags.status | String | Status of the tag applied to the asset. | 
| RiskIQDigitalFootprint.AssetChanges.tags.workspaceOrganizationID | Number | ID of the tag applied to the asset in the user's workspace. | 
| RiskIQDigitalFootprint.AssetChanges.tags.workspaceID | Number | ID of the user's workspace. | 
| RiskIQDigitalFootprint.AssetChanges.tags.workspaceTagType | String | Workspace type of the tag applied to the asset. | 
| RiskIQDigitalFootprint.AssetChanges.tags.color | String | Color of the tag applied to the asset. | 
| RiskIQDigitalFootprint.AssetChanges.tags.name | String | Name of the tag applied to the asset. | 
| RiskIQDigitalFootprint.AssetChanges.tags.id | Number | ID of the tag applied to the asset. | 
| RiskIQDigitalFootprint.AssetChanges.brands.createdAt | Date | Date and Time when the brand applied to the asset was created. | 
| RiskIQDigitalFootprint.AssetChanges.brands.updatedAt | Date | Date and Time when the brand applied to the asset was updated. | 
| RiskIQDigitalFootprint.AssetChanges.brands.status | String | Status of the brand applied to the asset. | 
| RiskIQDigitalFootprint.AssetChanges.brands.workspaceOrganizationID | Number | ID of the brand applied to the asset in the user's workspace. | 
| RiskIQDigitalFootprint.AssetChanges.brands.workspaceID | Number | ID of the user's workspace. | 
| RiskIQDigitalFootprint.AssetChanges.brands.name | String | Name of the brand applied to the asset. | 
| RiskIQDigitalFootprint.AssetChanges.brands.id | Number | ID of the brand applied to the asset. | 


#### Command Example
```!df-asset-changes type="Page" range="30" size="2"```

#### Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "http://dummy.com/",
            "Score": 0,
            "Type": "url",
            "Vendor": "RiskIQ Digital Footprint"
        },
        {
            "Indicator": "http://dummy1.com/",
            "Score": 0,
            "Type": "url",
            "Vendor": "RiskIQ Digital Footprint"
        }
    ],
    "RiskIQDigitalFootprint": {
        "AssetChanges": [
            {
                "autoConfirmed": false,
                "description": "http://dummy.com/",
                "enterprise": false,
                "keystone": false,
                "measure": "added",
                "name": "http://dummy.com/",
                "priority": "NONE",
                "runDate": "2020-07-11",
                "source": false,
                "state": "CONFIRMED",
                "type": "PAGE",
                "wildcard": false
            },
            {
                "autoConfirmed": false,
                "description": "http://dummy1.com/",
                "enterprise": false,
                "keystone": false,
                "measure": "added",
                "name": "http://dummy1.com/",
                "priority": "NONE",
                "runDate": "2020-07-11",
                "source": false,
                "state": "CONFIRMED",
                "type": "PAGE",
                "wildcard": false
            }
        ]
    },
    "URL": [
        {
            "Data": "http://dummy.com/"
        },
        {
            "Data": "http://dummy1.com/"
        }
    ]
}
```

#### Human Readable Output

>### [INVENTORY CHANGES: DETAILS](https://app.riskiq.net/a/main/index#/dashboard/inventorychanges/details/date=2020-07-11&measure=ADDED&range=30&type=PAGE)
>### Added Inventory Assets: 2
>### Total: 600
>### Fetched: 2
>|Name|Description|State|Priority|Measure|RunDate|
>|---|---|---|---|---|---|
>| http://dummy.com/ | http://dummy.com/ | CONFIRMED | NONE | added | 2020-07-11 |
>| http://dummy1.com/ | http://dummy1.com/ | CONFIRMED | NONE | added | 2020-07-11 |


### df-get-asset
***
Retrieve the asset of the specified UUID or type and name from Global Inventory.


#### Base Command

`df-get-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The unique identifier of an asset in global inventory. This argument supports a single value only. | Optional | 
| name | The name of the asset to retrieve. For example riskiq.com, 8.8.8.8, mail.net, etc. This argument supports a single value only. | Optional | 
| type | The type of the asset to retrieve. Valid Types: Domain, Host, IP Address, IP Block, ASN, Page, SSL Cert, Contact. This argument supports a single value only. | Optional | 
| global | Setting this value to true will search all of the global inventory. Setting it to false will search for assets in the workspace associated with the authentication token. The default value for this argument from RiskIQ platform is false. This argument supports a single value only. | Optional | 
| recent | If specified and 'true', then only return recent data on the asset. The default value for this argument from RiskIQ platform is false. This argument supports a single value only. | Optional | 
| size | Digital Footprint (Global Inventory) assets potentially contain pages of related data, for example attributes, cookies and host pairs. Size determines the number for each of these associated items that are returned. If a large value is entered for this argument, it might take a while to fetch the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.DomainStatus | String | The status of the domain. | 
| Domain.NameServers | String | Name servers of the domain | 
| Domain.Registrant.Country | String | The country of the domain registrant. | 
| Domain.Registrant.Email | String | The email address of the domain registrant. | 
| Domain.Registrant.Name | String | The name of the domain registrant. | 
| Domain.Registrant.Phone | String | The phone number of the domain registrant. | 
| Domain.Registrar.Name | String | The name of the registrar, for example: "GoDaddy". | 
| Domain.Registrar.AbuseEmail | String | The email address of the contact for reporting abuse. | 
| Domain.Registrar.AbusePhone | String | The phone number of contact for reporting abuse. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.WHOIS.DomainStatus | String | The status of the domain. | 
| Domain.WHOIS.NameServers | String | A list of name servers, for example: "ns1.bla.com, ns2.bla.com". | 
| Domain.WHOIS.Registrant.Country | String | The country of the domain registrant. | 
| Domain.WHOIS.Registrant.Email | String | The email address of the domain registrant. | 
| Domain.WHOIS.Registrant.Name | String | The name of the domain registrant. | 
| Domain.WHOIS.Registrant.Phone | String | The phone number of the domain registrant. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: "GoDaddy". | 
| Domain.WHOIS.Registrar.AbuseEmail | String | The email address of the contact for reporting abuse. | 
| Domain.WHOIS.Registrar.AbusePhone | String | The phone number of contact for reporting abuse. | 
| Domain.WHOIS.Admin.Country | String | The country of the domain administrator. | 
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator. | 
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator. | 
| Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator. | 
| IP.Address | String | IP address. | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| CVE.CVSS | String | The CVSS of the CVE, for example: 10.0 | 
| URL.Data | String | The URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| RiskIQDigitalFootprint.Asset.name | String | Name of the asset. | 
| RiskIQDigitalFootprint.Asset.type | String | Type of the asset. | 
| RiskIQDigitalFootprint.Asset.firstSeen | Date | Date and Time when the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.lastSeen | Date | Date and Time when the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.uuid | String | UUID of the asset. | 
| RiskIQDigitalFootprint.Asset.label | String | Label of the asset. | 
| RiskIQDigitalFootprint.Asset.description | String | Description of the asset. | 
| RiskIQDigitalFootprint.Asset.autoConfirmed | Boolean | Was the asset auto\-confirmed. | 
| RiskIQDigitalFootprint.Asset.enterprise | Boolean | Has the asset been designated as an enterprise asset. | 
| RiskIQDigitalFootprint.Asset.state | String | State of the asset. | 
| RiskIQDigitalFootprint.Asset.priority | String | Priority of the asset. | 
| RiskIQDigitalFootprint.Asset.keystone | Boolean | Was the asset designated as a discovery keystone. | 
| RiskIQDigitalFootprint.Asset.hostExcluded | Boolean | If true then only IP Addresses associated with confirmed IP Blocks will be included in the results. Possible values: True, False. | 
| RiskIQDigitalFootprint.Asset.id | Number | ID of the asset. | 
| RiskIQDigitalFootprint.Asset.createdAt | Date | The date that the asset was added to inventory. | 
| RiskIQDigitalFootprint.Asset.updatedAt | Date | The date of the most recent update was performed on the asset by a user action. | 
| RiskIQDigitalFootprint.Asset.confidence | String | Discovery confidence level of the asset. | 
| RiskIQDigitalFootprint.Asset.source | String | If the source of the asset is known. | 
| RiskIQDigitalFootprint.Asset.organizations.createdAt | Date | Date and Time when the organization applied to the asset was created. | 
| RiskIQDigitalFootprint.Asset.organizations.updatedAt | Date | Date and Time when the organization applied to the asset was updated. | 
| RiskIQDigitalFootprint.Asset.organizations.status | String | Status of the organization applied to the asset. | 
| RiskIQDigitalFootprint.Asset.organizations.workspaceOrganizationID | Number | ID of the organization applied to the asset in the user's workspace. | 
| RiskIQDigitalFootprint.Asset.organizations.workspaceID | Number | ID of the user's workspace. | 
| RiskIQDigitalFootprint.Asset.organizations.name | String | Name of the organization applied to the asset. | 
| RiskIQDigitalFootprint.Asset.organizations.id | Number | ID of the organization applied to the asset. | 
| RiskIQDigitalFootprint.Asset.tags.createdAt | Date | Date and Time when the tag applied to the asset was created. | 
| RiskIQDigitalFootprint.Asset.tags.updatedAt | Date | Date and Time when the tag applied to the asset was updated. | 
| RiskIQDigitalFootprint.Asset.tags.status | String | Status of the tag applied to the asset. | 
| RiskIQDigitalFootprint.Asset.tags.workspaceOrganizationID | Number | ID of the tag applied to the asset in the user's workspace. | 
| RiskIQDigitalFootprint.Asset.tags.workspaceID | Number | ID of the user's workspace. | 
| RiskIQDigitalFootprint.Asset.tags.workspaceTagType | String | Workspace type of the tag applied to the asset. | 
| RiskIQDigitalFootprint.Asset.tags.color | String | Color of the tag applied to the asset. | 
| RiskIQDigitalFootprint.Asset.tags.name | String | Name of the tag applied to the asset. | 
| RiskIQDigitalFootprint.Asset.tags.id | Number | ID of the tag applied to the asset. | 
| RiskIQDigitalFootprint.Asset.brands.createdAt | Date | Date and Time when the brand applied to the asset was created. | 
| RiskIQDigitalFootprint.Asset.brands.updatedAt | Date | Date and Time when the brand applied to the asset was updated. | 
| RiskIQDigitalFootprint.Asset.brands.status | String | Status of the brand applied to the asset. | 
| RiskIQDigitalFootprint.Asset.brands.workspaceOrganizationID | Number | ID of the brand applied to the asset in the user's workspace. | 
| RiskIQDigitalFootprint.Asset.brands.workspaceID | Number | ID of the user's workspace. | 
| RiskIQDigitalFootprint.Asset.brands.name | String | Name of the brand applied to the asset. | 
| RiskIQDigitalFootprint.Asset.brands.id | Number | ID of the brand applied to the asset. | 
| RiskIQDigitalFootprint.Asset.auditTrail.name | String | Name of audit trail detected for the requested asset. | 
| RiskIQDigitalFootprint.Asset.auditTrail.type | String | Type of audit trail detected for the requested asset. | 
| RiskIQDigitalFootprint.Asset.auditTrail.description | String | Description of audit trail detected for the requested asset. | 
| RiskIQDigitalFootprint.Asset.primaryContact.contactID | Number | Contact ID of primary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.primaryContact.firstName | String | First name of primary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.primaryContact.lastName | String | Last name of primary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.primaryContact.fullName | String | Full name of primary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.primaryContact.email | String | Email of primary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.primaryContact.userId | String | User ID of primary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.primaryContact.name | String | Name of primary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.primaryContact.id | String | ID of primary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.secondaryContact.contactID | Number | Contact ID of secondary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.secondaryContact.firstName | String | First name of secondary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.secondaryContact.lastName | String | Last name of secondary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.secondaryContact.fullName | String | Full name of secondary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.secondaryContact.email | String | Email of secondary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.secondaryContact.userId | String | User ID of secondary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.secondaryContact.name | String | Name of secondary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.secondaryContact.id | String | ID of secondary contact of the requested asset. | 
| RiskIQDigitalFootprint.Asset.externalID | String | External ID of the requested asset. | 
| RiskIQDigitalFootprint.Asset.externalMetadata | String | External metadata of the requested asset. | 
| RiskIQDigitalFootprint.Asset.note | String | Note of the requested asset. | 
| RiskIQDigitalFootprint.Asset.removedState | String | State of the asset after removing that asset from the inventory. | 
| RiskIQDigitalFootprint.Asset.wildcard | Boolean | Has the asset been designated as a wildcard asset. | 
| RiskIQDigitalFootprint.Asset.assetDomain | String | Domain of the asset. | 
| RiskIQDigitalFootprint.Asset.assetWhoisId | Number | Whois ID of the domain. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarIanaIds.value | Number | The IANA id associated with the domain registrar. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarIanaIds.firstSeen | Date | Date and Time when the Registrar IanaID of the domain was first observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarIanaIds.lastSeen | Date | Date and Time when the Registrar IanaID of the domain was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarIanaIds.recent | Boolean | If the Registrar IanaID of the domain is recent. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarIanaIds.current | Boolean | If the Registrar IanaID of the domain is current. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantContacts.value | String | Registrant Contact of the domain. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantContacts.firstSeen | Date | Date and Time when the Registrant Contact of the domain was first observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantContacts.lastSeen | Date | Date and Time when the Registrant Contact of the domain was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantContacts.recent | Boolean | If the Registrant Contact of the domain is recent. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantContacts.current | Boolean | If the Registrant Contact of the domain is current. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantOrgs.value | String | Registrant Organization of the domain. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantOrgs.firstSeen | Date | Date and Time when the Registrant Organization of the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantOrgs.lastSeen | Date | Date and Time when the Registrant Organization of the asset was last seen. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantOrgs.recent | Boolean | If the Registrant Organization of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantOrgs.current | Boolean | If the Registrant Organization of the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetAdminContacts.value | String | Administrator Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.assetAdminContacts.firstSeen | Date | Date and Time when the Administrator Contact of the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetAdminContacts.lastSeen | Date | Date and Time when the Administrator Contact of the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetAdminContacts.recent | Boolean | If the Administrator Contact of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetAdminContacts.current | Boolean | If the Administrator Contact of the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetTechnicalContacts.value | String | Technical Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.assetTechnicalContacts.firstSeen | Date | Date and Time when the Technical Contact of the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetTechnicalContacts.lastSeen | Date | Date and Time when the Technical Contact of the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetTechnicalContacts.recent | Boolean | If the Technical Contact of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetTechnicalContacts.current | Boolean | If the Technical Contact of the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetNameServers.value | String | Name Server of the asset. | 
| RiskIQDigitalFootprint.Asset.assetNameServers.firstSeen | Date | Date and Time when the Name Server of the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetNameServers.lastSeen | Date | Date and Time when the Name Server of the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetNameServers.recent | Boolean | If the Name Server of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetNameServers.current | Boolean | If the Name Server of the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetMailServers.value | String | Mail Server of the asset. | 
| RiskIQDigitalFootprint.Asset.assetMailServers.firstSeen | Date | Date and Time when the Mail Server of the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetMailServers.lastSeen | Date | Date and Time when the Mail Server of the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetMailServers.recent | Boolean | If the Mail Server of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetMailServers.current | Boolean | If the Mail Server of the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetWhoisServers.value | String | Whois Server of the domain. | 
| RiskIQDigitalFootprint.Asset.assetWhoisServers.firstSeen | Date | Date and Time when the Whois Server of the domain was first observed. | 
| RiskIQDigitalFootprint.Asset.assetWhoisServers.lastSeen | Date | Date and Time when the Whois Server of the domain was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetWhoisServers.recent | Boolean | If the Whois Server of the domain is recent. | 
| RiskIQDigitalFootprint.Asset.assetWhoisServers.current | Boolean | If the Whois Server of the domain is current. | 
| RiskIQDigitalFootprint.Asset.assetDomainStatuses.value | String | Domain Status of the domain. | 
| RiskIQDigitalFootprint.Asset.assetDomainStatuses.firstSeen | Date | Date and Time when the Domain Status of the domain was first observed. | 
| RiskIQDigitalFootprint.Asset.assetDomainStatuses.lastSeen | Date | Date and Time when the Domain Status of the domain was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetDomainStatuses.recent | Boolean | If the Domain Status of the domain is recent. | 
| RiskIQDigitalFootprint.Asset.assetDomainStatuses.current | Boolean | If the Domain Status of the domain is current. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarCreatedAt.value | Date | Date and Time when the Registrar of the asset was created. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarCreatedAt.firstSeen | Date | Date and Time when the Registrar's created date of the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarCreatedAt.lastSeen | Date | Date and Time when the Registrar's created date of the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarCreatedAt.recent | Boolean | If the Registrar's created date of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarCreatedAt.current | Boolean | If the Registrar's created date of the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarUpdatedAt.value | Date | Date and Time when the Registrar of the asset was updated. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarUpdatedAt.firstSeen | Date | Date and Time when the Registrar's updated date of the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarUpdatedAt.lastSeen | Date | Date and Time when the Registrar's updated date of the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarUpdatedAt.recent | Boolean | If the Registrar's updated at date of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarUpdatedAt.current | Boolean | If the Registrar's updated date of the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarExpiresAt.value | Date | Date and Time when the Registrar of the domain expires at. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarExpiresAt.firstSeen | Date | Date and Time when the Registrar's expiry date of the domain was first observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarExpiresAt.lastSeen | Date | Date and Time when the Registrar's expiry date of the domain was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarExpiresAt.recent | Boolean | If the Registrar's expiry date of the domain is recent. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarExpiresAt.current | Boolean | If the Registrar's expiry date of the domain is current. | 
| RiskIQDigitalFootprint.Asset.assetSoaRecords.nameServer | String | Name Server for the SOA record of the domain. | 
| RiskIQDigitalFootprint.Asset.assetSoaRecords.email | String | Email for the SOA record of the domain. | 
| RiskIQDigitalFootprint.Asset.assetSoaRecords.firstSeen | Date | Date and Time when the SOA record of the domain was first observed. | 
| RiskIQDigitalFootprint.Asset.assetSoaRecords.lastSeen | Date | Date and Time when the SOA record of the domain was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetSoaRecords.serialNumber | Number | Serial Number for the SOA record of the domain. | 
| RiskIQDigitalFootprint.Asset.assetSoaRecords.recent | Boolean | If the SOA record of the domain is recent. | 
| RiskIQDigitalFootprint.Asset.assetSoaRecords.current | Boolean | If the SOA record of the domain is current. | 
| RiskIQDigitalFootprint.Asset.assetDetailedFromWhoisAt | Date | Date and Time when the details from the whois was fetched. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarNames.value | String | Registrar Name of the domain. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarNames.firstSeen | Date | Date and Time when the Registrar Name of the domain was first observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarNames.lastSeen | Date | Date and Time when the Registrar Name of the domain was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarNames.recent | Boolean | If the Registrar Name of the domain is recent. | 
| RiskIQDigitalFootprint.Asset.assetRegistrarNames.current | Boolean | If the Registrar Name of the domain is current. | 
| RiskIQDigitalFootprint.Asset.assetFirstSeen | Date | Date and Time when the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetLastSeen | Date | Date and Time when the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetCount | Number | Count for the number of times this asset has been observed. | 
| RiskIQDigitalFootprint.Asset.assetParkedDomain.value | Boolean | Has the domain been identified as parked. | 
| RiskIQDigitalFootprint.Asset.assetParkedDomain.firstSeen | Date | Date and Time when the Parked domain value for the domain was first observed. | 
| RiskIQDigitalFootprint.Asset.assetParkedDomain.lastSeen | Date | Date and Time when the Parked domain value for the domain was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetParkedDomain.recent | Boolean | If the Parked domain value for the domain is recent. | 
| RiskIQDigitalFootprint.Asset.assetParkedDomain.current | Boolean | If the Parked domain value for the domain is current. | 
| RiskIQDigitalFootprint.Asset.assetAlexaRank | String | Alexa Rank of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisCreatedAt | Date | Date and Time when the whois details of the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.whoisUpdatedAt | Date | Date and Time when the whois details of the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.whoisStatus | String | Whois Status of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisID | Number | Whois ID of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisDomain | String | Domain fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisDomainMd5 | String | Domain MD5 fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisDomainUnicode | String | Domain Unicode fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTld | String | Whois TLD of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisNameservers | String | Name servers fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisServer | String | Whois server fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantAddress | String | Address of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantCity | String | City of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantCountry | String | Country of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantEmail | String | Email address of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantFax | String | Fax of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantId | Number | ID of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantName | String | Name of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantOrganization | String | Organization of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantPhone | String | Phone number of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantState | String | State of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantStreet | String | Street of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantWhoisContactID | Number | Whois Contact ID of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrantZip | String | Zip code of the Registrant fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarIanaID | Number | The IANA id associated with the domain registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarCreatedAt | Date | Date and Time when Registrar was created fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarUpdatedAt | Date | Date and Time when Registrar was updated fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarExpiresAt | Date | Date and Time when Registrar expires fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarAddress | String | Address of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarCity | String | City of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarCountry | String | Country of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarEmail | String | Email address of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarFax | String | Fax of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarId | Number | ID of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarName | String | Name of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarOrganization | String | Organization of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarPhone | String | Phone number of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarState | String | State of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarStreet | String | Street of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarWhoisContactID | Number | Whois Contact ID of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarZip | String | Zip code of the Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.address | String | Address of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.city | String | City of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.country | String | Country of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.email | String | Email address of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.fax | String | Fax of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.id | Number | ID of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.name | String | Name of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.organization | String | Organization of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.phone | String | Phone number of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.state | String | State of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.street | String | Street of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.whoisContactID | Number | Whois Contact ID of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrar.zip | String | Zip code of the Registrar fetched from registrar details of whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminAddress | String | Address of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminCity | String | City of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminCountry | String | Country of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminEmail | String | Email address of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminFax | String | Fax of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminId | Number | ID of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminName | String | Name of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminOrganization | String | Organization of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminPhone | String | Phone number of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminState | String | State of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminStreet | String | Street of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminWhoisContactID | Number | Whois Contact ID of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAdminZip | String | Zip code of the Administrator fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisAuditCreatedAt | Date | Date and Time when the whois audit was created. | 
| RiskIQDigitalFootprint.Asset.whoisAuditUpdatedAt | Date | Date and Time when the whois audit was updated. | 
| RiskIQDigitalFootprint.Asset.whoisBillingAddress | String | Address of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingCity | String | City of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingCountry | String | Country of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingEmail | String | Email address of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingFax | String | Fax of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingId | Number | ID of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingName | String | Name of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingOrganization | String | Organization of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingPhone | String | Phone of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingState | String | State of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingStreet | String | Street of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingWhoisContactID | Number | Whois Contact ID of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisBillingZip | String | Zip code of the Billing contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisCompositeParseCode | Number | Composite Parse code fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContactCountries | String | Contact Countries fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContactOrganizations | String | Contact Organizations fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContactEmails | String | Contact Emails fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContactNames | String | Contact Names fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.address | String | Address of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.state | String | State of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.street | String | Street of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.email | String | Email of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.phone | String | Phone of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.fax | String | Fax of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.name | String | Name of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.zip | String | Zip of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.country | String | Country of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.id | Number | ID of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.organization | String | Organization of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.state | String | State of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisContacts.whoisContactID | Number | Whois Contact ID of Whois Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisDomainAvailable | Boolean | If the domain is available fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisDomainStatus | String | Domain Status fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisExpired | Boolean | If Whois is expired fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisId | Number | ID fetched from the whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisNoRecord | Boolean | If there is no whois record for the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistrarParseCode | Number | Parse Code of Registrar fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisRegistryParseCode | Number | Parse Code of Registry fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalAddress | String | Address of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalCity | String | City of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalCountry | String | Country of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalEmail | String | Email address of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalFax | String | Fax of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalId | Number | ID of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalName | String | Name of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalOrganization | String | Organization of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalPhone | String | Phone number of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalStreet | String | Street of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalWhoisContactID | Number | Whois Contact ID of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.whoisTechnicalZip | String | Zip code of the Technical contact fetched from whois details of the asset. | 
| RiskIQDigitalFootprint.Asset.assetHost | String | Host of the asset. | 
| RiskIQDigitalFootprint.Asset.assetIpAddresses.value | String | IP address which the host has resolved to. | 
| RiskIQDigitalFootprint.Asset.assetIpAddresses.firstSeen | Date | Date and Time when the IP Address of the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetIpAddresses.lastSeen | Date | Date and Time when the IP Address of the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetIpAddresses.recent | Boolean | If the IP Address of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetIpAddresses.current | Boolean | If the IP Address of the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetIpAddresses.count | Number | The number of times that IP Address is observed for this asset. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.firstSeen | Date | Date and Time when the web component was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.lastSeen | Date | Date and Time when the web component was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.recent | Boolean | If the web component observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.ports.port | Number | Port on which the web component observed on the asset is running. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.ports.firstSeen | Date | Date and Time when the port value for the web component observed on the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.ports.lastSeen | Date | Date and Time when the port value for the web component observed on the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.ports.count | Number | The number of times the port was observed for that web component observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.webComponentName | String | Name of web component observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.webComponentCategory | String | Category of web component observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.webComponentVersion | String | Version of web component observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.cves.name | String | The id of a CVE identified on the web component observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.cves.cvssScore | Number | CVSS score reflecting the severity of a CVE found on the web component observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.cves.cweID | String | The id of a CWE identified on the web component observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebComponents.current | Number | If the web component observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetHeaders.headerName | String | Name of the header observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHeaders.headerValue | String | Value of the header observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHeaders.firstSeen | Date | Date and Time when the header was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHeaders.lastSeen | Date | Date and Time when the header was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHeaders.recent | Number | If the header observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetHeaders.current | Number | If the header observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetAttributes.attributeType | String | Attribute/Tracker type observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAttributes.attributeValue | String | Attribute/Tracker value observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAttributes.firstSeen | Date | Date and Time when the attribute/tracker was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAttributes.lastSeen | Date | Date and Time when the attribute/tracker was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAttributes.recent | Number | If the attribute/tracker observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetAttributes.current | Number | If the attribute/tracker observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetCookies.cookieName | String | Name of the cookie observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetCookies.cookieDomain | String | Domain of the cookie observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetCookies.firstSeen | Date | Date and Time when the cookie was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetCookies.lastSeen | Date | Date and Time when the cookie was most recently seen on the asset. | 
| RiskIQDigitalFootprint.Asset.assetCookies.recent | Number | If the cookie observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetCookies.current | Number | If the cookie observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.sha1 | String | SHA1 of the SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.serialNumber | String | Serial number of the SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.subjectAlternativeNames | String | Subject alternative names of the SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.issuerAlternativeNames | String | Issuer alternative names of the SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.firstSeen | Date | Date and Time when the SSL certificate was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.lastSeen | Date | Date and Time when the SSL certificate was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.keySize | Number | Key size of the SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.version | Number | Version of the SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.certificateAuthority | Boolean | If the authority of the SSL certificate observed on the asset is certified. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.selfSigned | Boolean | If the SSL certificate observed on the asset is self signed. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.recent | Boolean | If the SSL certificate of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.signatureAlgorithm | String | Signature Algorithm of the SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.signatureAlgorithmOid | String | Signature Algorithm OID of the SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.notBefore | Date | Date and Time before which the SSL certificate observed on the asset is invalid. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.notAfter | Date | Date and Time after which the SSL certificate observed on the asset is invalid. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.publicKeyAlgorithm | String | Public Key Algorithm of the SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.id | String | ID of the SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.issuer.country | String | Country of the issuer of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.issuer.unit | String | Organization unit of the issuer of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.issuer.organization | String | Organization of the issuer of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.issuer.commonname | String | Common Name of the issuer of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.subject.state | String | State of the issuer of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.subject.locale | String | Locale of the issuer of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.subject.country | String | Country of the subject of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.subject.unit | String | Organization Unit of the subject of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.subject.organization | String | Organization of the subject of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.subject.commonname | String | Common Name of the subject of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.subject.state | String | State of the subject of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.subject.locale | String | Locale of the subject of SSL certificate observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetSslCerts.current | Boolean | If the ssl certificate observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.host | String | Host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.domain | String | Domain observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.firstSeen | Date | Date and Time when the host was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.lastSeen | Date | Date and Time when the host was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.count | Number | Number of times the host was observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.blacklistSequenceCount | Number | Block list sequence count of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.phishSequenceCount | Number | Phish sequence count of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.malwareSequenceCount | Number | Malware sequence count of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.spamSequenceCount | Number | Spam sequence count of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.scamSequenceCount | Number | Scam sequence count of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.hostReputationScore | Number | Reputation score of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.hostPhishReputationScore | Number | Phish Reputation score of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.hostMalwareReputationScore | Number | Malware Reputation score of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.hostSpamReputationScore | Number | Host Spam Reputation score of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.hostScamReputationScore | Number | Host Scam Reputation score of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.domainReputationScore | Number | Domain Reputation score of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.domainPhishReputationScore | Number | Domain Phish Reputation score of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.domainMalwareReputationScore | Number | Domain Malware Reputation score of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.domainSpamReputationScore | Number | Domain Spam Reputation score of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostCore.domainScamReputationScore | Number | Domain Scam Reputation score of the host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.scheme | String | Scheme for the services observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.port | Number | Port for the services observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.firstSeen | Date | Date and Time when the service was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.lastSeen | Date | Date and Time when the service was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.recent | Boolean | If the service observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetServices.banners.port | Number | Port for the banner of the service observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.banners.banner | String | Banner of the service observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.banners.firstSeen | Date | Date and Time when the banner of the service was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.banners.lastSeen | Date | Date and Time when the banner of the service was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.banners.count | Number | Number of times the banner of the service is observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.banners.scanType | String | Scan type fetched from the banners details of the service observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.banners.bannerMetadata | String | Banner metadata fetched from the banners details of the service observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.banners.recent | Boolean | If the banner of the service observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetServices.scanMetadata.port | Number | Port fetched from the scan metadata details of the service observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.scanMetadata.bannerMetadata | String | Banner metadata fetched from the scan metadata details of the service observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetServices.scanMetadata.startScan | Date | Date and Time when metadata scan of the service observed on the asset started. | 
| RiskIQDigitalFootprint.Asset.assetServices.scanMetadata.endScan | Date | Date and Time when metadata scan of the service observed on the asset ended. | 
| RiskIQDigitalFootprint.Asset.assetServices.current | Boolean | If the service observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetCnames.value | String | Cname of the asset. | 
| RiskIQDigitalFootprint.Asset.assetCnames.firstSeen | Date | Date and Time when the Cname was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetCnames.lastSeen | Date | Date and Time when the Cname was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetCnames.recent | Number | If the cname observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetCnames.current | Number | If the cname observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.url | String | URL fetched from the Resource URL details of the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.md5 | String | MD5 of the resource fetched from the Resource URL details of the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.responseBodySize | Number | Response body size of the resource fetched from the Resource URL details of the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.firstSeen | Date | Date and Time when the resource was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.lastSeen | Date | Date and Time when the resource was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.count | Number | The number of times when the resource was observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.firstSeenCrawlGuid | String | Crawl GUID that was first observed for the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.firstSeenPageGuid | String | Page GUID that was first observed for the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.firstSeenResourceGuid | String | Resource GUID that was first observed for the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.lastSeenCrawlGuid | String | Crawl GUID that was first observed for the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.lastSeenPageGuid | String | Page GUID that was first observed for the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.lastSeenResourceGuid | String | Resource GUID that was first observed for the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.responseBodyMinhash | String | Response body minimum hash for the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.contentType | String | Content type of the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.sha256 | String | SHA256 of the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.sha384 | String | SHA384 of the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.sha512 | String | SHA512 of the resource observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.url | String | URL of the resource fetched from the resources details of resource URLs observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.cached | Boolean | If the resource observed on the asset is cached. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.resources.host | String | Host of the resource observed on the asset | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.firstSeen | Date | Date and Time when the Resource URL was first observed. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.lastSeen | Date | Date and Time when the Resource URL was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.recent | Number | If the Resource URL observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetResourceUrls.current | Number | If the Resource URL observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetIpBlocks.ipBlock | String | IP Block containing the IP Address. | 
| RiskIQDigitalFootprint.Asset.assetIpBlocks.count | Number | The number of times that IP Block is observed for this asset. | 
| RiskIQDigitalFootprint.Asset.assetIpBlocks.firstSeen | Date | Date and Time when the IP Block was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetIpBlocks.lastSeen | Date | Date and Time when the IP Block was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetIpBlocks.recent | Boolean | Is IP Block observed on the asset recent. | 
| RiskIQDigitalFootprint.Asset.assetIpBlocks.current | Boolean | Is IP Block observed on the asset current. | 
| RiskIQDigitalFootprint.Asset.assetNsRecord.value | Boolean | If this record is observed as an NS record on the asset. | 
| RiskIQDigitalFootprint.Asset.assetNsRecord.firstSeen | Date | Date and Time when the NS record was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetNsRecord.lastSeen | Date | Date and Time when the NS record was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetNsRecord.recent | Boolean | If NS record value is current. | 
| RiskIQDigitalFootprint.Asset.assetNsRecord.current | Boolean | If NS record value is recent. | 
| RiskIQDigitalFootprint.Asset.assetMxRecord.value | Boolean | If this record is observed as an MX record on the asset. | 
| RiskIQDigitalFootprint.Asset.assetMxRecord.firstSeen | Date | Date and Time when the MX record was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetMxRecord.lastSeen | Date | Date and Time when the MX record was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetMxRecord.recent | Boolean | If MX record value is current. | 
| RiskIQDigitalFootprint.Asset.assetMxRecord.current | Boolean | If MX record value is recent. | 
| RiskIQDigitalFootprint.Asset.assetWebserver.value | Booolean | If a Web Server is observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebserver.firstSeen | Date | Date and Time when the web server record was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebserver.lastSeen | Date | Date and Time when the web server record was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetWebserver.recent | Boolean | If the web server observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetWebserver.current | Boolean | If the web server observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetLocation.value.countrycode | String | Country code of the location observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetLocation.value.countryname | String | Country name of the location observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetLocation.value.region | String | Region of the location observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetLocation.value.regionname | String | Region name of the location observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetLocation.value.postalcode | String | Postal code of the location observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetLocation.value.latitude | Number | Latitude of the location observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetLocation.value.longitude | Number | Longitude of the location observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetLocation.value.metrocodeid | Number | Metro code ID of the location observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetLocation.firstSeen | Date | Date and Time when the location was first observed for the asset. | 
| RiskIQDigitalFootprint.Asset.assetLocation.lastSeen | Date | Date and Time when the location was most recently observed for the asset. | 
| RiskIQDigitalFootprint.Asset.assetAsnNumbers.value | Number | ASN number observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAsnNumbers.firstSeen | Date | Date and Time when the ASN number was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAsnNumbers.lastSeen | Date | Date and Time when the ASN number was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAsnNumbers.recent | Boolean | If the ASN number observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetAsnNumbers.current | Number | If the ASN number observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetHostPairs.firstSeen | Date | Date and Time when the host pair was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostPairs.lastSeen | Date | Date and Time when the host pair was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostPairs.recent | Boolean | If the host pair observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetHostPairs.childHostname | String | Child hostname of the host pair observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostPairs.parentHostname | String | Parent hostname of the host pair observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHostPairs.current | Boolean | If the host pair observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.discoveryRunID | Number | The id of the discovery run in which the asset was discovered. | 
| RiskIQDigitalFootprint.Asset.discoveryRunWorkspaceID | Number | ID of the workspace in which the discovery took place. | 
| RiskIQDigitalFootprint.Asset.discoveryRunRunType | String | Run type of the discovery. | 
| RiskIQDigitalFootprint.Asset.discoveryRunUserID | Number | ID of the user who run the discovery. | 
| RiskIQDigitalFootprint.Asset.discoveryRunRunDate | Date | Run Date of the discovery. | 
| RiskIQDigitalFootprint.Asset.discoveryRunAssetType | String | Asset type for which the discovery was run. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchCreatedAt | Date | Date and Time when the discovery run search was created. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchUpdatedAt | Date | Date and Time when the discovery run search was updated. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchStatus | String | Status of the discovery run search. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchAssetSearchID | Number | Asset search ID of the discovery run search. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchName | String | Name of the discovery run search | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchWorkspaceID | Number | Workspace ID fetched from discovery run search details. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchSourceID | Number | Source ID of the discovery run search. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchQuery | String | Query applied to the discovery run search. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchMaxResults | Number | Max results fetched in the discovery run search. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchLastSearchDate | Date | Date and Time when the most recent discovery search was run. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchEnabled | Boolean | If the discovery search is enabled. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchScheduled | Date | Date and Time when the discovery run search is scheduled. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchFrequency | Number | Frequency of the discovery run search. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchDiscoveredCount | Number | Count of discovered assets in the discovery run search. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchAssetSearchState | String | Asset search state fetched from discovery run search details. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchAssetSearchType | String | Asset search type fetched from discovery run search details. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchNotes | String | Notes for the discovery run search. | 
| RiskIQDigitalFootprint.Asset.discoveryRunSearchId | Number | ID of the discovery run search. | 
| RiskIQDigitalFootprint.Asset.discoveryRunFullName | String | Full name of the discovery run. | 
| RiskIQDigitalFootprint.Asset.assetIpAddress | String | IP address of the asset. | 
| RiskIQDigitalFootprint.Asset.assetReputations.listName | String | Reputation list name observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetReputations.threatType | String | Reputation threat type observed on the asset | 
| RiskIQDigitalFootprint.Asset.assetReputations.trusted | Boolean | If the reputation can be trusted. | 
| RiskIQDigitalFootprint.Asset.assetReputations.cidr | String | Reputation CIDR observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetReputations.firstSeen | Date | Date and Time when the Reputation was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetReputations.lastSeen | Date | Date and Time when the Reputation was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetReputations.listUpdatedAt | Date | Date and Time when the Reputation list observed on the asset was most recently updated. | 
| RiskIQDigitalFootprint.Asset.assetReputations.recent | Boolean | If the Reputation observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetReputations.current | Boolean | If the Reputation observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetNetRanges.value | String | Net Range associated with the asset. | 
| RiskIQDigitalFootprint.Asset.assetNetRanges.firstSeen | Date | Date and Time when the net range associated with the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetNetRanges.lastSeen | Date | Date and Time when the net range associated with the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetNetRanges.recent | Boolean | If net range value observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetNetRanges.current | Boolean | If net range value observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetHosts.value | String | Host observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHosts.firstSeen | Date | Date and Time when the host was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHosts.lastSeen | Date | Date and Time when the host was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetHosts.recent | Boolean | If the host observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetHosts.current | Boolean | If the host observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetAsns.asnID | Number | ASN ID of the ASN observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAsns.description | String | Description of the ASN observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAsns.registry | String | Registry of the ASN observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAsns.countryCode | String | Country code of the ASN observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAsns.name | String | Name of the ASN observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAsns.id | Number | ID of the ASN observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetAsns.fullName | String | Full name of the ASN observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetUrl | String | URL of the page. | 
| RiskIQDigitalFootprint.Asset.assetHttpMethod | String | HTTP method used for the page. | 
| RiskIQDigitalFootprint.Asset.assetService | String | Service of the page on which it is available. | 
| RiskIQDigitalFootprint.Asset.assetSuccessful.value | Boolean | If the HTTP call made was successful for the page. | 
| RiskIQDigitalFootprint.Asset.assetSuccessful.firstSeen | Date | Date and Time when the HTTP call was first observed to be successful for the page. | 
| RiskIQDigitalFootprint.Asset.assetSuccessful.lastSeen | Date | Date and Time when the HTTP call was most recently observed to be successful for the page. | 
| RiskIQDigitalFootprint.Asset.assetSuccessful.recent | Number | If the successful value for the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetSuccessful.current | Number | If the successful value for the page is current. | 
| RiskIQDigitalFootprint.Asset.assetHttpResponseCodes.value | Number | The http response code returned by the page. | 
| RiskIQDigitalFootprint.Asset.assetHttpResponseCodes.firstSeen | Date | Date and Time when the http response code returned by the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetHttpResponseCodes.lastSeen | Date | Date and Time when the http response code returned by the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetHttpResponseCodes.recent | Boolean | If the http response code returned by the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetHttpResponseCodes.current | Boolean | If the http response code returned by the page is current. | 
| RiskIQDigitalFootprint.Asset.assetHttpResponseMessages.value | String | The http response message returned by the page. | 
| RiskIQDigitalFootprint.Asset.assetHttpResponseMessages.firstSeen | Date | Date and Time when the http response message returned by the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetHttpResponseMessages.lastSeen | Date | Date and Time when the http response message returned by the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetHttpResponseMessages.recent | Boolean | If the http response message returned by the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetHttpResponseMessages.current | Boolean | If the http response message returned by the page is current. | 
| RiskIQDigitalFootprint.Asset.assetResponseTimes.value | Number | The time taken by the page to respond. | 
| RiskIQDigitalFootprint.Asset.assetResponseTimes.firstSeen | Date | Date and Time when the response time was first observed. | 
| RiskIQDigitalFootprint.Asset.assetResponseTimes.lastSeen | Date | Date and Time when the response time was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetResponseTimes.recent | Boolean | If the response time value is recent. | 
| RiskIQDigitalFootprint.Asset.assetResponseTimes.current | Boolean | If the response time value is current. | 
| RiskIQDigitalFootprint.Asset.assetFrames.value | Boolean | If a frame is observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetFrames.firstSeen | Date | Date and Time when the frame was first observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetFrames.lastSeen | Date | Date and Time when the frame was most recently observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetFrames.recent | Boolean | If the frame value is recent. | 
| RiskIQDigitalFootprint.Asset.assetFrames.current | Boolean | If the frame value is current. | 
| RiskIQDigitalFootprint.Asset.assetWindows.value | Boolean | If a window is observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetWindows.firstSeen | Date | Date and Time when the window was first observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetWindows.lastSeen | Date | Date and Time when the window was most recently observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetWindows.recent | Boolean | If the window value is recent. | 
| RiskIQDigitalFootprint.Asset.assetWindows.current | Boolean | If the window value is current. | 
| RiskIQDigitalFootprint.Asset.assetContentTypes.value | String | Content type of the page. | 
| RiskIQDigitalFootprint.Asset.assetContentTypes.firstSeen | Date | Date and Time when the content type of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetContentTypes.lastSeen | Date | Date and Time when the content type of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetContentTypes.recent | Boolean | If the content type of the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetContentTypes.current | Boolean | If the content type of the page is current. | 
| RiskIQDigitalFootprint.Asset.assetContentLengths.value | Number | Content length of the page. | 
| RiskIQDigitalFootprint.Asset.assetContentLengths.firstSeen | Date | Date and Time when the content length of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetContentLengths.lastSeen | Date | Date and Time when the content length of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetContentLengths.recent | Boolean | If the content length is recent. | 
| RiskIQDigitalFootprint.Asset.assetContentLengths.current | Boolean | If the content length of the page is current. | 
| RiskIQDigitalFootprint.Asset.assetWindowNames.value | String | Window name of the page. | 
| RiskIQDigitalFootprint.Asset.assetWindowNames.firstSeen | Date | Date and Time when the window name of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetWindowNames.lastSeen | Date | Date and Time when the window name of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetWindowNames.recent | Boolean | If the window name value of the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetWindowNames.current | Boolean | If the window name value of the page is current. | 
| RiskIQDigitalFootprint.Asset.assetCharsets.value | String | Charset of the page. | 
| RiskIQDigitalFootprint.Asset.assetCharsets.firstSeen | Date | Date and Time when the charset of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetCharsets.lastSeen | Date | Date and Time when the charset of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetCharsets.recent | Boolean | If the charset value of the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetCharsets.current | Boolean | If the charset value of the page is current. | 
| RiskIQDigitalFootprint.Asset.assetTitles.value | String | Title of the page. | 
| RiskIQDigitalFootprint.Asset.assetTitles.firstSeen | Date | Date and Time when the title of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetTitles.lastSeen | Date | Date and Time when the title of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetTitles.recent | Boolean | If the title of the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetTitles.current | Boolean | If the title of the page is current. | 
| RiskIQDigitalFootprint.Asset.assetLanguages.value | String | Language of the page. | 
| RiskIQDigitalFootprint.Asset.assetLanguages.firstSeen | Date | Date and Time when the language of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetLanguages.lastSeen | Date | Date and Time when the language of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetLanguages.recent | Boolean | If the language of the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetLanguages.current | Boolean | If the language of the page is current. | 
| RiskIQDigitalFootprint.Asset.assetResponseHeaders.headerName | String | Header Name of the response header returned from the page. | 
| RiskIQDigitalFootprint.Asset.assetResponseHeaders.headerValue | String | Header Value of the response header returned from the page. | 
| RiskIQDigitalFootprint.Asset.assetResponseHeaders.firstSeen | Date | Date and Time when the response header returned from the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetResponseHeaders.lastSeen | Date | Date and Time when the response header returned from the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetResponseHeaders.recent | Boolean | If the response header of the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetResponseHeaders.current | Boolean | If the response header of the page is current. | 
| RiskIQDigitalFootprint.Asset.assetSecurityPolicies.policyName | String | Security policy violation identified on the page. | 
| RiskIQDigitalFootprint.Asset.assetSecurityPolicies.isAffected | Boolean | If the page is affected by the security policy violation identified. | 
| RiskIQDigitalFootprint.Asset.assetSecurityPolicies.description | String | Description of the security policy violation identified on the page. | 
| RiskIQDigitalFootprint.Asset.assetSecurityPolicies.firstSeen | Date | Date and Time when the security policy violation was first observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetSecurityPolicies.lastSeen | Date | Date and Time when the security policy violation was most recently observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetSecurityPolicies.recent | Boolean | If the security policy violation of the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetSecurityPolicies.current | Boolean | If the security policy violation of the page is current. | 
| RiskIQDigitalFootprint.Asset.assetResponseBodyHashSignatures.value | String | Response body has signature of the asset. | 
| RiskIQDigitalFootprint.Asset.assetResponseBodyHashSignatures.firstSeen | Date | Date and Time when the response body hash signature of the asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetResponseBodyHashSignatures.lastSeen | Date | Date and Time when the response body hash signature of the asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetResponseBodyHashSignatures.recent | Boolean | If response body hash signature of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetResponseBodyHashSignatures.current | Boolean | If response body hash signature of the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetErrors.value | String | The error encountered while crawling the page. | 
| RiskIQDigitalFootprint.Asset.assetErrors.firstSeen | Date | Date and Time when the error was first encountered while crawling the page. | 
| RiskIQDigitalFootprint.Asset.assetErrors.lastSeen | Date | Date and Time when the error was most recently encountered while crawling the page. | 
| RiskIQDigitalFootprint.Asset.assetErrors.recent | Boolean | If the error encountered while crawling the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetErrors.current | Boolean | If the error encountered while crawling the page is current. | 
| RiskIQDigitalFootprint.Asset.assetCause.causepageguid | String | Cause Page GUID observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetCause.cause | String | Cause observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetCause.location | String | Location of the page. | 
| RiskIQDigitalFootprint.Asset.assetCause.possiblematches | Number | Posible matches of the page. | 
| RiskIQDigitalFootprint.Asset.assetCause.loopdetected | Boolean | If the loop was detected due to the cause observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetCause.version | Number | Version of the cause observed on the page. | 
| RiskIQDigitalFootprint.Asset.assetReferrer | String | Referrer of the page. | 
| RiskIQDigitalFootprint.Asset.assetRedirectType | String | Redirect type of the page. | 
| RiskIQDigitalFootprint.Asset.assetFinalUrls.value | String | Final URL of the page after following one or more redirects. | 
| RiskIQDigitalFootprint.Asset.assetFinalUrls.firstSeen | Date | Date and Time when the final url of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetFinalUrls.lastSeen | Date | Date and Time when the final url of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetFinalUrls.recent | Boolean | If final url of the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetFinalUrls.current | Boolean | If final url of the page is current. | 
| RiskIQDigitalFootprint.Asset.assetFinalResponseCodes.value | Number | Final response codes of the page after following one or more redirects. | 
| RiskIQDigitalFootprint.Asset.assetFinalResponseCodes.firstSeen | Date | Date and Time when the final response code was first observed. | 
| RiskIQDigitalFootprint.Asset.assetFinalResponseCodes.lastSeen | Date | Date and Time when the final response code was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetFinalResponseCodes.recent | Boolean | If the final response code is recent. | 
| RiskIQDigitalFootprint.Asset.assetFinalResponseCodes.current | Boolean | If the final response code is current. | 
| RiskIQDigitalFootprint.Asset.assetParkedPage.value | Boolean | Has the page been identified as parked. | 
| RiskIQDigitalFootprint.Asset.assetParkedPage.firstSeen | Date | Date and Time when the identified parked value of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetParkedPage.lastSeen | Date | Date and Time when the identified parked value of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetParkedPage.recent | Boolean | If the parked page value is recent. | 
| RiskIQDigitalFootprint.Asset.assetParkedPage.current | Boolean | If the parked page value is current. | 
| RiskIQDigitalFootprint.Asset.assetGuids.pageGuid | String | GUID of the page. | 
| RiskIQDigitalFootprint.Asset.assetGuids.crawlStateGuid | String | Crawl state GUID of the page. | 
| RiskIQDigitalFootprint.Asset.assetGuids.loadDate | Date | Date and Time when the GUIDs of the page were loaded. | 
| RiskIQDigitalFootprint.Asset.assetFinalIpAddresses.value | String | Final IP Address of the page after following one or more redirects. | 
| RiskIQDigitalFootprint.Asset.assetFinalIpAddresses.firstSeen | Date | Date and Time when the final IP Address of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetFinalIpAddresses.lastSeen | Date | Date and Time when the final IP Address of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetFinalIpAddresses.recent | Boolean | If the final IP Address observed for the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetFinalIpAddresses.current | Boolean | If the final IP Address observed for the page is current. | 
| RiskIQDigitalFootprint.Asset.assetFinalAsns.value | Number | Final ASN of the page after following one or more redirects. | 
| RiskIQDigitalFootprint.Asset.assetFinalAsns.firstSeen | Date | Date and Time when the final asn of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetFinalAsns.lastSeen | Date | Date and Time when the final asn of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetFinalAsns.recent | Boolean | If the final asn observed for the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetFinalAsns.current | Boolean | If the final asn observed for the page is current. | 
| RiskIQDigitalFootprint.Asset.assetFinalIpBlocks.ipBlock | String | Final IP Block of the page after following one or more redirects. | 
| RiskIQDigitalFootprint.Asset.assetFinalIpBlocks.firstSeen | Date | Date and Time when the final IP Block of the page was first observed. | 
| RiskIQDigitalFootprint.Asset.assetFinalIpBlocks.lastSeen | Date | Date and Time when the final IP Block of the page was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetFinalIpBlocks.recent | Boolean | If the final IP Block observed for the page is recent. | 
| RiskIQDigitalFootprint.Asset.assetFinalIpBlocks.current | Boolean | If the final IP Block observed for the page is current. | 
| RiskIQDigitalFootprint.Asset.assetIsRootUrl | Boolean | If the URl is root URL. | 
| RiskIQDigitalFootprint.Asset.assetAsNames.value | String | Name of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetAsNames.firstSeen | Date | Date and Time when the ASN name was first observed. | 
| RiskIQDigitalFootprint.Asset.assetAsNames.lastSeen | Date | Date and Time when the ASN name was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetAsNames.recent | Boolean | If the ASN name is recent. | 
| RiskIQDigitalFootprint.Asset.assetAsNames.current | Boolean | If the ASN name is current. | 
| RiskIQDigitalFootprint.Asset.assetOrgNames.value | String | Organization name of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetOrgNames.firstSeen | Date | Date and Time when the organization name of the ASN was first observed. | 
| RiskIQDigitalFootprint.Asset.assetOrgNames.lastSeen | Date | Date and Time when the organization name of the ASN was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetOrgNames.recent | Boolean | If the organization name is recent. | 
| RiskIQDigitalFootprint.Asset.assetOrgNames.current | Boolean | If the organization name is current. | 
| RiskIQDigitalFootprint.Asset.assetOrgIds.value | String | Organization ID of the asset. | 
| RiskIQDigitalFootprint.Asset.assetOrgIds.firstSeen | Date | Date and Time when the organization ID of the ASN was first observed. | 
| RiskIQDigitalFootprint.Asset.assetOrgIds.lastSeen | Date | Date and Time when the organization ID of the ASN was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetOrgIds.recent | Boolean | If the organization id of the ASN is recent. | 
| RiskIQDigitalFootprint.Asset.assetOrgIds.current | Boolean | If the organization id of the ASN is current. | 
| RiskIQDigitalFootprint.Asset.assetCountries.value | String | Country of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetCountries.firstSeen | Date | Date and Time when the Country of ASN was first observed. | 
| RiskIQDigitalFootprint.Asset.assetCountries.lastSeen | Date | Date and Time when the Country of ASN was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetCountries.recent | Boolean | If the country of the ASN is recent. | 
| RiskIQDigitalFootprint.Asset.assetCountries.current | Boolean | If the country of the ASN is current. | 
| RiskIQDigitalFootprint.Asset.assetRegistries.value | String | Registry of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetRegistries.firstSeen | Date | Date and Time when the registry of the ASN was first observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistries.lastSeen | Date | Date and Time when the registry of the ASN was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistries.recent | Boolean | If the registry of ASN is recent. | 
| RiskIQDigitalFootprint.Asset.assetRegistries.current | Boolean | If the registry of ASN is current. | 
| RiskIQDigitalFootprint.Asset.assetAsnNumber | Number | ASN Number of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetAsn.asnID | Number | ASN ID of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetAsn.description | String | Description of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetAsn.registry | String | Registry of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetAsn.countryCode | String | Country code of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetAsn.name | String | Name of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetAsn.id | Number | ID of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetAsn.fullName | String | Full name of the ASN. | 
| RiskIQDigitalFootprint.Asset.assetIpBlock | String | IP Block of the asset. | 
| RiskIQDigitalFootprint.Asset.assetBgpPrefixes.value | String | The BGP prefix for the IP Block. | 
| RiskIQDigitalFootprint.Asset.assetBgpPrefixes.firstSeen | Date | Date and Time when the BGP prefix for the IP Block was first observed. | 
| RiskIQDigitalFootprint.Asset.assetBgpPrefixes.lastSeen | Date | Date and Time when the BGP prefix for the IP Block was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetBgpPrefixes.recent | Boolean | If the BGP prefix for the IP Block is recent. | 
| RiskIQDigitalFootprint.Asset.assetBgpPrefixes.current | Boolean | If the BGP prefix for the IP Block is current. | 
| RiskIQDigitalFootprint.Asset.assetNetNames.value | String | Net name observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetNetNames.firstSeen | Date | Date and Time when the net name was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetNetNames.lastSeen | Date | Date and Time when the net name was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.assetNetNames.recent | Boolean | If the net name value observed on the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetNetNames.current | Boolean | If the net name value observed on the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetStartIp | String | Start IP Address of the IP Block. | 
| RiskIQDigitalFootprint.Asset.assetEndIp | String | End IP Address of the IP Block. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantContacts.value | String | Registrant Contact of the asset. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantContacts.firstSeen | Date | Date and Time when the registrant contact was first observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantContacts.lastSeen | Date | Date and Time when the registrant contact was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantContacts.recent | Boolean | If the registrant contact of the asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetRegistrantContacts.current | Boolean | If the registrant contact of the asset is current. | 
| RiskIQDigitalFootprint.Asset.assetSha1 | String | SHA1 key of the SSL certificate. | 
| RiskIQDigitalFootprint.Asset.assetSerialNumber | String | Serial number of the SSL certificate. | 
| RiskIQDigitalFootprint.Asset.assetKeySize | Number | Key size of the SSL certicate's key. | 
| RiskIQDigitalFootprint.Asset.assetVersion | Number | Version of the SSL certificate. | 
| RiskIQDigitalFootprint.Asset.assetCertificateAuthority | Boolean | If the authority of the SSL certificate is certified. | 
| RiskIQDigitalFootprint.Asset.assetSelfSigned | Boolean | If the SSL certificate observed on the asset is self signed. | 
| RiskIQDigitalFootprint.Asset.assetSignatureAlgorithm | String | Signature Algorithm of the SSL certificate. | 
| RiskIQDigitalFootprint.Asset.assetSignatureAlgorithmOid | String | Signature Algorithm OID of the SSL certificate. | 
| RiskIQDigitalFootprint.Asset.assetNotBefore | Date | Date and Time before which the SSL certificate is invalid. | 
| RiskIQDigitalFootprint.Asset.assetNotAfter | Date | Date and Time after which the SSL certificate is invalid. | 
| RiskIQDigitalFootprint.Asset.assetPublicKeyAlgorithm | String | Public Key Algorithm of the SSL certificate. | 
| RiskIQDigitalFootprint.Asset.assetId | String | ID of the SSL certificate. | 
| RiskIQDigitalFootprint.Asset.issuerCountry | String | Country of the issuer of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.issuerUnit | String | Organization unit of the issuer of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.issuerOrganization | String | Organization of the issuer of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.issuerCommonname | String | Common Name of the issuer of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.issuerState | String | State of the issuer of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.issuerLocale | String | Locale of the issuer of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.subjectCommonname | String | Common Name of the subject of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.subjectCountry | String | Country of the subject of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.subjectUnit | String | Organization unit of the subject of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.subjectOrganization | String | Organization of the subject of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.subjectState | String | State of the subject of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.subjectLocale | String | Locale of the subject of SSL certificate. | 
| RiskIQDigitalFootprint.Asset.issuerAlternativeNames | String | Issuer alternative names of the SSL certificate. | 
| RiskIQDigitalFootprint.Asset.subjectAlternativeNames | String | Subject alternative names of the SSL certificate. | 
| RiskIQDigitalFootprint.Asset.assetEmail | String | Email address associated with the contact asset. | 
| RiskIQDigitalFootprint.Asset.assetNames.value | String | Name associated with the contact asset. | 
| RiskIQDigitalFootprint.Asset.assetNames.firstSeen | Date | Date and Time when the name associated with contact asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetNames.lastSeen | Date | Date and Time when the name associated with contact asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetNames.recent | Boolean | If the name associated with contact asset is recent. | 
| RiskIQDigitalFootprint.Asset.assetNames.current | Boolean | If the name associated with contact asset is current. | 
| RiskIQDigitalFootprint.Asset.assetOrganizations.value | String | Organization associated with the contact asset. | 
| RiskIQDigitalFootprint.Asset.assetOrganizations.firstSeen | Date | Date and Time when the organization associated with contact asset was first observed. | 
| RiskIQDigitalFootprint.Asset.assetOrganizations.lastSeen | Date | Date and Time when the organization associated with contact asset was most recently observed. | 
| RiskIQDigitalFootprint.Asset.assetOrganizations.recent | Boolean | If the organization associated with contact is recent. | 
| RiskIQDigitalFootprint.Asset.assetOrganizations.current | Boolean | If the organization associated with contact is current. | 
| RiskIQDigitalFootprint.Asset.history.added | String | Added property value of the asset. | 
| RiskIQDigitalFootprint.Asset.history.changedBy | String | Name of the user who performed the change. | 
| RiskIQDigitalFootprint.Asset.history.property | String | Property name that was updated. | 
| RiskIQDigitalFootprint.Asset.history.updatedAt | Date | Date and Time when the change was most recently updated. | 
| RiskIQDigitalFootprint.Asset.history.removed | String | Removed property value of the asset. | 
| RiskIQDigitalFootprint.Asset.history.newValue | String | Value of the property after the change was performed. | 
| RiskIQDigitalFootprint.Asset.history.oldValue | String | Value of the property before the change was performed. | 
| RiskIQDigitalFootprint.Asset.history.reason | String | Reason for performing this update. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.firstSeen | Date | Date and Time when the host pair data was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.lastSeen | Date | Date and Time when the host pair data was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.count | Number | Number of times the host pair data was observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.id | String | ID of the host pair data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.childHostname | String | Child hostname of the host pair data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.parentHostname | String | Parent hostname of the host pair data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.cause | String | Cause of the host pair data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.childCount | Number | Number of times the child hostname for host pair data was observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.parentCount | Number | Number of times the parent hostname for host pair data was observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.childScore | Number | Score of the child hostname for host pair data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.parentScore | Number | Score of the parent hostname for host pair data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.hostPairs.pairScore | Number | Score of the host pair data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.firstSeen | Date | Date and Time when the attribute data was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.lastSeen | Date | Date and Time when the attribute data was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.count | Number | Number of times the attribute data was observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.id | String | ID of the attribute data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.hostname | String | Hostname of the attribute data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.domain | String | Domain of the attribute data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.attributeValue | String | Attribute value of the attribute data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.attributeType | String | Attribute type of the attribute data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.address | String | Address of the attribute data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.asn | Number | ASN number of the attribute data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.attributes.bgpPrefix | String | BGP Prefix of the attribute data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.firstSeen | Date | Date and Time when the web component data was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.lastSeen | Date | Date and Time when the web component data was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.count | Number | Number of times the web component data was observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.id | String | ID of the web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.hostname | String | Hostname of the web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.domain | String | Domain of the web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.webComponentName | String | Name of the web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.webComponentCategory | String | Category of the web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.ports.firstSeen | Date | Date and Time when the ports of web component data was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.ports.lastSeen | Date | Date and Time when the ports of web component data was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.ports.count | Number | Number of times the port of web component data was observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.ports.portNumber | Number | Port number of web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.webComponentVersion | String | Web component version of web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.address | String | Address of web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.asn | Number | ASN number of web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.bgpPrefix | String | BGP prefix of web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.cves.name | String | CVE name of web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.cves.cweID | String | CWE ID of web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.webComponents.cves.cvssScore | Number | CVSS score of web component data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.firstSeen | Date | Date and Time when when the SSL certificate data was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.lastSeen | Date | Date and Time when when the SSL certificate data was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.count | Number | Number of times the SSL certificate data was observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.id | String | ID of the SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.sha1 | String | SHA1 of the SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.version | Number | Version of the SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.serialNumber | String | Serial number of the SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.signatureAlgorithm | String | Signature algorithm of the SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.signatureAlgorithmOid | String | Signature algorithm OID of the SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.issuer.country | String | Country of the issuer of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.issuer.unit | String | Organization Unit of the issuer of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.issuer.organization | String | Organization of the issuer of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.issuer.commonname | String | Common Name of the issuer of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.issuer.state | String | State of the issuer of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.issuer.locale | String | Locale of the issuer of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.subject.commonname | String | Common Name of the subject of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.subject.country | String | Country of the subject of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.subject.unit | String | Organization Unit of the subject of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.subject.organization | String | Organization of the subject of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.subject.state | String | State of the subject of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.subject.locale | String | Locale of the subject of SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.notBefore | Date | Date and Time before which the SSL certificate data observed on the asset is invalid. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.notAfter | Date | Date and Time after which the SSL certificate data observed on the asset is invalid. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.subjectAlternativeNames | String | Subject alternative names of the SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.issuerAlternativeNames | String | Issuer alternative names of the SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.publicKeyAlgorithm | String | Public Key Algorithm of the SSL certificate data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.certificateAuthority | Boolean | If the authority of the SSL certificate data observed on the asset is certified. | 
| RiskIQDigitalFootprint.Asset.data.sslCerts.selfSigned | Boolean | If the SSL certificate data observed on the asset is self signed. | 
| RiskIQDigitalFootprint.Asset.data.cookies.firstSeen | Date | Date and Time when the cookie data was first observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.cookies.lastSeen | Date | Date and Time when the cookie data was most recently observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.cookies.count | Number | Number of times the cookie data was observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.cookies.id | String | ID of the cookie data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.cookies.hostname | String | Host name of the cookie data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.cookies.domain | String | Domain of the cookie data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.cookies.cookieDomain | String | Cookie Domain of the cookie data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.cookies.cookieName | String | Cookie name of the cookie data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.cookies.address | String | Address of the cookie data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.cookies.asn | Number | ASN number of the cookie data observed on the asset. | 
| RiskIQDigitalFootprint.Asset.data.cookies.bgpPrefix | String | BGP prefix of the cookie data observed on the asset. | 


#### Command Example
```!df-get-asset name="dummy.com" type="Domain" global="true"```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "dummy.com",
        "Score": 0,
        "Type": "domain",
        "Vendor": "RiskIQ Digital Footprint"
    },
    "Domain": {
        "Admin": {
            "Country": "",
            "Email": "admin@dummy.com",
            "Name": "Domain Manager",
            "Phone": "12 3456789101"
        },
        "Name": "dummy.com",
        "NameServers": "dummy.nameserver.com",
        "Registrant": {
            "Country": "",
            "Email": "domains@dummy.com",
            "Name": "RiskIQ, Inc.",
            "Phone": "1 2345678901"
        },
        "WHOIS": {
            "Admin": {
                "Country": "",
                "Email": "admin@dummy.com",
                "Name": "Domain Manager",
                "Phone": "12 3456789101"
            },
            "NameServers": "dummy.nameserver.com",
            "Registrant": {
                "Country": "",
                "Email": "domains@dummy.com",
                "Name": "RiskIQ, Inc.",
                "Phone": "1 2345678901"
            }
        }
    },
    "RiskIQDigitalFootprint": {
        "Asset": {
            "assetAdminContacts": [
                {
                    "current": true,
                    "firstSeen": 1558844749884,
                    "lastSeen": 1592699566724,
                    "recent": true,
                    "value": "admin@dummy.com"
                }
            ],
            "assetAlexaRank": "Not in Alexa",
            "assetCount": 1063,
            "assetDetailedFromWhoisAt": 1592699566724,
            "assetDomain": "dummy.com",
            "assetFirstSeen": 1558769518000,
            "assetLastSeen": 1593124040000,
            "assetNameServers": [
                {
                    "current": true,
                    "firstSeen": 1558769518000,
                    "lastSeen": 1593124040000,
                    "recent": true,
                    "value": "dummy.nameserver.com"
                },
                {
                    "current": true,
                    "firstSeen": 1558769518000,
                    "lastSeen": 1593124040000,
                    "recent": true,
                    "value": "dummy1.nameserver.com"
                }
            ],
            "assetParkedDomain": [
                {
                    "firstSeen": 1558836583687,
                    "lastSeen": 1558836583687,
                    "value": false
                }
            ],
            "assetRegistrantContacts": [
                {
                    "current": true,
                    "firstSeen": 1558844749884,
                    "lastSeen": 1592699566724,
                    "recent": true,
                    "value": "domains@dummy.com"
                }
            ],
            "assetRegistrantOrgs": [
                {
                    "current": true,
                    "firstSeen": 1558844749884,
                    "lastSeen": 1592699566724,
                    "recent": true,
                    "value": "RiskIQ, Inc."
                }
            ],
            "assetRegistrarCreatedAt": [
                {
                    "current": true,
                    "firstSeen": 1558844749884,
                    "lastSeen": 1592699566724,
                    "recent": true,
                    "value": 1494374400000
                }
            ],
            "assetRegistrarExpiresAt": [
                {
                    "current": true,
                    "firstSeen": 1589819603070,
                    "lastSeen": 1592699566724,
                    "recent": true,
                    "value": 1620604800000
                },
                {
                    "firstSeen": 1558844749884,
                    "lastSeen": 1589819603070,
                    "value": 1589068800000
                }
            ],
            "assetSoaRecords": [
                {
                    "current": true,
                    "email": "dummyadm@dummy.com",
                    "firstSeen": 1558769518000,
                    "lastSeen": 1593124040000,
                    "nameServer": "dummy.nameserver.com",
                    "recent": true,
                    "serialNumber": 1587126286
                }
            ],
            "assetTechnicalContacts": [
                {
                    "current": true,
                    "firstSeen": 1558844749884,
                    "lastSeen": 1592699566724,
                    "recent": true,
                    "value": "technical@dummy.com"
                }
            ],
            "assetWhoisId": 6668186720435795000,
            "assetWhoisServers": [
                {
                    "current": true,
                    "firstSeen": 1558844749884,
                    "lastSeen": 1592699566724,
                    "recent": true,
                    "value": "whois.dummy.com"
                }
            ],
            "description": "dummy.com",
            "firstSeen": 1558769518000,
            "label": "dummy.com",
            "lastSeen": 1593362239046,
            "name": "dummy.com",
            "type": "DOMAIN",
            "uuid": "78c63cee-18bb-d342-f00d-81bdbcf53be8",
            "whoisAdminEmail": "admin@dummy.com",
            "whoisAdminId": 0,
            "whoisAdminOrganization": "Domain Manager",
            "whoisAdminPhone": "12 3456789101",
            "whoisAdminWhoisContactID": 0,
            "whoisAuditCreatedAt": 1589819603039,
            "whoisAuditUpdatedAt": 1589819603039,
            "whoisCompositeParseCode": 7619,
            "whoisContactEmails": "domains@dummy.com, admin@dummy.com, technical@dummy.com, dummyadm@dummy.com",
            "whoisContactOrganizations": "RiskIQ, Inc., Domain Manager, Technical Manager, Domain Parking Admin",
            "whoisContacts": [
                {
                    "email": "domains@dummy.com",
                    "id": 0,
                    "organization": "RiskIQ, Inc.",
                    "phone": "1 2345678901",
                    "whoisContactID": 0
                },
                {
                    "email": "admin@dummy.com",
                    "id": 0,
                    "organization": "Domain Manager",
                    "phone": "12 3456789101",
                    "whoisContactID": 0
                },
                {
                    "email": "technical@dummy.com",
                    "id": 0,
                    "organization": "Technical Manager",
                    "phone": "12 3456789101",
                    "whoisContactID": 0
                },
                {
                    "email": "dummyadm@dummy.com",
                    "id": 0,
                    "organization": "Domain Parking Admin",
                    "phone": "354 5782030",
                    "whoisContactID": 0
                }
            ],
            "whoisCreatedAt": 1589819603070,
            "whoisDomain": "dummy.com",
            "whoisDomainAvailable": false,
            "whoisDomainMd5": "63dfc67f70ed3fb8f2fa1b26fa52cadc",
            "whoisDomainUnicode": "dummy.com",
            "whoisExpired": false,
            "whoisID": 6668186720435795000,
            "whoisId": 6668186720435795000,
            "whoisNameservers": "dummy.nameserver.com",
            "whoisNoRecord": false,
            "whoisRegistrantEmail": "domains@dummy.com",
            "whoisRegistrantId": 0,
            "whoisRegistrantOrganization": "RiskIQ, Inc.",
            "whoisRegistrantPhone": "1 2345678901",
            "whoisRegistrantWhoisContactID": 0,
            "whoisRegistrarCreatedAt": 1494374400000,
            "whoisRegistrarExpiresAt": 1620604800000,
            "whoisRegistrarParseCode": 0,
            "whoisRegistryParseCode": 7619,
            "whoisServer": "whois.dummy.com",
            "whoisStatus": "ACTIVE",
            "whoisTechnicalEmail": "technical@dummy.com",
            "whoisTechnicalId": 0,
            "whoisTechnicalOrganization": "Technical Manager",
            "whoisTechnicalPhone": "12 3456789101",
            "whoisTechnicalWhoisContactID": 0,
            "whoisTld": "is",
            "whoisUpdatedAt": 1592699566724
        }
    }
}
```

#### Human Readable Output

>### ASSET DETAILS
>### Basic Details
>|Name|Type|UUID|First Seen (GMT)|Last Seen (GMT)|
>|---|---|---|---|---|
>| dummy.com | DOMAIN | 78c63cee-18bb-d342-f00d-81bdbcf53be8 | 2019-05-25 07:31:58 | 2020-06-28 16:37:19 |
>### Domain Details
>|Domain Name|Alexa Rank|
>|---|---|
>| dummy.com | Not in Alexa |
>### Name Servers
>|Name|First Seen (GMT)|Last Seen (GMT)|Recent|Current|
>|---|---|---|---|---|
>| dummy.nameserver.com | 2019-05-25 07:31:58 | 2020-06-25 22:27:20 | true | true |
>| dummy1.nameserver.com | 2019-05-25 07:31:58 | 2020-06-25 22:27:20 | true | true |
>### WHOIS
>|Whois Server|Email|Organization|Phone|Name Servers|
>|---|---|---|---|---|
>| whois.dummy.com | Registrant: domains@dummy.com<br/>Admin: admin@dummy.com<br/>Technical: technical@dummy.com<br/> | Registrant: RiskIQ, Inc.<br/>Admin: Domain Manager<br/>Technical: Technical Manager<br/> | Registrant: 1 2345678901<br/>Admin: 12 3456789101<br/>Technical: 12 3456789101<br/> | dummy.nameserver.com |


### df-add-assets
***
Add one or more assets to Global Inventory with a provided set of properties to apply to all assets.


#### Base Command

`df-add-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the asset to be added. This argument supports a single value only. | Optional | 
| type | Asset type. Possible values: Domain, Host, IP Address, IP Block, ASN, Page, SSL Cert, Contact. This argument supports a single value only. | Optional | 
| state | Set the asset state. Possible values: Candidate, Approved Inventory, Requires Investigation, Dependencies, Monitor Only. This argument supports a single value only. | Optional | 
| priority | Set the asset Priority. Possible values: High, Medium, Low, None. The default value for this argument from RiskIQ platform is None. This argument supports a single value only. | Optional | 
| confirm | A boolean value to indicate if the asset state should be CONFIRMED into inventory (confirm: true) or as a CANDIDATE asset in inventory (confirm: false or not specified). This argument supports a single value only. | Optional | 
| target_asset_types | A list of target asset types to also add to inventory, along with any supplied properties, that are connected to the asset identifiers (e.g. an asset identifier for a PAGE can cascade the properties to all known IPs for that PAGE). Provide comma(,) separated values to add multiple target asset types. | Optional | 
| fail_on_error | If true then the request will fail if an invalid update is detected. If false then any invalid updates will be skipped but others will continue. The default value for this argument from RiskIQ platform is true. This argument supports a single value only. | Optional | 
| asset_json | A raw JSON payload or a file entry ID that consists of a JSON payload which has the set of properties for the asset(s) to be added to inventory. | Optional | 
| brand | Name or numeric id of a brand to be applied to the asset. Provide comma(,) separated values to add multiple brand values. | Optional | 
| organization | Name or numeric id of an organization to be applied to the asset. Provide comma(,) separated values to add multiple organization values. | Optional | 
| tag | Name or numeric id of a tag to be applied to the asset. Provide comma(,) separated values to add multiple tags. | Optional | 
| enterprise | Designated as an enterprise asset. Possible values: true, false. This argument supports a single value only. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RiskIQDigitalFootprint.Task.uuid | String | Unique Identifier to check the status of the added asset using Get Task Status request. | 
| RiskIQDigitalFootprint.Task.state | String | The state of the task for adding the asset according to the last fetch. | 
| RiskIQDigitalFootprint.Task.reason | String | The reason mentioned in the task for adding the asset according to the last fetch. | 
| RiskIQDigitalFootprint.Task.estimated | Number | Number of estimated asset\(s\) that should be added. | 
| RiskIQDigitalFootprint.Task.totalUpdates | Number | Number of total assets that have been added. | 


#### Command Example
```!df-add-assets name="testdomain.com" type="Domain"```

#### Context Example
```
{
    "RiskIQDigitalFootprint": {
        "Task": {
            "estimated": 1,
            "state": "COMPLETE",
            "totalUpdates": 1,
            "uuid": "fbe5e0a7-ec92-4a8e-bd3c-4b9c4b8cbd78"
        }
    }
}
```

#### Human Readable Output

>### The requested asset(s) have been successfully added.

### df-update-assets
***
Update one or more assets in Global Inventory with provided set of properties.


#### Base Command

`df-update-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the asset to be updated. This argument supports a single value only. | Optional | 
| type | The type of the asset to be updated. Possible values: Domain, Host, IP Address, IP Block, ASN, Page, SSL Cert, Contact. This argument supports a single value only. | Optional | 
| state | Set the asset state. Possible values: Candidate, Approved Inventory, Requires Investigation, Dependencies, Monitor Only. This argument supports a single value only. | Optional | 
| priority | Set the asset priority. Possible values: High, Medium, Low, None. The default value for this argument from RiskIQ platform is None. This argument supports a single value only. | Optional | 
| removed_state | Remove an asset from inventory. Possible values: Dismissed. This argument supports a single value only. | Optional | 
| target_asset_types | An array of related asset types which will also be updated. (e.g. an asset identifier for a PAGE can cascade the properties to all known IPs for that PAGE). | Optional | 
| fail_on_error | If true then the request will fail if an invalid update is detected. If false then any invalid updates will be skipped but others will continue. The default value for this argument from RiskIQ platform is true. This argument supports a single value only. | Optional | 
| asset_json | A raw JSON payload or a file entry ID that consists of a JSON payload which has the set of properties for the asset(s) to be updated in inventory. | Optional | 
| brand | Name or numeric id of a brand to be applied to the asset. Provide comma(,) separated values to update multiple brand values. | Optional | 
| organization | Name or numeric id of an organization to be applied to the asset. Provide comma(,) separated values to update multiple organization values. | Optional | 
| tag | Name or numeric id of a tag to be applied to the asset. Provide comma(,) separated values to update multiple tags. | Optional | 
| action | The action to be performed for updating the given properties. The possible values are: Update, Add, Remove with Update being the default. The value for this argument will be considered as action for all the properties passed by the user. This argument supports a single value only. | Optional | 
| enterprise | Designated as an enterprise asset. Possible values: true, false. This argument supports a single value only. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RiskIQDigitalFootprint.Task.uuid | String | Unique Identifier to check the status of the updating asset using Get Task Status request. | 
| RiskIQDigitalFootprint.Task.state | String | The state of the task for updating the asset according to the last fetch. | 
| RiskIQDigitalFootprint.Task.reason | String | The reason mentioned in the task for updating the asset according to the last fetch. | 
| RiskIQDigitalFootprint.Task.estimated | Number | Number of estimated asset\(s\) that should be updated. | 
| RiskIQDigitalFootprint.Task.totalUpdates | Number | Number of total asset\(s\) that have been updated. | 


#### Command Example
```!df-update-assets name="dummy.com" type="Domain" organization="RiskIQ" action="Add"```

#### Context Example
```
{
    "RiskIQDigitalFootprint": {
        "Task": {
            "estimated": 1,
            "state": "COMPLETE",
            "totalUpdates": 1,
            "uuid": "62e41139-5f0b-4583-a2b9-2b18f80b4840"
        }
    }
}
```

#### Human Readable Output

>### The requested asset(s) have been successfully updated.