The Lansweeper integration allows users to retrieve the asset details.
This integration was integrated and tested with version 2.0 of Lansweeper

## Configure Lansweeper in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Application Identity Code | Identity code generated for the specific application. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ls-site-list
***
Retrieve a list of all sites to which an application has access.


#### Base Command

`ls-site-list`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lansweeper.Site.id | String | Site ID. | 
| Lansweeper.Site.name | String | Site name. | 


#### Command Example
```!ls-site-list```

#### Context Example
```json
{
    "Lansweeper": {
        "Site": [
            {
                "id": "401d153d-2a59-45eb-879a-c291390448ca",
                "name": "api-demo-data"
            },
            {
                "id": "56d4ed4f-b2ad-4587-91b5-07bd453c5c76",
                "name": "api-demo-data-v2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Authorized Site(s)
>|Site ID|Site Name|
>|---|---|
>| 401d153d-2a59-45eb-879a-c291390448ca | api-demo-data |
>| 56d4ed4f-b2ad-4587-91b5-07bd453c5c76 | api-demo-data-v2 |


### ls-ip-hunt
***
Return a list of all assets associated with a given site and IP address.


#### Base Command

`ls-ip-hunt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Specify the site ID to retrieve the assets.<br/><br/>Note: To get site ID, execute ls-site-list command. | Optional | 
| ip | Specify the IP address to retrieve the specific asset. <br/><br/>Note: Supports multiple comma separated values. | Required | 
| limit | Number of records to retrieve in the response.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is 500. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lansweeper.IP.assetId | String | Asset ID. | 
| Lansweeper.IP.assetBasicInfo.name | String | Asset name. | 
| Lansweeper.IP.assetBasicInfo.domain | String | Domain the asset belongs to. | 
| Lansweeper.IP.assetBasicInfo.description | String | Description of the asset. | 
| Lansweeper.IP.assetBasicInfo.firstSeen | Date | Date and time at which the asset was first scanned. | 
| Lansweeper.IP.assetBasicInfo.fqdn | String | FQDN of the asset. | 
| Lansweeper.IP.assetBasicInfo.ipAddress | String | IP address associated with the asset. | 
| Lansweeper.IP.assetBasicInfo.lastSeen | Date | Date and time at which the asset was last scanned. | 
| Lansweeper.IP.assetBasicInfo.mac | String | Asset's main MAC address. | 
| Lansweeper.IP.assetBasicInfo.userName | String | Name of the last logged on user. | 
| Lansweeper.IP.assetBasicInfo.type | String | Type of the asset. | 
| Lansweeper.IP.assetBasicInfo.userDomain | String | Domain of the last logged on user. | 
| Lansweeper.IP.assetCustom.sku | String | Asset's SKU. | 
| Lansweeper.IP.assetCustom.model | String | Model of the asset. | 
| Lansweeper.IP.assetCustom.firmwareVersion | String | Firmware version, retrieved from plug and play devices via the UPnP, DNS-SD or SSDP protocol. | 
| Lansweeper.IP.assetCustom.purchaseDate | Date | When the asset was purchased. | 
| Lansweeper.IP.assetCustom.warrantyDate | Date | When the asset's warranty expires. | 
| Lansweeper.IP.assetCustom.comment | String | Comment on the asset.. | 
| Lansweeper.IP.assetCustom.location | String | Location of the asset. | 
| Lansweeper.IP.assetCustom.contact | String | Contact person of the asset. | 
| Lansweeper.IP.assetCustom.manufacturer | String | Manufacturer of the asset. | 
| Lansweeper.IP.assetCustom.serialNumber | String | Serial number of the asset. | 
| Lansweeper.IP.assetCustom.dnsName | String | DNS name of the asset. | 
| Lansweeper.IP.assetCustom.stateName | String | State name of the asset. | 
| Lansweeper.IP.operatingSystem.caption | String | Short description of the object. The string includes the operating system version. | 
| Lansweeper.IP.operatingSystem.productType | String | Type of the operating system. | 
| Lansweeper.IP.url | String | URL to the summary of the asset. | 
| Lansweeper.IP.siteId | String | The ID of the site to which the asset belongs. | 
| Lansweeper.IP.siteName | String | The name of the site to which the asset belongs. | 


#### Command Example
```!ls-ip-hunt ip="192.168.2.1"```

#### Context Example
```json
{
    "Lansweeper": {
        "IP": [
            {
                "assetBasicInfo": {
                    "firstSeen": "2018-06-15T12:03:34.917Z",
                    "ipAddress": "192.168.2.1",
                    "lastSeen": "2018-07-19T14:45:58.793Z",
                    "mac": "02:0C:29:FE:A6:64",
                    "name": "192.168.2.1",
                    "type": "Network device"
                },
                "assetCustom": {
                    "stateName": "Active"
                },
                "assetId": "608fa4d61be3044511e7239e",
                "siteId": "401d153d-2a59-45eb-879a-c291390448ca",
                "siteName": "api-demo-data",
                "url": "https://app.lansweeper.com/api-demo-data/asset/MTI3My1Bc3NldC0wZGYzZGRiYS0zNzA3LTQ0ZWUtOWI0My1jMTkxOTQ1NmZkYTE=/summary"
            },
            {
                "assetBasicInfo": {
                    "firstSeen": "2018-06-15T10:02:34.917Z",
                    "ipAddress": "192.168.2.1",
                    "lastSeen": "2018-07-19T12:44:58.793Z",
                    "mac": "02:0C:29:FE:A6:64",
                    "name": "192.168.2.1",
                    "type": "Network device"
                },
                "assetCustom": {
                    "stateName": "Active"
                },
                "assetId": "60eed3ba8a037f9341893701",
                "siteId": "56d4ed4f-b2ad-4587-91b5-07bd453c5c76",
                "siteName": "api-demo-data-v2",
                "url": "https://app.lansweeper.com/api-demo-data-v2/asset/MTI3My1Bc3NldC1mODdkZjg5MS1kNmVkLTQyYzgtYThmMS1jZDJmMTBlYmE1ZGU=/summary"
            }
        ]
    }
}
```

#### Human Readable Output

>### Asset(s)
>|Name|Domain|User Name|User Domain|FQDN|Description|Type|IP Address|Mac Address|Model|Manufacturer|Serial Number|SKU|Site Name|First Seen|Last Seen|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| [XLAN-897](https://app.lansweeper.com/api-demo-data/asset/ODk3LUFzc2V0LTBkZjNkZGJhLTM3MDctNDRlZS05YjQzLWMxOTE5NDU2ZmRhMQ==/summary) | Demo-domain | John Doe | Demo-domain | Demo67.com | Video / Image Editing | APC | 192.168.2.1 | 03:00:00:00:00:57 | iMac18,3 | Apple | LAN897 | LN001 | api-demo-data | 2018-02-12T16:04:02.733Z | 2018-02-12T16:04:02.733Z |
>| [XLAN-897](https://app.lansweeper.com/api-demo-data-v2/asset/ODk3LUFzc2V0LWY4N2RmODkxLWQ2ZWQtNDJjOC1hOGYxLWNkMmYxMGViYTVkZQ==/summary) | Demo-domain | John Doe | Demo-domain | Demo67.com | Video / Image Editing | APC | 192.168.2.1 | 03:00:00:00:00:57 | iMac18,3 | Apple | LAN897 | LN001 | api-demo-data-v2 | 2018-02-12T14:04:02.733Z | 2021-08-10T14:18:20.913Z |


### ls-mac-hunt
***
Return a list of all assets associated with a given site and MAC address.


#### Base Command

`ls-mac-hunt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | Specify the site ID to retrieve the assets.<br/><br/>Note: To get site ID, execute ls-site-list command. | Optional | 
| mac_address | Specify the MAC address to retrieve the specific asset. <br/><br/>Note: Supports multiple comma separated values. | Required | 
| limit | Number of records to retrieve in the response.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is 500. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lansweeper.Mac.assetId | String | Asset ID. | 
| Lansweeper.Mac.assetBasicInfo.name | String | Asset name. | 
| Lansweeper.Mac.assetBasicInfo.domain | String | Domain the asset belongs to. | 
| Lansweeper.Mac.assetBasicInfo.description | String | Description of the asset. | 
| Lansweeper.Mac.assetBasicInfo.firstSeen | Date | Date and time at which the asset was first scanned. | 
| Lansweeper.Mac.assetBasicInfo.fqdn | String | FQDN of the asset. | 
| Lansweeper.Mac.assetBasicInfo.ipAddress | String | IP address associated with the asset. | 
| Lansweeper.Mac.assetBasicInfo.lastSeen | Date | Date and time at which the asset was last scanned. | 
| Lansweeper.Mac.assetBasicInfo.mac | String | Asset's main MAC address. | 
| Lansweeper.Mac.assetBasicInfo.userName | String | Name of the last logged on user. | 
| Lansweeper.Mac.assetBasicInfo.type | String | Type of the asset. | 
| Lansweeper.Mac.assetBasicInfo.userDomain | String | Domain of the last logged on user. | 
| Lansweeper.Mac.assetCustom.sku | String | Asset's SKU. | 
| Lansweeper.Mac.assetCustom.model | String | Model of the asset. | 
| Lansweeper.Mac.assetCustom.firmwareVersion | String | Firmware version, retrieved from plug and play devices via the UPnP, DNS-SD or SSDP protocol. | 
| Lansweeper.Mac.assetCustom.purchaseDate | Date | When the asset was purchased. | 
| Lansweeper.Mac.assetCustom.warrantyDate | Date | When the asset's warranty expires. | 
| Lansweeper.Mac.assetCustom.comment | String | Comment on the asset.. | 
| Lansweeper.Mac.assetCustom.location | String | Location of the asset. | 
| Lansweeper.Mac.assetCustom.contact | String | Contact person of the asset. | 
| Lansweeper.Mac.assetCustom.manufacturer | String | Manufacturer of the asset. | 
| Lansweeper.Mac.assetCustom.serialNumber | String | Serial number of the asset. | 
| Lansweeper.Mac.assetCustom.dnsName | String | DNS name of the asset. | 
| Lansweeper.Mac.assetCustom.stateName | String | State name of the asset. | 
| Lansweeper.Mac.operatingSystem.caption | String | Short description of the object. The string includes the operating system version. | 
| Lansweeper.Mac.operatingSystem.productType | String | Type of the operating system. | 
| Lansweeper.Mac.url | String | URL to the summary of the asset. | 
| Lansweeper.Mac.siteId | String | The ID of the site to which the asset belongs. | 
| Lansweeper.Mac.siteName | String | The name of the site to which the asset belongs. | 


#### Command Example
```!ls-mac-hunt mac_address="03:00:00:00:00:57"```

#### Context Example
```json
{
    "Lansweeper": {
        "Mac": [
            {
                "assetBasicInfo": {
                    "domain": "Demo-domain",
                    "firstSeen": "2018-02-12T16:04:02.733Z",
                    "fqdn": "Demo67.com",
                    "ipAddress": "10.10.11.104",
                    "lastSeen": "2018-02-12T16:04:02.733Z",
                    "mac": "03:00:00:00:00:57",
                    "name": "XLAN-897",
                    "type": "APC",
                    "userDomain": "Demo-domain"
                },
                "assetCustom": {
                    "location": "Main Branch",
                    "purchaseDate": "2018-02-02T00:00:00.000Z",
                    "serialNumber": "LAN897",
                    "stateName": "Active",
                    "warrantyDate": "2023-02-02T00:00:00.000Z"
                },
                "assetId": "608fa4c81be3044511e6d97f",
                "siteId": "401d153d-2a59-45eb-879a-c291390448ca",
                "siteName": "api-demo-data",
                "url": "https://app.lansweeper.com/api-demo-data/asset/ODk3LUFzc2V0LTBkZjNkZGJhLTM3MDctNDRlZS05YjQzLWMxOTE5NDU2ZmRhMQ==/summary"
            },
            {
                "assetBasicInfo": {
                    "domain": "Demo-domain",
                    "firstSeen": "2018-02-12T14:04:02.733Z",
                    "fqdn": "Demo67.com",
                    "ipAddress": "10.10.11.104",
                    "lastSeen": "2021-08-10T14:18:20.913Z",
                    "mac": "03:00:00:00:00:57",
                    "name": "XLAN-897",
                    "type": "APC",
                    "userDomain": "Demo-domain"
                },
                "assetCustom": {
                    "location": "Main Branch",
                    "purchaseDate": "2018-02-02T02:00:00.000Z",
                    "serialNumber": "LAN897",
                    "stateName": "Active",
                    "warrantyDate": "2023-02-02T02:00:00.000Z"
                },
                "assetId": "60eed3b78a037f934189271c",
                "siteId": "56d4ed4f-b2ad-4587-91b5-07bd453c5c76",
                "siteName": "api-demo-data-v2",
                "url": "https://app.lansweeper.com/api-demo-data-v2/asset/ODk3LUFzc2V0LWY4N2RmODkxLWQ2ZWQtNDJjOC1hOGYxLWNkMmYxMGViYTVkZQ==/summary"
            }
        ]
    }
}
```

#### Human Readable Output

>### Asset(s)
>|Name|Domain|User Name|User Domain|FQDN|Description|Type|IP Address|Mac Address|Model|Manufacturer|Serial Number|SKU|Site Name|First Seen|Last Seen|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| [XLAN-897](https://app.lansweeper.com/api-demo-data/asset/ODk3LUFzc2V0LTBkZjNkZGJhLTM3MDctNDRlZS05YjQzLWMxOTE5NDU2ZmRhMQ==/summary) | Demo-domain | John Doe | Demo-domain | Demo67.com | Video / Image Editing | APC | 10.10.11.104 | 03:00:00:00:00:57 | iMac18,3 | Apple | LAN897 | LN001 | api-demo-data | 2018-02-12T16:04:02.733Z | 2018-02-12T16:04:02.733Z |
>| [XLAN-897](https://app.lansweeper.com/api-demo-data-v2/asset/ODk3LUFzc2V0LWY4N2RmODkxLWQ2ZWQtNDJjOC1hOGYxLWNkMmYxMGViYTVkZQ==/summary) | Demo-domain | John Doe | Demo-domain | Demo67.com | Video / Image Editing | APC | 10.10.11.104 | 03:00:00:00:00:57 | iMac18,3 | Apple | LAN897 | LN001 | api-demo-data-v2 | 2018-02-12T14:04:02.733Z | 2021-08-10T14:18:20.913Z |
