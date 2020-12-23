The Nozomi Networks Guardian platform is a hardware or virtual appliance that is used to monitor OT/IoT/IT networks. It combines asset discovery, network visualization, vulnerability assessment, risk monitoring and threat detection in a single solution.
  This integration is used to gather alert and asset information from Nozomi.

## Configure Nozomi Networks on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Nozomi Networks.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| endpoint | Endpoint url | True |
| username | Username | True |
| password | Password | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| fetchTime | Get incidents from last | False |
| riskFrom | Get incidents from risk level | False |
| fecthAlsoIncidents | Fetch also nozomi incidents | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nozomi-find-assets
***
This command permits you to get some assets from Nozomi, you can use the query filter to to refine your search. With the limits you can decide the max number of assets you can retrieve from Nozomi, the limit can't be bigger than 1000.


#### Base Command

`nozomi-find-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | You can add a filter to get exactly the assets you want. For example 'where ip match 10.0.1.10', 'where vendor ==  Selta Telematica S.p.a' | Optional | 
| limit | Maximun number of assets get from Nozomi, can't be bigger than 1000 | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nozomi.Asset.id | String | uniq id of an asset | 
| Nozomi.Asset.level | Number | network layer | 
| Nozomi.Asset.capture_device | String | source from which the asset was captured | 
| Nozomi.Asset.ip | Unknown | array of asset ip | 
| Nozomi.Asset.mac_address | Unknown | array of asset mac address | 
| Nozomi.asset.mac_vendor | Unknown | array of mac vendor | 
| os | String | operating system | 
| vendor | String | asset vendor | 
| Nozomi.Asset.firmware_version | String | firmaware version | 
| serial_number | String | serial number | 
| product_name | String | product name | 
| type | String | asset type as 'OT\_device' | 
| protocols | Unknown | array of asset protocols | 


#### Command Example
```!nozomi-find-assets limit=3 filter="| where level == 4"```

#### Context Example
```
{
    "Nozomi": {
        "Asset": [
            {
                "name": "10.197.23.146",
                "level": "1",
                "id": "a3707ec4-7c85-437e-9d46-dbabd39b4dc2",
                "appliance_hosts": [
                    "nozomi-dev"
                ],
                "capture_device": "/vagrant/ids-testapi/fixtures/iec104_mestre_mini.pcap",
                "ip": [
                    "10.197.23.146"
                ],
                "mac_address": [
                    "00:02:3e:99:fe:1b"
                ],
                "mac_address_level": {
                    "00:02:3e:99:fe:1b": "unconfirmed"
                },
                "vlan_id": [],
                "mac_vendor": [
                    "Selta Telematica S.p.a"
                ],
                "os": "",
                "roles": [
                    "slave"
                ],
                "vendor": "",
                "_asset_kb_id": "",
                "vendor:info": {
                    "source": "passive"
                },
                "firmware_version": "",
                "firmware_version:info": {
                    "source": "passive"
                },
                "os_or_firmware": "",
                "serial_number": "",
                "serial_number:info": {
                    "source": "passive"
                },
                "product_name": "",
                "product_name:info": {
                    "source": "passive"
                },
                "type": "OT_device",
                "type:info": {
                    "source": "passive"
                },
                "protocols": [
                    "iec104"
                ],
                "nodes": [
                    "10.197.23.146"
                ],
                "zones": [
                    "RemoteRTU"
                ],
                "custom_fields": {}
            }
        ]
    }
}
```

#### Human Readable Output

>Nozomi Networks - No assets found

### nozomi-close-incidents-as-security
***
Close incidents as security


#### Base Command

`nozomi-close-incidents-as-security`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | List of IDs to close as security | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nozomi.CloseStatus | String | Status of the request | 
| Ids | Unknown | Ids closed | 
| CloseAction | String | As the incidents are closed | 


#### Command Example
```!nozomi-close-incidents-as-security ids=['fa441619-39d4-46c1-a2fb-fc3b285c0b64']```

#### Context Example
```
{
    "Nozomi": {
        "CloseAction": "closed_as_security",
        "CloseStatus": "SUCCESS",
        "Ids": [
            "fa441619-39d4-46c1-a2fb-fc3b285c0b64"
        ]
    }
}
```

#### Human Readable Output

>Command changes the status of alerts passed as "closed_as_security" in Nozomi Networks platform.

### nozomi-close-incidents-as-change
***
Close incidents as change


#### Base Command

`nozomi-close-incidents-as-change`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | List of IDs to close as change. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nozomi.CloseStatus | String | Status of the request | 
| Ids | Unknown | Ids closed | 
| CloseAction | String | As the incidents are closed | 


#### Command Example
```!nozomi-close-incidents-as-change ids=['fa441619-39d4-46c1-a2fb-fc3b285c0b64']```

#### Context Example
```
{
    "Nozomi": {
        "CloseAction": "closed_as_change",
        "CloseStatus": "SUCCESS",
        "Ids": [
            "fa441619-39d4-46c1-a2fb-fc3b285c0b64"
        ]
    }
}
```

#### Human Readable Output

>Command changes the status of alerts passed as "closed_as_change" in Nozomi Networks platform.

### nozomi-query
***
Can execute a nozomi query to get all the information you want.
A query can be something like that: "alerts | select id name status ack | where status == open"
Take a look to n2os manual to know how to do a query.


#### Base Command

`nozomi-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A valid query  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nozomi.Result | Unknown | An array of items | 
| Nozomi.Error | String | In case the query is not correct the errors shows you the reason. | 


#### Command Example
```!nozomi-query query="links | where from match 192.168.10.2 | where protocol match ssh"```

#### Context Example
```
{
    "Nozomi": {
        "Result": []
    }
}
```

#### Human Readable Output

>### Nozomi Networks - Results for Query
>**No entries.**


### nozomi-find-ip-by-mac
***
Find a node ip from a mac address


#### Base Command

`nozomi-find-ip-by-mac`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mac | a mac address | Required | 
| only_nodes_confirmed | This argument permit you to return only the nodes IPs from a mac address of nodes having the status to 'confirmed'. Default value is True.  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nozomi.Ips | Unknown | Array of ips found for the mac address passed, empty if not found. | 
| Nozomi.Error | String | Usually an ip not found error | 


#### Command Example
```!nozomi-find-ip-by-mac mac='00:0c:29:22:50:26' only_nodes_confirmed='True'```

#### Context Example
```
{
    "Nozomi": {
        "Error": "Ip not found"
    }
}
```

#### Human Readable Output

>Nozomi Networks - No IP results were found for mac address: '00:0c:29:22:50:26'
