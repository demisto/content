Cloud controlled WiFi, routing, and security
This integration was integrated and tested with version 1.0.0 of Cisco Meraki

## Configure Cisco Meraki on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco Meraki.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### meraki-fetch-organizations
***
List the organizations that the api-key has privileges on


#### Base Command

`meraki-fetch-organizations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Organization | List | List of organizations, each includes ID &amp; Name | 


#### Command Example
```!meraki-fetch-organizations```

#### Context Example
```json
{
    "Organization": [
        {
            "ID": "828552",
            "Name": "Demisto"
        }
    ]
}
```

#### Human Readable Output

>### Organizations
>|id|name|url|
>|---|---|---|
>|828552|Demisto|https:<span>//</span>n146.meraki.com/o/N7z3rd/manage/organization/overview|


### meraki-get-organization-license-state
***
License state for an organization


#### Base Command

`meraki-get-organization-license-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationId | Organization id. | Required | 
| headers | Table's headers to be shown by order. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| status | String | license status |
| expirationDate | String | license expiration date |

#### Command Example
```!meraki-get-organization-license-state organizationId=828552```

#### Human Readable Output

>### Organization License State
>|status|expirationDate|
>|---|---|
>|OK|N/A|


### meraki-fetch-organization-inventory
***
List of Inventories for an organization


#### Base Command

`meraki-fetch-organization-inventory`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationId | Organization id. | Required | 
| headers | Table's headers to be shown by order. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Devices | List | List of devices, each includes Serial, NetworkId, Model, ClaimedAt, PublicIp &amp; Mac | 


#### Command Example
``` ```

#### Human Readable Output



### meraki-fetch-networks
***
List the networks in an organization


#### Base Command

`meraki-fetch-networks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationId | Organization id. | Required | 
| headers | Table's headers to be shown by order. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Network | List | List of networks, each includes ID, Name, Type, OrganizationId, Tags &amp; TimeZone | 


#### Command Example
```!meraki-fetch-networks organizationId=828552```

#### Context Example
```json
{
    "Network": [
        {
            "ID": "N_645140646620837008",
            "Name": "Demisto-DEV",
            "OrganizationId": "828552",
            "Tags": null,
            "Timezone": "America/Los_Angeles",
            "Type": "switch"
        }
    ]
}
```

#### Human Readable Output

>### Networks
>|id|organizationId|name|timeZone|productTypes.0|type|disableMyMerakiCom|disableRemoteStatusPage|
>|---|---|---|---|---|---|---|---|
>|N_645140646620837008|828552|Demisto-DEV|America/Los_Angeles|switch|switch|-|true|


### meraki-fetch-devices
***
List the devices in a network


#### Base Command

`meraki-fetch-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network id. | Required | 
| headers | Table's headers to be shown by order. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Device | List | List of devices, each includes Serial, Name, Lat, Lng, Model, NetworkId, Tags, MAC &amp; Address | 


#### Command Example
``` ```

#### Human Readable Output



### meraki-fetch-device-uplink
***
List of uplink information for a device.


#### Base Command

`meraki-fetch-device-uplink`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network id. | Required | 
| serial | Device serial#. | Required | 
| headers | Table's headers to be shown by order. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uplink | List | List of device uplink, each includes Status &amp; Interface | 


#### Command Example
``` ```

#### Human Readable Output



### meraki-fetch-ssids
***
List the SSIDs in a network


#### Base Command

`meraki-fetch-ssids`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network id. | Required | 
| headers | Table's headers to be shown by order. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SSID | List | List of SSIDs, each includes Number, NetworkId, Name, SplashPage, BandSelection, Enabled, AuthMode &amp; WalledGardenRanges | 


#### Command Example
``` ```

#### Human Readable Output



### meraki-fetch-clients
***
List the clients of a device, up to a maximum of a month ago


#### Base Command

`meraki-fetch-clients`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Device serial#. | Required | 
| timespan |  The timespan(in seconds) for which clients will be fetched. Must be at most one month and in seconds (e.g. 1 day is 86400 seconds). | Required | 
| headers | Table's headers to be shown by order. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Client | List | List of clients, each includes ID, MAC, IP, Description, mDNSName, Hostname, Usage &amp; VLAN | 


#### Command Example
``` ```

#### Human Readable Output



### meraki-fetch-firewall-rules
***
List of L3 firewall rules for an SSID


#### Base Command

`meraki-fetch-firewall-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network id. | Required | 
| number | SSID number. | Required | 
| headers | Table's headers to be shown by order. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Firewall | List | List of firewalls, each includes Number, NetworkId, Policy, Protocol, DestPort, DestCidr &amp; Comment | 


#### Command Example
``` ```

#### Human Readable Output



### meraki-remove-device
***
Remove a single device


#### Base Command

`meraki-remove-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network id. | Required | 
| serial | Device serial to remove. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### meraki-get-device
***
Get a single device


#### Base Command

`meraki-get-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network id. | Required | 
| serial | Device serial. | Required | 
| headers | Table's headers to be shown by order. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Device | unknown | Device which includes Serial, Name, Lat, Lng, Model, NetworkId, Tags, MAC &amp; Address | 


#### Command Example
``` ```

#### Human Readable Output



### meraki-update-device
***
Update the attributes of a device


#### Base Command

`meraki-update-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network id. | Required | 
| serial | Device serial to update. | Required | 
| name | New name of the device. | Optional | 
| tags | New tags of the device. | Optional | 
| address | New address of the device. | Optional | 
| lat | New latitude of the device. | Optional | 
| lng | New longitude of the device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Device | unknown | Updated device which includes Serial, Name, Lat, Lng, Model, NetworkId, Tags, MAC &amp; Address | 


#### Command Example
``` ```

#### Human Readable Output



### meraki-claim-device
***
Claim a device into a network


#### Base Command

`meraki-claim-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network id. | Required | 
| serial | Device serial to claim. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### meraki-update-firewall-rules
***
update rule to L3 firewall rules of an SSID


#### Base Command

`meraki-update-firewall-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network id. | Required | 
| number | SSID number. Default is  . | Required | 
| allowLanAccess | allow or deny wireless client access to local LAN, true allows access and false denies access. Possible values are: true, false. | Required | 
| policy |  Whether or not you want to allow or deny a protocol (value must be 'allow' or 'deny'). Possible values are: allow, deny. | Required | 
| protocol | The type of protocol (must be 'tcp','udp', 'icmp' or 'any'). Possible values are: tcp, udp, icmp, any. | Required | 
| destPort |  The destination port (can be 'any' or an integer within the range of 1-65535). | Required | 
| destCidr | The destination IP address or subnet in CIDR form, can also be 'any'. | Required | 
| comment | A note about the rule. | Optional | 
| removeOthers | true to remove all others rule, false to only add rule. Possible values are: true, false. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Firewall | List | List of firewalls, each includes Number, NetworkId, Policy, Protocol, DestPort, DestCidr &amp; Comment | 


#### Command Example
``` ```

#### Human Readable Output


