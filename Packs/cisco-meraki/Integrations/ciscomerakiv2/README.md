Cloud controlled WiFi, routing, and security.
This integration was integrated and tested with version xx of Cisco Meraki V2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-cisco-meraki-v2).

## Configure Cisco Meraki V2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco Meraki V2.
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
List the organizations that the api-key has privileges on.


#### Base Command

`meraki-fetch-organizations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Organizations.id | String | ID of the organization. | 
| Meraki.Organizations.name | String | Name of the organization. | 
| Meraki.Organizations.url | String | URL of the organization. | 

### meraki-get-organization-license-state
***
License state for an organization.


#### Base Command

`meraki-get-organization-license-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationId | Organization ID. | Required | 
| networkId | Filter the licenses to those assigned in a particular network. | Optional | 
| deviceSerial | Filter the licenses to those assigned to a particular device. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Licenses.id | String | License ID. | 
| Meraki.Licenses.state | String | License state. | 
| Meraki.Licenses.expirationDate | String | License expiration date. | 

### meraki-fetch-organization-devices
***
List of devices for an organization.


#### Base Command

`meraki-fetch-organization-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationId | Organization ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Devices.name | String | Name of the device. | 
| Meraki.Devices.lat | String | Latitude of the device. | 
| Meraki.Devices.lng | String | Longitude of the device. | 
| Meraki.Devices.address | String | Address of the device. | 
| Meraki.Devices.notes | String | Notes | 
| Meraki.Devices.tags | String | Tags. | 
| Meraki.Devices.networkID | String | Network ID of the device. | 
| Meraki.Devices.serial | String | Serail of the device. | 
| Meraki.Devices.model | String | Model of the device. | 
| Meraki.Devices.mac | String | MAC address of the device. | 
| Meraki.Devices.lanIp | String | LAN IP of the device. | 
| Meraki.Devices.firmware | String | Firmware of the device. | 

### meraki-fetch-networks
***
List the networks in an organization.


#### Base Command

`meraki-fetch-networks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationId | Organization ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Networks.id | String | Network ID. | 
| Meraki.Networks.organizationId | String | The organization ID the network belongs to. | 
| Meraki.Networks.name | String | The network name. | 
| Meraki.Networks.timeZone | String | The network timezone. | 
| Meraki.Networks.tags | list | List of network tags. | 
| Meraki.Networks.productTypes | list | List of product types. | 

### meraki-fetch-network-devices
***
List the devices in a network.


#### Base Command

`meraki-fetch-network-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Devices.name | String | Device name. | 
| Meraki.Devices.lat | String | Device latitude. | 
| Meraki.Devices.lng | String | Device longitude. | 
| Meraki.Devices.serial | String | Device serial. | 
| Meraki.Devices.mac | String | Device MAC Address. | 
| Meraki.Devices.model | String | Device model. | 
| Meraki.Devices.address | String | Device address. | 
| Meraki.Devices.notes | String | Device notes. | 
| Meraki.Devices.lanIp | String | Device LAN IP. | 
| Meraki.Devices.tags | String | Device tags. | 
| Meraki.Devices.networkId | String | Device Network ID. | 
| Meraki.Devices.beaconIdParams.uuid | String | Device uuid. | 
| Meraki.Devices.beaconIdParams.major | String | Device major. | 
| Meraki.Devices.beaconIdParams.minor | String | Device minor. | 
| Meraki.Devices.firmware | String | Device firmware. | 
| Meraki.Devices.floorPlanId | String | Device floor plan ID. | 

### meraki-fetch-device
***
Fetches a device.


#### Base Command

`meraki-fetch-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Device serail. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Devices.name | String | Device name. | 
| Meraki.Devices.lat | String | Device latitude. | 
| Meraki.Devices.lng | String | Device longitude. | 
| Meraki.Devices.serial | String | Device serial. | 
| Meraki.Devices.mac | String | Device MAC Address. | 
| Meraki.Devices.model | String | Device model. | 
| Meraki.Devices.address | String | Device address. | 
| Meraki.Devices.notes | String | Device notes. | 
| Meraki.Devices.lanIp | String | Device LAN IP. | 
| Meraki.Devices.tags | String | Device tags. | 
| Meraki.Devices.networkId | String | Device Network ID. | 
| Meraki.Devices.beaconIdParams.uuid | String | Device uuid. | 
| Meraki.Devices.beaconIdParams.major | String | Device major. | 
| Meraki.Devices.beaconIdParams.minor | String | Device minor. | 
| Meraki.Devices.firmware | String | Device firmware. | 
| Meraki.Devices.floorPlanId | String | Device floor plan ID. | 

### meraki-fetch-organization-uplinks
***
List the uplink status of every Meraki MX, MG and Z series devices in the organization.


#### Base Command

`meraki-fetch-organization-uplinks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationId | Organization ID. | Required | 
| networkIds | List (CSV) of network IDs. The returned devices will be filtered to only include these networks IDs. | Optional | 
| serials | List (CSV) of serial numbers. The returned devices will be filtered to only include these serials. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Uplink.networkId | string | Network ID | 
| Meraki.Uplink.serial | string | Serial | 
| Meraki.Uplink.model | string | Model | 
| Meraki.Uplink.lastReportedAt | string | Last reported at | 
| Meraki.Uplink.uplinks.interface | string | Interface | 
| Meraki.Uplink.uplinks.status | string | Status | 
| Meraki.Uplink.uplinks.ip | string | IP | 
| Meraki.Uplink.uplinks.gateway | string | Gateway | 
| Meraki.Uplink.uplinks.publicIp | string | Public IP | 
| Meraki.Uplink.uplinks.primaryDns | string | Primary DNS | 
| Meraki.Uplink.uplinks.secondaryDns | string | Secondary DNS | 
| Meraki.Uplink.uplinks.ipAssignedBy | string | IP assigned by | 

### meraki-fetch-ssids
***
List the SSIDs in a network.


#### Base Command

`meraki-fetch-ssids`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.SSID | list | List of all SSIDs and details. | 

### meraki-fetch-device-clients
***
List the clients of a device, up to a maximum of a month ago.


#### Base Command

`meraki-fetch-device-clients`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Device serial number. | Required | 
| timespan | The timespan (in seconds) during which clients will be fetched. Must be at most one month and in seconds (e.g., 1 day is 86400 seconds). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Clients.usage.sent | number | Bytes sent by the client. | 
| Meraki.Clients.usage.recv | number | Bytes received by the client. | 
| Meraki.Clients.id | String | Client ID. | 
| Meraki.Clients.description | String | Client description. | 
| Meraki.Clients.mac | String | MAC address of the client. | 
| Meraki.Clients.ip | String | IP address of the client. | 
| Meraki.Clients.user | String | Client username. | 
| Meraki.Clients.vlan | String | VLAN ID. | 
| Meraki.Clients.namedVlan | String | Named VLAN. | 
| Meraki.Clients.switchport | String | Switchport. | 
| Meraki.Clients.adaptivePolicyGroup | String | Adaptive policy group. | 
| Meraki.Clients.mdnsName | String | MDNS name. | 
| Meraki.Clients.dhcpHostname | String | DHCP hostname. | 

### meraki-fetch-network-clients
***
List the clients of a network.


#### Base Command

`meraki-fetch-network-clients`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network ID. | Required | 
| timespan | The timespan for which the information will be fetched. The value must be in seconds and be less than or equal to 31 days. The default is 1 day. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Clients.usage.sent | number | Bytes sent by the client. | 
| Meraki.Clients.usage.recv | number | Bytes received by the client. | 
| Meraki.Clients.id | String | Client ID. | 
| Meraki.Clients.description | String | Client description. | 
| Meraki.Clients.mac | String | MAC address of the client. | 
| Meraki.Clients.ip | String | IP address of the client. | 
| Meraki.Clients.user | String | Client username. | 
| Meraki.Clients.vlan | String | VLAN ID. | 
| Meraki.Clients.namedVlan | String | Named VLAN. | 
| Meraki.Clients.switchport | String | Switchport. | 
| Meraki.Clients.adaptivePolicyGroup | String | Adaptive policy group. | 
| Meraki.Clients.mdnsName | String | MDNS name. | 
| Meraki.Clients.dhcpHostname | String | DHCP hostname. | 

### meraki-search-clients
***
Searches for a client using their MAC address.


#### Base Command

`meraki-search-clients`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organizationId | Organization ID. | Required | 
| mac | The MAC address of the client. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Search.Clients.clientId | string | Client ID. | 
| Meraki.Search.Clients.mac | string | MAC address of the client. | 
| Meraki.Search.Clients.manufacturer | String | Manufacturer. | 
| Meraki.Search.Clients.records | list | Records associated with the client. | 

### meraki-fetch-appliance-firewall-rules
***
List of L3 firewall rules for an appliance.


#### Base Command

`meraki-fetch-appliance-firewall-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Firewall.Rules.comment | string | Comment. | 
| Meraki.Firewall.Rules.policy | string | Policy. | 
| Meraki.Firewall.Rules.protocol | string | Protocol. | 
| Meraki.Firewall.Rules.dstPort | string | Destination port. | 
| Meraki.Firewall.Rules.destCidr | string | Destination CIDR. | 
| Meraki.Firewall.Rules.srcPort | string | Soirce port. | 
| Meraki.Firewall.Rules.srcCidr | string | Source CIDR. | 
| Meraki.Firewall.Rules.syslogEnabled | bool | Syslog enabled. | 

### meraki-fetch-wireless-firewall-rules
***
List of L3 firewall rules for an SSID.


#### Base Command

`meraki-fetch-wireless-firewall-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network ID. | Required | 
| number | SSID number. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Firewall.Rules.comment | string | Comment. | 
| Meraki.Firewall.Rules.policy | string | Policy. | 
| Meraki.Firewall.Rules.protocol | string | Protocol. | 
| Meraki.Firewall.Rules.dstPort | string | Destination port. | 
| Meraki.Firewall.Rules.destCidr | string | Destination CIDR. | 

### meraki-remove-device
***
Remove a single device.


#### Base Command

`meraki-remove-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network ID. | Required | 
| serial | Serial number of the device to remove. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.DeviceRemoval.serial | String | Device serial. | 
| Meraki.DeviceRemoval.networkId | String | Network ID. | 
| Meraki.DeviceRemoval.success | bool | Whether the device was removed. | 
| Meraki.DeviceRemoval.errors | list | Any errors received. | 

### meraki-update-device
***
Update the attributes of a device.


#### Base Command

`meraki-update-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| serial | Serial number of the device to update. | Required | 
| name | New name of the device. | Optional | 
| tags | New tags (CSV) of the device. | Optional | 
| address | New address of the device. | Optional | 
| lat | New latitude of the device. | Optional | 
| lng | New longitude of the device. | Optional | 
| notes | New notes of the device. | Optional | 
| moveMapMarker | Whether or not to set the latitude and longitude of a device based on the new address. Only applies when lat and lng are not specified. Possible values are: false, true. Default is false. | Optional | 
| switchProfileId | The ID of a switch profile to bind to the device (for available switch profiles, see the 'Switch Profiles' endpoint). Use null to unbind the switch device from the current profile. For a device to be bindable to a switch profile, it must (1) be a switch, and (2) belong to a network that is bound to a configuration template. | Optional | 
| floorPlanId | The floor plan to associate to this device. null disassociates the device from the floorplan. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Devices.name | String | Device name. | 
| Meraki.Devices.lat | String | Device latitude. | 
| Meraki.Devices.lng | String | Device longitude. | 
| Meraki.Devices.serial | String | Device serial. | 
| Meraki.Devices.mac | String | Device MAC Address. | 
| Meraki.Devices.model | String | Device model. | 
| Meraki.Devices.address | String | Device address. | 
| Meraki.Devices.notes | String | Device notes. | 
| Meraki.Devices.lanIp | String | Device LAN IP. | 
| Meraki.Devices.tags | String | Device tags. | 
| Meraki.Devices.networkId | String | Device Network ID. | 
| Meraki.Devices.beaconIdParams.uuid | String | Device uuid. | 
| Meraki.Devices.beaconIdParams.major | String | Device major. | 
| Meraki.Devices.beaconIdParams.minor | String | Device minor. | 
| Meraki.Devices.firmware | String | Device firmware. | 
| Meraki.Devices.floorPlanId | String | Device floor plan ID. | 

### meraki-claim-device
***
Claim a device into a network.


#### Base Command

`meraki-claim-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network ID. | Required | 
| serials | CSV of serial numbers of the devices to claim. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.ClaimDevices.serials | String | Device serial. | 
| Meraki.ClaimDevices.networkId | String | Network ID. | 
| Meraki.ClaimDevices.success | bool | Whether the device was removed. | 
| Meraki.ClaimDevices.errors | list | Any errors received. | 

### meraki-update-wireless-firewall-rules
***
Update the L3 firewall rules of an SSID on an MR network.


#### Base Command

`meraki-update-wireless-firewall-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network ID. | Required | 
| number | SSID number. Default is  . | Required | 
| allowLanAccess | Whether to allow or deny wireless client access to the local LAN. True allows access and false denies access. Possible values: true, false. Possible values are: true, false. | Required | 
| rules | An ordered array of the firewall rules for this SSID (not including the local LAN access rule or the default rule). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Firewall.Rules.comment | string | Comment. | 
| Meraki.Firewall.Rules.policy | string | Policy. | 
| Meraki.Firewall.Rules.protocol | string | Protocol. | 
| Meraki.Firewall.Rules.dstPort | string | Destination port. | 
| Meraki.Firewall.Rules.destCidr | string | Destination CIDR. | 

### meraki-update-appliance-firewall-rules
***
Update the L3 firewall rules of an MX network.


#### Base Command

`meraki-update-appliance-firewall-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkId | Network ID. | Required | 
| syslogDefaultRule | Log the special default rule (boolean value - enable only if you've configured a syslog server). Possible values are: true, false. | Optional | 
| rules | An ordered array of the firewall rules (not including the default rule). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Meraki.Firewall.Rules.comment | string | Comment. | 
| Meraki.Firewall.Rules.policy | string | Policy. | 
| Meraki.Firewall.Rules.protocol | string | Protocol. | 
| Meraki.Firewall.Rules.dstPort | string | Destination port. | 
| Meraki.Firewall.Rules.destCidr | string | Destination CIDR. | 
| Meraki.Firewall.Rules.srcPort | string | Soirce port. | 
| Meraki.Firewall.Rules.srcCidr | string | Source CIDR. | 
| Meraki.Firewall.Rules.syslogEnabled | bool | Syslog enabled. | 

## Breaking changes from the previous version of this integration - Cisco Meraki V2
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
