VMware vCenter server is a centralized management application that lets you manage virtual machines and ESXi hosts centrally.

## Configure VMware on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for VMware.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Server URL \(i.e., 192.168.0.1:30022\) | True |
    | credentials | Credentials | True |
    | insecure | Trust any certificate (not secure) Select in case you wish to circumvent server certification validation. You may want to do this in case the server you are connecting to does not have a valid certificate. | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Use Cases
- Create and revert to snapshot.
- Get information regarding virtual machines.
- Power-on, power-off, suspend and rebooting virtual machines.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### vmware-get-vms
***
Returns all virtual machines on a system.


#### Base Command

`vmware-get-vms`

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWare.Name | String | VM name. | 
| VMWare.Template | bool | true if template, else false. | 
| VMWare.Path | String | Path to VM. | 
| VMWare.Guest | String | Guest full name. | 
| VMWare.UUID | String | VM instance UUID. | 
| VMWare.IP | String | VM IP address. | 
| VMWare.State | String | VM state \(i.e., poweredOn, poweredOff, suspended, HardRebooted\). | 
| VMWare.HostName | String | Host name of VM. | 
| VMWare.MACAddress | String | MAC address of VM .| 


#### Command Example
``` !vmware-get-vms ```

#### Context Example
```json
{
  "VMWare":[
    {
        "Guest": "Ubuntu Linux (64-bit)",
        "HostName": "ubuntu",
        "IP": "192.168.100.1",
        "MACAddress": "00:50:56:bc:86:ec",
        "Name": "UbuntuTest",
        "Path": "[datastore1] UbuntuTest/UbuntuTest.vmx",
        "State": "poweredOn",
        "Template": false,
        "UUID": "503ca58b-0821-cf21-fb56-459e55df6d19"
    }
  ]
}
```


### vmware-poweron
***
Powers on a powered-off or suspended virtual machine.


#### Base Command

`vmware-poweron`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm-uuid | VM UUID of virtual machine to be powered on. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWare.UUID | String | VM instance UUID. | 
| VMWare.State | String | VM state \(i.e., poweredOn, poweredOff, suspended, HardRebooted\). | 


#### Command Example
```!vmware-poweron vm-uuid="503ca58b-0821-cf21-fb56-459e55df6d19" ```

#### Context Example
```json
{
  "VMWare": {
      "State": "poweredOn",
      "UUID": "503ca58b-0821-cf21-fb56-459e55df6d19"
    }
}
```
#### Human Readable Output
> Virtual Machine was powered on successfully.


### vmware-poweroff
***
Powers off a powered-on or suspended virtual machine.


#### Base Command

`vmware-poweroff`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm-uuid | VM UUID of virtual machine to be powered on. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWare.UUID | String | VM instance UUID. | 
| VMWare.State | String | VM state \(i.e., poweredOn, poweredOff, suspended, HardRebooted\). | 


#### Command Example
```!vmware-poweroff vm-uuid="503ca58b-0821-cf21-fb56-459e55df6d19" ```

#### Context Example
```json
{
  "VMWare": {
      "State": "poweredOff",
      "UUID": "503ca58b-0821-cf21-fb56-459e55df6d19"
    }
}
```
#### Human Readable Output
> Virtual Machine was powered off successfully.



### vmware-hard-reboot
***
Reboots a powered-on virtual machine.


#### Base Command

`vmware-hard-reboot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm-uuid | VM UUID of virtual machine to reboot. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWare.UUID | String | VM instance UUID. | 
| VMWare.State | String | VM state \(i.e., poweredOn, poweredOff, suspended, HardRebooted\). | 


#### Command Example
```!vmware-hard-reboot vm-uuid="503ca58b-0821-cf21-fb56-459e55df6d19" ```

#### Context Example
```json
{
  "VMWare": {
      "State": "HardRebooted",
      "UUID": "503ca58b-0821-cf21-fb56-459e55df6d19"
    }
}
```

#### Human Readable Output
> Virtual Machine was rebooted successfully.


### vmware-suspend
***
Suspends a powered-on virtual machine.


#### Base Command

`vmware-suspend`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm-uuid | VM UUID of virtual machine to be suspended. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWare.UUID | String | VM instance UUID. | 
| VMWare.State | String | VM state \(i.e., poweredOn, poweredOff, suspended, HardRebooted\), | 


#### Command Example
```!vmware-suspend vm-uuid="503ca58b-0821-cf21-fb56-459e55df6d19" ```

#### Context Example
```json
{
  "VMWare": {
      "State": "suspended",
      "UUID": "503ca58b-0821-cf21-fb56-459e55df6d19"
    }
}
```

#### Human Readable Output
> Virtual Machine was suspended successfully.


### vmware-soft-reboot
***
Issues a command to the guest operating system asking it to perform a reboot.


#### Base Command

`vmware-soft-reboot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm-uuid | VM UUID of virtual machine to reboot. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!vmware-soft-reboot vm-uuid="503ca58b-0821-cf21-fb56-459e55df6d19" ```

#### Human Readable Output
> A request to reboot the guest has been sent.


### vmware-create-snapshot
***
Creates a VM snapshot.


#### Base Command

`vmware-create-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm-uuid | VM UUID of virtual machine to take snapshot of. | Required | 
| name | Snapshot name. | Optional | 
| description | Snapshot description. | Optional | 
| memory | Snapshot the virtual machine's memory. Default is "True". | Optional | 
| quiesce | Quiesce guest file system (needs VMWare Tools installed). Default is "False". | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!vmware-create-snapshot vm-uuid="503ca58b-0821-cf21-fb56-459e55df6d19" name="SnapShotName" description="A daily snapshot of VM" memory=true quiesce=false ```

#### Human Readable Output
>Snapshot SnapShotName completed.


### vmware-revert-snapshot
***
Reverts VM to snapshot.


#### Base Command

`vmware-revert-snapshot`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| snapshot-name | Snapshot name to revert to. | Required | 
| vm-uuid | VM UUID of virtual machine to revert snapshot. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWare.UUID | String | VM instance UUID. | 
| VMWare.Snapshot | String | Name of the snapshot reverted to. | 


#### Command Example
```!vmware-revert-snapshot  vm-uuid="503ca58b-0821-cf21-fb56-459e55df6d19" snapshot-name="SnapShotName"```

#### Context Example
```json
{
  "VMWare": {
      "Snapshot": "Reverted to SnapShotName",
      "UUID": "503ca58b-0821-cf21-fb56-459e55df6d19"
    }
}
```
#### Human Readable Output
> Reverted to snapshot SnapShotName successfully.


### vmware-get-events
***
Gets events of VM


#### Base Command

`vmware-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm-uuid | VM UUID of virtual machine to get events of. | Required | 
| event-type | Type of events to get, given in CSV (i.e.,  VmGuestRebootEvent,VmGuestShutdownEvent). | Optional | 


#### Context Output

There is no context output for this command.


### vmware-change-nic-state
***
Changes the state of a VM NIC.


#### Base Command

`vmware-change-nic-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm-uuid | VM UUID of virtual machine to change NIC state. | Required | 
| nic-state | New state of the NIC to be changed. | Required | 
| nic-number | Number of the NIC to be changed. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWare.UUID | String | VM instance UUID. | 
| VMWare.NICState | String | VM NIC state \(i.e., connected, disconnected, delete\). | 


#### Command Example
```!vmware-change-nic-state vm-uuid="503ca58b-0821-cf21-fb56-459e55df6d19" nic-state="disconnected" nic-number=1 ```

#### Context Example
```json
{
  "VMWare": {
      "NICState": "disconnected",
      "UUID": "503ca58b-0821-cf21-fb56-459e55df6d19"
    }
}
```
#### Human Readable Outpu
> Virtual Machine's NIC was disconnected successfully.

