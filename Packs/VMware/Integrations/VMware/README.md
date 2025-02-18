VMware vCenter server is a centralized management application that lets you manage virtual machines and ESXi hosts centrally.
This integration was integrated and tested with version 7.03 of VMware

## Configure VMware in Cortex


| **Parameter**                        | **Description**                                   | **Required** |
|--------------------------------------|------------|---|
| Server URL (i.e., 192.168.0.1:30022) | The server URL of the VCenter.                    | True       |
| Credentials                          | Username and password used to login into the system. | True       |
| insecure                             | Trust any certificate (not secure).               | True       |
| proxy                                | Use system proxy settings.                        | False      |


## Use Cases
- Create and revert to snapshot.
- Get information regarding virtual machines.
- Power-on, power-off, suspend, reboot, clone, create, delete, relocate, resigster and unregister virtual machines.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### vmware-get-vms
***
Returns all virtual machines on a system.


#### Base Command

`vmware-get-vms`
#### Input

| **Argument Name** | **Description**                    | **Required** |
|-------------------|------------------------------------|--------------|
| ip                | List of IPs to filter VMs by.      | Optional     | 
| hostname          | Hostname to filter VMs by.         | Optional     | 
| name              | List of VM names to filter VMs by. | Optional     | 
| uuid              | List of UUIDs to filter VMs by.    | Optional     | 


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
| VMWare.MACAddress | String | MAC address of VM. | 
| VMWare.SnapshotCreateDate | String | Create date of the last snapshot of the VM. | 
| VMWare.SnapshotUUID | String | UUID of the last snapshot of the VM. | 
| VMWare.Deleted | Boolean | If set to true, the VM was deleted. | 


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


#### Human Readable Output

|Name|Template|Path|Guest|UUID|IP|State|HostName|MACAddress|SnapshotCreateDate|SnapshotUUID|Deleted|
|---|---|---|---|---|---|---|---|---|---|---|---|
| VMware_vCenter_7_Integration_Test | false | [datastore1] VMware_vCenter_7_Integration_Test/VMware_vCenter_7_Integration_Test.vmx | Other 3.x or later Linux (64-bit) | 52535506-77f9-ac98-77d3-63bb537ad7d2 | 192.168.1.141 | poweredOn | localhost | 00:0c:29:d4:ca:14 |   |   | false |
| VMware_enhancement_test_vm | false | [datastore1] enhancement_test_3/enhancement_test_3.vmx | Other (32-bit) | 503d608e-92a1-358a-9674-2806326527f5 |   | poweredOn |   |  |   |   | false |
| CentOS7_VMware_Integration_Test | false | [datastore1] CentOS7_VMware_Integration_Test/CentOS7_VMware_Integration_Test.vmx | CentOS 7 (64-bit) | 503dd190-3c64-493b-38ff-37db4e4ba2ab | 192.168.1.142 | poweredOn | localhost.localdomain | 00:50:56:bd:25:c4 | 2021-09-22 12:09:57.989388+00:00 | 423da02f-c7f4-3cda-a33e-1c85c10e048d | false |
| TetsVM1 | false | [datastore1] TetsVM1/TetsVM1.vmx | Other (32-bit) | 503dae8b-afc2-d253-40d5-7e25e05d86f4 |   | poweredOn |   |  |   |   | false |
| enhancement test 2 | false | [datastore1] enhancement test 2/enhancement test 2.vmx | Other (32-bit) | 503d4b98-8a62-c31e-239a-fc9480f55d30 |   | poweredOff |   |  |   |   | false |



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
| VMWare.State | String | VM state \(i.e., poweredOn, poweredOff, suspended, HardRebooted\). | 


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
| memory | Snapshot the virtual machine's memory. Possible values are: true, false. Default is True. | Optional | 
| quiesce | Quiesce guest file system (needs VMWare Tools installed). Possible values are: true, false. Default is False. | Optional | 


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
Gets events of a VM.


#### Base Command

`vmware-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm-uuid | VM UUID of virtual machine to get events of. | Required | 
| event-type | Type of events to get, given in CSV (i.e.,  VmGuestRebootEvent,VmGuestShutdownEvent). Default is VmGuestRebootEvent,VmGuestShutdownEvent,VmPoweredOnEvent,VmPoweredOffEvent,VmSuspendedEvent. | Optional | 
| start-date | Event's start date. | Optional | 
| end-date | Event's end date. | Optional | 
| user | User name. | Optional | 
| limit | Number of events to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWareEvents.id | String | The id of the event. | 
| VMWareEvents.Event | String | Description of the event. | 
| VMWareEvents.CreatedTime | String | Creation time of the event. | 
| VMWareEvents.UserName | Date | The user name of the user who triggered the event. | 


#### Command Example
``` !vmware-get-events vm-uuid=525306-77f9-ac98-77d3-63bb537ad7d2 start-date="2021-12-14T00:00:00" end-date="2021-12-16T00:00:00" user="VSPHERE.TEST"```

#### Context Example
```json
{
  "VMWareEvenet": [
        {
            "CreatedTime": "2021-12-15 09:38:46", 
            "UserName": "VSPHERE.TEST", 
            "Event": "Guest OS reboot for Datacenter", 
            "id": 99973
        }
    ]
}
```

#### Human Readable Output
|CreatedTime|Event| UserName     |id|
|---|---|--------------|---|
| 2021-12-15 09:38:46 | Guest OS reboot for Datacenter | VSPHERE.TEST | 999 |



### vmware-change-nic-state
***
Changes the state of a VM NIC.


#### Base Command

`vmware-change-nic-state`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vm-uuid | VM UUID of virtual machine to change NIC state. | Required | 
| nic-state | New state of the NIC to be changed. Possible values are: connect, disconnect, delete. | Required | 
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

#### Human Readable Output
> Virtual Machine's NIC was disconnected successfully.



### vmware-list-vms-by-tag
***
Lists all virtual storage objects attached to the tag.


#### Base Command

`vmware-list-vms-by-tag`
#### Input

| **Argument Name** | **Description**                        | **Required** |
| --- |----------------------------------------| --- |
| category | The category to which the tag belongs. | Required | 
| tag | The tag to be queried.                 | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWareTag.TagName | String | The tag that was queried. | 
| VMwareTag.Category | String | The category to which the tag belongs. | 
| VMwareTag.VM | String | VM name which the tag attached to. | 


#### Command Example
``` !vmware-list-vms-by-tag category="Test Category" tag=test```

#### Context Example
```json
{
  "VMWareTag": [
        {
            "Category": "Test Category", 
            "VM": "CentOS7_VMware_Integration_Test", 
            "TagName": "test"
        }, 
        {
            "Category": "Test Category", 
            "VM": "enhancement test 2", 
            "TagName": "test"
        }, 
        {
            "Category": "Test Category", 
            "VM": "VMware_enhancement_test_vm", 
            "TagName": "test"
        }
    ]}
```    

#### Human Readable Output
|Category|TagName|VM|
|---|---|---|
| Test Category | test | Integration_Test |
| Test Category | test | enhancement test 2 |
| Test Category | test | VMware_enhancement_test_vm |



### vmware-create-vm
***
Creates a new virtual machine in the current folder and attaches it to the specified resource pool. This operation creates a virtual machine, instead of cloning a virtual machine from an existing one.


#### Base Command

`vmware-create-vm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Display name of the virtual machine. | Required | 
| cpu-num | Number of virtual processors in a virtual machine. | Required | 
| cpu-allocation | Resource limits for CPU. | Required | 
| memory | Resource limits for memory. | Required | 
| virtual-memory | Size of a virtual machine's memory, in MB. | Required | 
| guestld | Short guest operating system identifier. | Optional | 
| guest-os-familiy | description. | Required | 
| guest-os-version | description.  | Required | 
| host | The target host on which the virtual machine will run.  | Required | 
| folder | The target folder in which the virtual machine will be located.  | Required | 
| pool | The resource pool to which the virtual machine will be attached.  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWare.vName | String | VM name. | 
| VMWare.Template | bool | true if template, else false. | 
| VMWare.Path | String | Path to VM. | 
| VMWare.Guest | String | Guest full name. | 
| VMWare.UUID | String | VM instance UUID. | 
| VMWare.IP | String | VM IP address. | 
| VMWare.State | String | VM state \(i.e., poweredOn, poweredOff, suspended, HardRebooted\). | 
| VMWare.HostName | String | Host name of VM. | 
| VMWare.MACAddress | String | MAC address of VM. | 
| VMWare.SnapshotCreateDate | String | Create date of the last snapshot of the VM. | 
| VMWare.SnapshotUUID | String | UUID of the last snapshot of the VM. | 
| VMWare.Deleted | Boolean | If set to true, the VM was deleted. | 


#### Command Example
```!vmware-create-vm cpu-allocation=1 cpu-num=1 guest-os-familiy=Windows guest-os-version="Microsoft Windows Server 2019 (64-bit)" host=11.11.1.111 memory=32 name="test_vm_ui" virtual-memory=32 folder="vm"```

#### Context Example
```json
{
  "VMWare": [
        {
           "MACAddress": "", 
            "Name": "test_vm_ui", 
            "Deleted": false, 
            "IP": " ", 
            "HostName": " ", 
            "SnapshotCreateDate": "", 
            "UUID": "503d-11bc-834e-51a8-51b19a1b6924", 
            "State": "poweredOff", 
            "Snapshot": " ", 
            "Template": false, 
            "SnapshotUUID": "", 
            "Path": "[datastore1] test_vm_ui/test_vm_ui.vmx", 
            "Guest": "Other (32-bit)"
        }
    ]
}
```

#### Human Readable Output
|Name|Template|Path|Guest|UUID|State|Deleted|
|---|---|---|---|---|---|---|
| test_vm_ui | false | [datastore1] test_vm_ui/test_vm_ui.vmx | Other (32-bit) | 503d9bc9-5c5a-603e-65d9-0fea7b29b9a7 | poweredOff | false |



### vmware-clone-vm
***
Creates a clone of this virtual machine. If the virtual machine is used as a template, this method corresponds to the deploy command.


#### Base Command

`vmware-clone-vm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the VM to clone.  | Required | 
| name | The name of the new virtual machine.  | Required | 
| folder | The location of the new virtual machine.  | Required | 
| template | Specifies whether or not the new virtual machine should be marked as a template.  | Optional | 
| powerOn | Specifies whether or not the new VirtualMachine should be powered on after creation. Possible values are: true, false. Default is False. | Required | 
| datastore | The datastore where the virtual machine should be located.  | Optional | 
| host | The target host for the virtual machine.  | Optional | 
| pool | The resource pool to which this virtual machine should be attached.  | Optional | 


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
| VMWare.MACAddress | String | MAC address of VM. | 
| VMWare.SnapshotCreateDate | String | Create date of the last snapshot of the VM. | 
| VMWare.SnapshotUUID | String | UUID of the last snapshot of the VM. | 
| VMWare.Deleted | Boolean | If set to true, the VM was deleted. | 


#### Command Example
```!vmware-clone-vm folder=vm name=cloned_vm powerOn=false uuid=603e-65d9-0fea7b29b9a7```

#### Context Example
```json
{
  "VMWare": [
        {
            "MACAddress": "", 
            "Name": "cloned_vm", 
            "Deleted": false, 
            "IP": " ", 
            "HostName": " ", 
            "SnapshotCreateDate": "", 
            "UUID": "e5aa-8fe8-a3faf1191395", 
            "State": "poweredOff", 
            "Template": false, 
            "SnapshotUUID": "", 
            "Path": "[datastore1] cloned_vm/cloned_vm.vmx", 
            "Guest": "Other (32-bit)"
        }
    ]
}
```

#### Human Readable Output
|Name|Template|Path|Guest|UUID|State| Deleted |
|---|---|---|---|---|---|---------|
| cloned_vm | false | [datastore1] cloned_vm/cloned_vm.vmx | Other (32-bit) | e5aa-8fe8-a3faf1191395 | poweredOff | false   |


### vmware-relocate-vm
***
Relocates a virtual machine to the location specified.


#### Base Command

`vmware-relocate-vm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| datastore | The datastore where the virtual machine should be located. If not specified, the current datastore is used.  | Optional | 
| folder | The folder where the virtual machine should be located.  | Required | 
| host | The target host for the virtual machine.  | Optional | 
| pool | The resource pool to which this virtual machine should be attached.  | Optional | 
| service | The service endpoint of vCenter where the virtual machine should be located. If not specified, the current vCenter service is used.  | Optional | 
| profile | Storage profile requirement for Virtual Machine's home directory.  | Optional | 
| priority | The task priorityץ. Possible values are: defaultPriority, highPriority, lowPriority. | Required | 
| uuid | The UUID of the VM to relocate.  | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!vmware-relocate-vm folder=enhancement_check priority=defaultPriority uuid=e5aa-8fe8-a3faf1191395```

#### Human Readable Output
>Virtual Machine was relocated successfully.



### vmware-delete-vm
***
Destroys this object, deleting its contents and removing it from its parent folder (if any).


#### Base Command

`vmware-delete-vm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the VM to delete.  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VMWare.UUID | String | VM instance UUID. | 
| VMWare.Deleted | String | If set to true, the VM was deleted. | 


#### Command Example
```!vmware-delete-vm uuid=503d537f-a8d0-e5aa-8fe8-a3faf1191395```

#### Human Readable Output
>Virtual Machine was deleted successfully.


### vmware-register-vm
***
Adds an existing virtual machine to the folder.


#### Base Command

`vmware-register-vm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | A datastore path to the virtual machine.  | Required | 
| name | The name to be assigned to the virtual machine.  | Required | 
| host | The target host on which the virtual machine will run.  | Required | 
| asTemplate | Flag to specify whether or not the virtual machine should be marked as a template. Possible values are: true, false. Default is False. | Optional | 
| folder | Folder to register the VM to.  | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!vmware-register-vm path="[datastore1] test_vm_ui/test_vm_ui.vmx" folder=vm host=192.168.1.140 name=rgistered_vm asTemplate=false```

#### Human Readable Output
>Virtual Machine was registered successfully.

### vmware-unregister-vm
***
emoves this virtual machine from the inventory without removing any of the virtual machine's files on disk.


#### Base Command

`vmware-unregister-vm`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The UUID of the VM to remove.  | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!vmware-unregister-vm uuid=503d9bc9-5c5a-603e-65d9-0fea7b29b9a7```

#### Human Readable Output
>Virtual Machine was unregistered successfully.
