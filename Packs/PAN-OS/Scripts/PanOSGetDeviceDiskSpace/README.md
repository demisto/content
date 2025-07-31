This script fetches disk space info from the target device and returns all information or a subset as specified in command arguments.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* Panorama
* pan-os

## Used In

---
This script is used in the following playbooks and scripts.

* PAN-OS - Firewall Upgrade Readiness Checks

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| target | The serial number of the device to get disk space info from. |
| panos_instance_name | The instance name of the PAN-OS Integration to use. Specify only one instance. |
| disk_space_units |  |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PANOS.DiskSpace.hostid | Serial number of the device. | string |
| PANOS.DiskSpace.FileSystems.FileSystem | The device file system. | string |
| PANOS.DiskSpace.FileSystems.Size | The size of the file system. | number |
| PANOS.DiskSpace.FileSystems.Used | The amount of used space on the file system. | number |
| PANOS.DiskSpace.FileSystems.Avail | The amount of free space on the file system. | number |
| PANOS.DiskSpace.FileSystems.Used% | The percentage of total size used. | string |
| PANOS.DiskSpace.FileSystems.MountedOn | The path where the file system is mounted. | string |
| PANOS.DiskSpace.FileSystems.Units | The unit used to represent disk space values. | string |
