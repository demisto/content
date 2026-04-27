This script is a wrapper for the 'pano-os-platform-get-available-software' command, adding options to return only images newer than is currently installed to minimize amount of context data generated.

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
* pan-os-platform-get-available-software

## Used In

---
This script is used in the following playbooks and scripts.

* PAN-OS - Firewall Upgrade Readiness Checks

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| device_filter_string | The string by which to filter the results to only show specific hostnames or serial numbers. |
| target | The target number of the firewall. Used only on a Panorama instance. |
| panos_instance_name | The instance name of the PAN-OS Integration to use. Specify only one instance. |
| newer_images_only | Whether to return only images newer than currently installed. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PANOS.SoftwareVersions.Summary.hostid | The host ID. | String |
| PANOS.SoftwareVersions.Summary.version | The software version in Major.Minor.Maint format. | String |
| PANOS.SoftwareVersions.Summary.filename | The software version filename. | String |
| PANOS.SoftwareVersions.Summary.size | The size of the software in MB. | String |
| PANOS.SoftwareVersions.Summary.size_kb | The size of the software in KB. | String |
| PANOS.SoftwareVersions.Summary.release_notes | The link to version release notes in the Palo Alto Networks knowledge base. | String |
| PANOS.SoftwareVersions.Summary.downloaded | True if the software version is present on the system. | Boolean |
| PANOS.SoftwareVersions.Summary.current | True if this is the currently installed software on the system. | Boolean |
| PANOS.SoftwareVersions.Summary.latest | True if this is the most recently released software for this platform. | Boolean |
| PANOS.SoftwareVersions.Summary.uploaded | True if the software version has been uploaded to the system. | Boolean |
