Enrich Armis alerts with the devices in the context details.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Armis

### Scripts

This playbook does not use any scripts.

### Commands

armis-search-devices

## Playbook Inputs

---

| **Name**        | **Description**                                      | **Default Value**         | **Required** |
| --------------- | ---------------------------------------------------- | ------------------------- | ------------ |
| Armis_Device_ID | Get the device ID that is associated with the alert. | ${incident.armisdeviceid} | Required     |

## Playbook Outputs

---

| **Path**                      | **Description**                     | **Type** |
| ----------------------------- | ----------------------------------- | -------- |
| Device ID                     | Device ID.                          | string   |
| Armis.SearchDevices.name      | Device name.                        | string   |
| Armis.SearchDevices.riskLevel | Device risk level defined by Armis. | number   |
| Armis.SearchDevices.ipaddress | IPv4 address.                       | string   |
| Armis.SearchDevices.site      | Site name                           | string   |
| Armis.SearchDevices.tags      | Tags.                               | string   |

## Playbook Image

---

![Armis Alert Enrichment](../doc_files/Armis_Device_Enrichment.png)
