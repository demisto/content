This playbook automates the download and installation of the following Dynamic Update types on Palo Alto firewalls:

- App/Threat
- Anti-Virus
- WildFire
- GlobalProtect Clientless VPN

NOTE: This playbook is intended for use with a single PAN-OS Integration Instance.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

- Panorama

### Scripts

- PrintErrorEntry
- Set
- SetAndHandleEmpty

### Commands

- pan-os-download-latest-antivirus-update
- pan-os-download-latest-content-update
- pan-os-download-latest-gp-update
- pan-os-download-latest-wildfire-update
- pan-os-install-latest-antivirus-update
- pan-os-install-latest-content-update
- pan-os-install-latest-gp-update
- pan-os-install-latest-wildfire-update
- pan-os-platform-get-system-info

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DynamicUpdates | A dictionary containing details of the Dynamic Update type\(s\) downloaded and installed, including their version number and associated job IDs. | unknown |

## Playbook Image

---

![PAN-OS - Download and Install Dynamic Content Updates](../doc_files/PAN-OS_-_Download_and_Install_Dynamic_Content_Updates.png)
