## Containment Plan - Block Indicators

This playbook is a sub-playbook within the containment plan playbook.

### Indicator Blocking

The playbook block indicators by two methods:

1. It adds the malicious hashes into the XSIAM hash block list
2. It utilizes the sub-playbook "Block Indicators - Generic v3"

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Block Indicators - Generic v3

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

* setParentIncidentContext
* core-blocklist-files

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| BlockIndicators | Set to 'True' to block the indicators. | True | Optional |
| UserVerification | Possible values: True/False.<br/>Whether to provide user verification for blocking those IPs. <br/><br/>False - No prompt will be displayed to the user.<br/>True - The server will ask the user for blocking verification and will display the blocking list. | False | Optional |
| AutoBlockIndicators | Possible values: True/False.  Default: True.<br/>Should the given indicators be automatically blocked, or should the user be given the option to choose?<br/><br/>If set to False - no prompt will appear, and all provided indicators will be blocked automatically.<br/>If set to True - the user will be prompted to select which indicators to block. | True | Optional |
| FileHash | The file hash to block. |  | Optional |
| IP | The IP indicators. |  | Optional |
| Domain | The domain indicators. |  | Optional |
| URL | The URL indicator. |  | Optional |
| Username | The username to disable. |  | Optional |
| FilePath | The path of the file to block. |  | Optional |
| AutoContainment | Whether to execute containment plan automatically. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.blocklist.added_hashes | The file Hash that was added to the blocklist. | unknown |

## Playbook Image

---

![Containment Plan - Block Indicators](../doc_files/Containment_Plan_-_Block_Indicators.png)
