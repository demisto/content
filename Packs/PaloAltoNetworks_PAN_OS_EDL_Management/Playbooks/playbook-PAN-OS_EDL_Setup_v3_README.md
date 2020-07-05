Configures an external dynamic list in PAN-OS.
In the event that the file exists on the web server, it syncs the file to Cortex XSOAR. Then it creates an EDL object and a matching rule.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS - Create Or Edit EDL Rule
* PAN-OS Commit Configuration

### Integrations
* Palo Alto Networks PAN-OS EDL Management

### Scripts
* AreValuesEqual

### Commands
* pan-os-edl-get-external-file-metadata
* panorama-get-edl
* pan-os-edl-update
* panorama-create-edl
* pan-os-edl-update-from-external-file
* panorama

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| list-name | The name of the list that stores the IOCs.
The name of the file on the web server. This file name is the same as the name of the list with the extension &quot;.txt&quot; added. |  |  | Required |
| ioc-type | The type of the IOCs that the list stores. Can be &quot;ip&quot;, &quot;url&quot;, or &quot;domain&quot;. |  |  | Required |
| list-items | comma separated values |  |  | Required |
| action-type | The action that is defined in the rule:
allow/deny/drop | drop |  | Required |
| auto-commit | Whether to commit the configuration automatically. | False |  | Optional |
| log-forwarding-object-name | The server address to which to forward logs. |  |  | Optional |
| web-server-ip | The IP address of the web server on which the files are stored. The web server IP address is configured in the integration instance. |  |  | Required |
| pre-post-rulebase | Either pre\-rulebase or post\-rulebase,  according to the rule structure. | pre-rulebase |  | Required |
| rule-position | The position of the rule in the ruleset. Valid values are:
  \* top
  \* bottom
  \* before
  \* after

The default position is &\#x27;top&\#x27; | bottom |  | Optional |
| relative-rule-name | If the rule\-position that is chosen is before or after, specify the rule name to which it is related. |  |  | Optional |
| inbound-or-outbound-rule | Determines if the rule is inbound or outbound. | outbound |  | Optional |
| rule-name | The name of the rule to update, or the name of the rule that will be created. |  |  | Optional |
| device-group | The device group to work on. Exists only in panorama\! |  |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Panorama.EDL.Name | Name of theEDL. | unknown |
| Panorama.Commit.Warnings | Commit Warnings | unknown |
| Panorama.Push.Warnings | Push  warnings | unknown |

## Playbook Image
---
![PAN-OS_EDL_Setup_v3](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/PAN-OS_EDL_Setup_v3.png)
