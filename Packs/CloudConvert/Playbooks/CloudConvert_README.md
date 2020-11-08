Use this playbook in order to conduct a file conversion using CloudConvert

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* CloudConvert


### Commands
* CloudConvert-export
* CloudConvert-import
* CloudConvert-convert

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| url | This is the url of the imported file |  | Optional |
| entry_id | This is the entry id of the imported file |  | Optional |
| output_format | This is the desired output format<br/> |  | Required |
| export_via | The method for exporting the resulted file, url or war_room_entry<br/> |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![CloudConvert](https://cloudconvert.com/images/logo_flat_110_borderless.png)