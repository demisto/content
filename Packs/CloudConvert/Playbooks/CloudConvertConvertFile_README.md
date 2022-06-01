Use this playbook to convert a file to the required format using CloudConvert.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* CloudConvert


### Commands
* cloudconvert-download
* cloudconvert-upload
* cloudconvert-convert
* cloudconvert-check-status

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| url | The URL of the uploaded file. |  | Optional |
| entry_id | The entry ID of the uploaded file. |  | Optional |
| output_format | The required output format.|  | Required |
| download_via | The method for downloading the converted file - URL or war_room_entry. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![CloudConvert](https://user-images.githubusercontent.com/72340690/100620498-2ad0cc00-3327-11eb-8959-3ec0726dbced.png)

