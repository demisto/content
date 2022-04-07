This playbook sumbmits a request to SentinelOne to fetch a file from an endpoint

Input:
* Hostname (Default: ${Endpoint.Hostname})
* Path
* Password (Default: ${PossibleyInfected)(*&7890})
* Timeout (Default: 10)

### Fetch File Process Notes
  The SentinelOne API for downloading files is aynchronous. At the time this was written there is no way to correlate a request for a file to the file entry that shows up in the activities feed. So, if two requests were submitted simultaneously to download two different files from the same host, there is no way to determine which file entry in the activity entry corresponds to which request.  So this playbook *assumes* that the most recent file upload from a given agent ID that occurs *after* we submit a file fetch request is our request. It uses locks to ensure that this is the case *if* the only source of file upload request is this XSOAR playbook (or another one that uses the same lock name). If analysts on XSOAR, other playbooks, or other systems are also submitting file fetches, this logic will fail.

  If a file does not exist on an endpoint, the fetch-files API will still return success, and a zip file of the upload will still be uploaded to SentinelOne. However, the zip contents will be empty, except for a metadata.json file

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts

### Sub-playbooks
* SentinelOne - Check for New File Upload Activity

### Integrations
* SentinelOne v2

### Scripts
* Print
* Exists

### Commands
* so-agents-query
* so-get-agent-processes

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** |  **Required** |
| --- | --- | --- | --- |  
| Hostname | The hostname of the device to run on. | ${Endpoint.Hostname} | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
## Playbook Image
---
This image section will be updated when the image it references has been committed to git
