Playbook for the Cֹonfiguration Setup incident type.

### Integrations
* Google Cloud Storage
* GitLab
* AWS - S3

### Scripts
* JobCreator
* CustomPackInstaller
* ContentPackInstaller
* http
* ConfigurationSetup
* ListCreator

### Commands
* gitlab-raw-file-get
* aws-s3-download-file
* GitHub-get-file-content
* setIncident
* closeInvestigation
* gcs-download-file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| InstanceName | Core REST API instance name to use. |  | Optional |
| GitlabInstanceName | Gitlab instance name to use. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.
