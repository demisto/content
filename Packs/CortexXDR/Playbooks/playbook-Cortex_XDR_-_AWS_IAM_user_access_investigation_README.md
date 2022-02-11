Investigate and respond to Cortex XDR Cloud alerts where an AWS IAM user`s access key is used suspiciously to access the cloud environment. 
The following alerts are supported for AWS environments.
- Penetration testing tool attempt
- Penetration testing tool activity
- Suspicious API call from a Tor exit node

This is a beta playbook, which lets you implement and test pre-release software. At the moment we support AWS but are working towards multi-cloud support. Since the playbook is beta, it might contain bugs. Updates to the playbook during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the content to help us identify issues, fix them, and continually improve.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* AWS IAM - User enrichment
* Block IP - Generic v2

### Integrations
* XQLQueryingEngine
* XDR_iocs
* CortexXDRIR

### Scripts
* Set

### Commands
* ip
* aws-iam-update-access-key
* xdr-get-cloud-original-alerts
* xdr-xql-generic-query
* xdr-get-incident-extra-data
* aws-iam-delete-login-profile
* setIncident
* setIndicators

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IndicatorTag | Tag name for bad reputation IP addresses investigated in the incident.<br/>Use it when the EDL service is configured to add indicators to block in PANW PAN-OS.<br/>If indicator verdict\(Malicious/Bad\) is used to add indicators to XSOAR EDL you don't need to use the tag. Indicators will be set as malicious automatically in the incident.<br/> |  | Optional |
| DAG | This input determines whether Palo Alto Networks Panorama or Firewall Dynamic Address Groups are used.<br/>Specify the Dynamic Address Group tag name for IP handling. |  | Optional |
| AutoBlockIP | True/False to initiate Block IP playbook automatically.  | False | Optional |
| AutoDeleteProfile | True/False to automatically delete the user login profile if it exists.  | False | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - AWS IAM user access investigation](https://raw.githubusercontent.com/demisto/content/d441425e7e4655adb198c7722887825b3cfbf997/Packs/CortexXDR/doc_files/Cortex_XDR_-_AWS_IAM_user_access_investigation.png)
