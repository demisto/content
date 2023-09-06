Deprecated. Use `Cloud IAM User Access Investigation` instead. Respond to Cortex XDR Cloud alerts where an AWS IAM user`s access key is used suspiciously to access the cloud environment. 
The following alerts are supported for AWS environments.
- Penetration testing tool attempt
- Penetration testing tool activity
- Suspicious API call from a Tor exit node
 This is a beta playbook, which lets you implement and test pre-release software. Although AWS is supported, we are working towards multi-cloud support. As the playbook is beta, it might contain bugs. Updates to the playbook during the beta phase might include non-backward compatible features. We encourage your feedback on the quality and usability of the content to help us identify and fix issues, so we can continually improve the content.


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Block Indicators - Generic v2

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

* aws-iam-get-user-login-profile
* aws-iam-delete-login-profile
* setIndicators
* aws-iam-update-access-key

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| userName | The name of the user whose key you want to update. |  | Optional |
| accessKeyId | The access key ID of the secret access key you want to update. |  | Optional |
| AutoDeleteProfile | Whether to automatically delete the user login profile, if it exists \(True/False\). |  | Optional |
| IP | The IP address to block using the playbook. |  | Optional |
| AutoBlockIP | Whether to initiate the block IP playbook automatically \(True/False\). | False | Optional |
| IndicatorTag | The Tag name for bad reputation IP addresses investigated in the incident.<br/>Use it when the EDL service is configured to add indicators to block in PANW PAN-OS.<br/>If indicator verdict \(Malicious/Bad\) is used to add indicators to Cortex XSIAM EDL, you don't need to use the tag. Indicators are set as malicious, automatically in the incident. |  | Optional |
| DAG | Determines whether Palo Alto Networks Panorama or Firewall Dynamic Address Groups are used.<br/>Specify the Dynamic Address Group tag name for IP handling. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![AWS IAM User Access Investigation - Remediation](../doc_files/AWS_IAM_User_Access_Investigation_-_Remediation.png)
