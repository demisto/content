Identify whether the service is a "development" server. Development servers have no external users and run no production workflows. These servers might be named "dev", but they might also be named "qa", "pre-production", "user acceptance testing", or use other non-production terms. This automation uses both public data visible to anyone (`active_classifications` as derived by Xpanse ASM) as well as checking internal data for AI-learned indicators of development systems (`asm_tags` as derived from integrations with non-public systems).

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| asm_tags | Array of key-value objects. Each object within the array must contain the keys "Key" and "Value" to be considered. The values associated with those keys can be arbitrary. Example: \[\{"Key": "env", "Value": "dev"\}, \{"Key": "Name", "Value": "ssh-ec2-machine-name"\}\] |
| active_classifications | Array of strings representing the Xpanse ASM "active classifications" for the service. Example: \["RdpServer", "SelfSignedCertificate"\] |

## Outputs
---
There are no outputs for this script.
