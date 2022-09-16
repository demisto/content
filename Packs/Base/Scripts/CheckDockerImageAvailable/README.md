Check if a docker image is available for performing docker pull. Script simulates the docker pull flow but doesn't actually pull the image. Returns an entry with 'ok' if all is good otherwise will return an error.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | Docker image full name with version: For example: demisto/python:2.7.15.155 |
| use_system_proxy | Use system proxy settings |
| trust_any_certificate | Trust any certificate \(not secure\) |

## Outputs
---
There are no outputs for this script.
