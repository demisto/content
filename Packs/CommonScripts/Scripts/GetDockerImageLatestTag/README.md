Gets docker image latest tag. Script simulates the docker pull flow but doesn't actually pull the image. Returns an entry with the docker image latest tag if all is good, otherwise will return an error.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| docker_image | Docker image full name with version: For example: demisto/python |
| use_system_proxy | Use system proxy settings |
| trust_any_certificate | Trust any certificate \(not secure\) |

## Outputs
---
There are no outputs for this script.


## Script Examples
### Example command
```!GetDockerImageLatestTag docker_image=demisto/python3```


### Human Readable Output

>3.10.4.29342
