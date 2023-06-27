This is a pre-processing script that is used to create the attachments of incoming incidents in an existing incident, then drop the incoming incident.
It should be configured as a pre-processing rule, and the logic for finding the right incident should be added to the code manually.
The automation collects the paths and names of the attachments of the incoming incident and passes it to the "CreateFileFromPathObject" automation that is being executed on the existing incident.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | preProcessing |

## Inputs
---
There are no inputs for this script.

## Outputs
---
There are no outputs for this script.
