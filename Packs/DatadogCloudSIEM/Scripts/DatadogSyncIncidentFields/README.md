This script synchronizes Datadog Cloud SIEM security signal data with XSOAR incident fields. It retrieves the latest security signal information from Datadog and updates the incident with current field values, owner information, and closure state.

## Dependencies

---
This script uses the following commands and scripts.

### Commands

* datadog-signal-get
* setIncident
* setOwner
* closeInvestigation

### Scripts

This script does not use any scripts.

## Inputs

---
This script does not take any inputs. It operates on the current incident context and requires the incident to have a Datadog Security Signal ID in its custom fields.

## Outputs

---
There are no context outputs for this script. The script updates the incident fields directly.

## Use Cases

---
* Synchronize incident fields with the latest Datadog security signal data
* Update incident owner based on Datadog signal assignee
* Automatically close XSOAR incidents when the corresponding Datadog security signal is archived
