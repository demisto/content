This script prevents duplication of existing incidents, and closes an incident once the work on its violation is over.

Run as the action of the `GIB DRP Rule All Types` pre-processing rule, it takes the incoming Group-IB
DRP violation and, for every incident that already carries the same **GIB DRP ID**:

* copies the violation's current fields onto it with a single `setIncident` call,
* closes it as *Resolved* when the violation's status is `resolved` (taken down; older API versions report
  it as `solved`) or `legal` (handed to legal), and as *False Positive* when DRP found it false
  (`false_status`) or the customer rejected it (approve state `rejected`) - DRP does nothing more with
  either, so nothing later would close the incident; approving does not close, the take-down is still ahead, and
* expires the indicator created from the violation URI with that close, when **GIB DRP Expire Indicator On
  Close** is set on the incoming or the existing incident.

The fetch passes every change of a violation it created an incident for through to this rule, whatever
the instance's status and approval filters say, so the close arrives here as an ordinary update.

The incoming incident is then dropped, so an updated violation never becomes a second incident. It is
kept only when no existing incident matched, or when every update failed, so a new violation state is
never silently lost.

The search deliberately covers **closed** incidents too, and never writes `status` or `severity` back:
a violation whose incident was already closed is updated in place instead of coming back as a new
incident, a closed incident is not reopened by the update, and the severity set by the instance that
created the incident - or raised by an analyst since - survives an update that arrives through another
instance.

The rule that runs this script must carry the script's `scriptID`, not only its `scriptName`. Cortex
XSOAR 8 executes a script rule only when the id is present; with the name alone the rule matches the
incoming incident and then lets it through untouched, so every re-fetch of a violation becomes a new
incident.

The search sees an incident only once Cortex XSOAR has created it. Two instances whose filters overlap
and that start fetching at the same moment can therefore each create an incident for the same
violation before either can see the other's; every later update is folded into one of the two, but
the pair stays. Give overlapping instances non-overlapping filters, or enable them a fetch interval
apart.

Because the search runs against the whole incident table, this is the layer that folds updates
across instances: the integration's known-violations cache lives in each instance's own fetch state
and only decides whether a violation is new to that instance.

## Permissions

---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/Cortex-XSOAR-Administrator-Guide/Automations)

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | preProcessing |
| Cortex XSOAR Version | 6.0.0 |

## Inputs

---
There are no inputs for this script.

## Outputs

---
There are no outputs for this script.
