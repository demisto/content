The backbone of highly effective managed detection and response (MDR) is the Zero Trust Analytics Platform (ZTAP) utilized by elite security analysts to resolve every alert.

## What does this pack do?
This pack enables you to:
- Sync and update escalated ZTAP alerts.
- Respond to Critical Start analysts directly from the XSOAR platform.

This pack includes the integration, the **ZTAP Alert** incident type, and an incident layout that displays information.

## Custom Classifier
If using a custom classifier the following fields are required for bidirectional sync

| **Input Field** | **Output Field** |
| --- | --- |
| xsoar\_mirror\_id | dbotMirrorId |
| xsoar\_mirror\_direction | dbotMirrorDirection |
| xsoar\_mirror\_instance | dbotMirrorInstance |
| xsoar\_mirror\_last\_sync | dbotMirrorLastSync |
| xsoar\_mirror\_tags | dbotMirrorTags |

## Custom Playbook
If using a custom playbook comments from before the alert was escalated will not be fetched.
In order to fetch them call `ztap-get-alert-entries` during initial processing.
Note that the escalation comment will be fetched during this step.
