## [Unreleased]
-


## [20.3.4] - 2020-03-30
#### New Playbook
This playbook remediates Prisma Cloud GCP Compute Engine alerts.  It calls sub-playbooks that perform the actual remediation steps.

Remediation:
 - GCP VM instances have serial port access enabled
 - GCP VM instances have block project-wide SSH keys feature disabled
 - GCP VM instances without any custom metadata information
