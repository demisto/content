**This playbook addresses the following alerts**:
- SSO authentication attempt with suspicious characteristics.
- Successful SSO authentication with suspicious characteristics.

**Playbook Stages**:

**Triage**:
- Collect initial information about the user and the SSO authentication event.
- Validate whether the authentication proxy is linked to iCloud Relay.

**Investigation**:
- **Check IOCs Reputation**:
  - Analyze the reputation of IP addresses associated with the alert.
- **Search Related Alerts**:
  - Look for alerts related to the same user within the system to identify suspicious activity trends.
- **Check If User Is Risky**:
  - Retrieve the user's risk score and evaluate high-risk indicators for suspicious activities.
- **Check User Agent**:
  - Identify suspicious user agents used during the authentication attempts.
- **Check Okta Logs**:
  - Retrieve Okta authentication logs for failed login attempts and suspicious authentication activities within the last day.

**Containment**:
- **Automatic Actions**:
  - Clear user sessions if any suspicious evidence is found during the investigation.
- **Analyst Review**:
  - Provide an analyst with findings for review and determine the appropriate action:
    - No action required.
    - Suspend the user in Okta.
  - If the analyst chooses to suspend the user, their active sessions are cleared in Okta.

**Requirements**:
For the best results, it's recommended to ensure these integrations are configured and working:
- **Core** integration for user risk evaluation and suspicious activity checks.
- **Okta v2** integration for analyzing authentication logs, clearing sessions, and user suspension.
- Any IP reputation integration that supports the `!ip` command for checking IP address reputation.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Containment Plan - Clear User Sessions

### Integrations

* Cortex Core - IR
* Okta v2

### Scripts

* GetTime
* SearchAlertsV2
* SetAndHandleEmpty

### Commands

* closeInvestigation
* core-get-cloud-original-alerts
* core-list-risky-users
* ip
* okta-get-failed-logins
* okta-get-logs
* okta-suspend-user

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![SSO Authentication With Suspicious Characteristics](../doc_files/SSO_Authentication_With_Suspicious_Characteristics.png)
