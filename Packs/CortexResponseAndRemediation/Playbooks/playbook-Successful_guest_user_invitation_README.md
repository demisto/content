**This playbook addresses the following alerts**:
- Rare successful guest invitation in the organization

**Playbook Stages**:

**Triage**:
- Gather initial information about the invited user and associated alerts.

**Investigation**:
- **Check IOCs Reputation**:
  - Analyze the reputation of IP addresses, email addresses, and domains related to the incident.
- **Check for Azure Alerts**:
  - Retrieve user Principal Name (UPN).
  - Extract recent Azure security alerts for the inviting user.
- **Check if User is Risky**:
  - Assess the risk score of the inviting user based on Core and Azure risk indicators.
  - Investigate reasons behind any identified risks, including recent detections.

**Containment**:
- Provide a manual task for an analyst to review the findings and decide the next steps.
- Possible actions:
  - Disable the invited user.
  - Disable the inviting user.
  - Disable both users.
  - Take no action.
- If users are disabled, revoke their active sessions to ensure immediate containment.

**Requirements**:
For the best results, it's recommended to ensure these integrations are configured and working:
- `Cortex Core - Investigation and Response` for Core user risk evaluation.
- `Azure Risky Users` for retrieving user risk scores.
- `Microsoft 365 Defender` for advanced hunting queries and Azure security alerts.
- `Microsoft Graph User` for disabling accounts and revoking sessions.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CoreIOCs
* CortexCoreIR
* CortexCoreXQLQueryEngine

### Scripts

* GetTime
* SetAndHandleEmpty

### Commands

* azure-risky-users-list
* azure-risky-users-risk-detections-list
* closeInvestigation
* core-get-cloud-original-alerts
* core-list-risky-users
* domain
* email
* ip
* microsoft-365-defender-advanced-hunting
* msgraph-user-account-disable
* msgraph-user-session-revoke

## Playbook Inputs

---
There are no inputs for this playbook.

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Successful_guest user invitation](../doc_files/Successful_guest_user_invitation.png)
