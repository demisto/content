# XSUP-74179 - Jira Context

- **Key:** XSUP-74179
- **Summary:** Cortex XDR Alerts Handling v2 fails to generate a missing Alert ID after switching from `xdr-get-incident-extra-data` to `xdr-case-list`.
- **Type:** XSOAR-XSIAM Content | **Priority:** P3 | **Status:** New
- **Reporter:** Kevin Francis (kevtan) | **Assignee:** Jacob Levy (jlevy)
- **Labels:** FS, Focused_Services
- **Created:** 2026-08-03 | **Updated:** 2026-08-04
- **Salesforce case:** SF-04134352 | **Customer:** Southern Company
- **Environment:** Cortex XSOAR 8.14.0-8912722 (SaaS), Cortex XDR content pack 6.3.31, NAM (US), tenant `xdr-us-1006637827566`

## Reporter-described symptom

The OOTB "Cortex XDR Incident Handling V3" playbook calls the deprecated command
`xdr-get-incident-extra-data` at task 54. When the customer manually substituted the
documented replacement `xdr-case-list extra_data=true`, the downstream "Cortex XDR Alerts
Handling v2" sub-playbook (task 78) failed with a **missing Alert ID** error, so the
customer reverted to the deprecated command.

## TAC findings (verified against source)

- `xdr-get-incident-extra-data` documents `PaloAltoNetworksXDR.Incident.alerts.alert_id`
  (`CortexXDRIR.yml` line 422).
- `xdr-case-list` documents `PaloAltoNetworksXDR.Case.Issues.issue_id`
  (`CortexXDRIR.yml` lines 4362-4365).
- Correct argument names are `case_id` and `extra_data` (not `id` / `extra-data` as quoted
  in XSUP-68645).
- `extra_data` was added in commit `c82ac68`, released in content pack 6.3.26 (CRTX-251016).

## Engineering asks in the ticket

1. Confirm whether the OOTB playbooks were updated to the replacement command.
2. If not, update task 78's `alert_id` input mapping.
3. Audit the rest of the Incident Handling V3 workflow for other implicit dependencies on
   the deprecated command's output shape.
4. Advise the target content-pack release.

## Attachments

Two customer screenshots are referenced in the description (task 54 and task 78 views).
The Jira REST attachment listing was not retrievable in this environment (no attachment
download tool available in this session). Both screenshots are fully described in the
ticket text and were independently confirmed against the repo source, so they are not
blocking.

## Workaround

Customer stays on the deprecated command, which still functions. Degraded, not a hard
block - until the deprecated command is removed.
