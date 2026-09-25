Approves or rejects a Group-IB DRP violation.

This sits behind the **Approve Violation** and **Reject Violation** buttons on the
**GIB DRP Violation** layout, and behind the approve/reject tasks of the
**Group-IB Digital Risk Protection - Violation Incident Postprocessing** playbook.

The decision goes to the instance that fetched the incident. Without `using` Cortex XSOAR runs
`gibdrp-change-violation-status` on every enabled instance of the integration, and with several
instances (one per brand, section or severity) the instances that do not own the violation answer with
an error and the button fails. The `using` argument wins; then the incident's `sourceInstance`, when
that instance is still active; then the only active instance.

Approving does **not** close the incident by default. It settles the customer's half of the case; the
take-down continues in Group-IB DRP afterwards, and the incident is closed later by the
`GIBDRPIncidentUpdate` pre-processing rule, once DRP reports the violation as `resolved` (taken down;
`solved` on older API versions) or `legal` (handed to legal). With **Close the incident when a
violation is approved** enabled on the instance, `gibdrp-change-violation-status` answers with
`closeIncident: true` and the automation closes the incident as *Resolved* at once.

Rejecting always closes the incident as *False Positive*: DRP does nothing more with a rejected
violation, so nothing later would close the incident. When **GIB DRP Expire Indicator On Close** is set
on the incident (from the instance's **Expire the indicator when the violation is closed**), the
indicator created from the violation is expired as well.

On success it writes the new approve state (`approved` or `rejected`) onto the incident. Both layout
buttons are displayed only while **GIB DRP Approve State** is `under_review`, so recording the
decision is what stops them from offering a decision that has already been made. If that write fails
the automation still reports success - the decision already reached DRP and cannot be taken back -
and the field catches up on the next fetch.

A violation can only be changed while its `status` is `detected` and its `approveState` is
`under_review`. Anything else is refused by the integration with the violation's actual state.

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | drp |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Whether to approve or reject the violation. Possible values are: approve, reject. | Required |
| id | Group-IB DRP violation ID. Defaults to the incident's GIB DRP ID field. | Optional |
| using | Name of the Group-IB Digital Risk Protection integration instance to use. Defaults to the instance that fetched the incident, or to the only active instance. | Optional |

## Outputs

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.ViolationResolution.id | String | Group-IB DRP violation ID that was resolved. |
| GIBDRP.ViolationResolution.status | String | The status the violation was set to. |
| GIBDRP.ViolationResolution.approveState | String | The approve state the violation moved to \(approved or rejected\). |
| GIBDRP.ViolationResolution.incidentUpdated | Boolean | Whether the new approve state was recorded on the incident. |
| GIBDRP.ViolationResolution.incidentClosed | Boolean | Whether the incident was closed with the decision \(always on reject, on approve as configured on the instance\). |
| GIBDRP.ViolationResolution.indicatorExpired | Boolean | Whether the indicator created from the violation was expired with the rejection. |
