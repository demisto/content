This playbook retrieves forensics from hosts for the following integrations:
 - Illusive Networks 
 - Microsoft Defender For Endpoint.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Illusive-Collect-Forensics-On-Demand
* Microsoft Defender For Endpoint - Collect investigation package

### Integrations

This playbook does not use any integrations.

### Scripts

* IsIntegrationAvailable

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| fqdn_or_ip | If using the Illusive Networks integration to retrieve additional forensics, provide the host fqdn_or_ip from which to get the forensics.  |  | Optional |
| start_date | Date_range must be "number date_range_unit", for example 2 hours, 4 minutes, 6 months, 1 day. |  | Optional |
| end_date | Date_range must be "number date_range_unit" for example 2 hours, 4 minutes, 6 months, 1 day. |  | Optional |
| machine_ID | Provide the machine IDs of the systems you want to retrieve. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MicrosoftATP | An object containing the machine action details. | unknown |
| MicrosoftATP.MachineAction | Microsoft Defender For Endpoint machine action details. | unknown |
| Illusive.Forensics.Evidence | An object containing evidence from Illusive Networks. | unknown |
| Illusive.Forensics.Evidence.details | The forensics evidence details. | unknown |
| Illusive.Forensics.Evidence.eventId | The event ID. | unknown |
| Illusive.Forensics.Evidence.id | The forensics evidence ID. | unknown |
| Illusive.Forensics.Evidence.source | The evidence source. | unknown |
| Illusive.Forensics.Evidence.starred | Whether the forensics evidence has been starred. | unknown |
| Illusive.Forensics.Evidence.time | Date and time of the forensics evidence.  | unknown |
| Illusive.Forensics.Evidence.title | The forensics evidence description. | unknown |
| Illusive.Forensics | Ab object containing the Incident ID in Illusive Networks. | unknown |
| Illusive.Forensics.IncidentId | The incident ID. | unknown |

## Playbook Image

---

![Get host forensics - Generic](../doc_files/Get_host_forensics_-_Generic.png)
