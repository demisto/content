This playbook is responsible for collecting data from Cortex XDR detector and enriching data for further usage and building the layout.

The playbook collects or enriches the following data:
- Resource enrichment
   - Previous activity seen in the specified region or project
- Account enrichment
- Network enrichment
   - Attacker IP
   - Geolocation
   - ASN

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Account Enrichment - Generic v2.1
* IP Enrichment - Generic v2

### Integrations

This playbook does not use any integrations.

### Scripts

* Set
* IsInCidrRanges
* CopyContextToField
* If-Then-Else

### Commands

* ip
* setIncident

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| ResolveIP | Determines whether to convert the IP address to a hostname using a DNS query \(True/ False\). | True | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. \\nFor IP Enrichment - Generic v2 playbook. | lists.PrivateIPs | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IP | The IP objects. | unknown |
| DBotScore | Indicator, Score, Type, Vendor. | unknown |
| Account | The account object. | unknown |
| IAM | Generic IAM output. | unknown |
| ASNType | Checks for cloud ASNs. | unknown |
| isKnownRegion | Checks if any recent activity was seen in the region. | unknown |
| isKnownProject | Checks if any recent activity was seen in the project. | unknown |
| resourceCount | Involved resource count. | unknown |
| uniqueRegionCount | Involved region distinct count. | unknown |

## Playbook Image

---

![Cortex XDR - Cloud Enrichment](../doc_files/Cortex_XDR_-_Cloud_Enrichment.png)
