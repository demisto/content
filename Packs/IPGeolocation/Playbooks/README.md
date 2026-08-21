Enriches one or more IP addresses with IPGeolocation.io data.

The playbook first confirms that an enabled IPGeolocation.io integration instance is available; if none is
found, it ends immediately instead of silently completing with no enrichment. It then scores the address with
the generic ip command, which writes a DBotScore derived from the IPGeolocation.io IP Security threat score and
detection flags. It then adds Autonomous System context to support infrastructure pivoting. When the resulting
verdict meets or exceeds the SuspiciousThreshold input (Suspicious by default), it resolves the abuse contact
for the network(s) owning only the IP addresses that met the threshold, so a notification or takedown task can
use it without spending API credits on addresses that scored clean.

All enrichment tasks tolerate errors, so a private, bogon or unresolvable address does not stop the playbook.

This playbook requires a paid IPGeolocation.io subscription, because IP Security, ASN and Abuse Contact data are
not available on the Free plan.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* IPGeolocation.io

### Scripts

* IsIntegrationAvailable

### Commands

* ip
* ipgeolocation-abuse-contact
* ipgeolocation-asn

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| IP | The IP address or addresses to enrich. Defaults to the IP indicators already in the incident context. | IP.Address | Optional |
| SuspiciousThreshold | The minimum IPGeolocation.io DBotScore \(2 = Suspicious, 3 = Malicious\) at which the playbook resolves the abuse contact of the owning network. Defaults to 2 \(Suspicious\). Set to 3 to restrict abuse-contact resolution to Malicious verdicts only. | 2 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore | The IPGeolocation.io reputation of the IP address. | unknown |
| IP | The standard IP indicator context, including geolocation, Autonomous System and abuse contact fields. | unknown |
| IPGeolocation.IP | The IPGeolocation.io geolocation, security and abuse contact data for the IP address. | unknown |
| IPGeolocation.ASN | The IPGeolocation.io Autonomous System data for the IP address. | unknown |
