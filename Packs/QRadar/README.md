QRadar aggregates and parses logs that come in from various data sources. The QRadar admin creates rules for detecting suspicious traffic, suspicious IDs, etc., and runs searches to obtain additional data about these offences.

## What does this pack do?
The integration in this pack automatically fetches the offences from QRadar along with all the additional data about the offenses. The data from QRadar is populated into XSOAR incident fields providing the XSOAR analyst with all the information about the incident just by performing a fetch. 

## Use Case-
### Incident and Offense Management:
Automate the fetching and management of security incidents (offenses) from QRadar into Cortex. This includes enrichment of offenses with additional data, calculating severity, assigning incidents to analysts, and even automating the closure of false positives.
### Threat Hunting:
Leverage the QRadar integration to perform advanced threat hunting activities. Use playbooks to run automated queries across QRadar data to identify indicators of compromise (IoCs) such as suspicious IP addresses, domains, or file hashes.
### Automated Response and Enrichment:
Use the integration to automate the enrichment of offenses with contextual data, such as linking associated IP addresses, user details, and related assets.
### Indicator Management:
Automate the process of pushing indicators into QRadar reference sets. This can be used to either block malicious indicators or exclude benign ones from triggering alerts, thereby fine-tuning the detection capabilities of your QRadar instance.

_For more information, visit our [Cortex XSOAR Developer Docs](https://xsoar.pan.dev/docs/reference/packs/QRadar)._

_If you're new to our QRadar Content Pack, check out our [Ingest Incidents from a SIEM Using QRadar](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Tutorials-6.x/Ingest-Incidents-from-a-SIEM-Using-Splunk) tutorial._
