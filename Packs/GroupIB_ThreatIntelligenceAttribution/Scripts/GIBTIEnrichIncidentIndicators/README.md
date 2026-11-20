Enriches the indicators of a Group-IB incident.

Incidents fetched by the **Group-IB Threat Intelligence** integration get their indicators through the platform's extraction of *GIB Related Indicators Data*, and the e-mail addresses of threat reports and phishing kits through *GIB Related Emails*: bare values without a verdict, tags or attributes. This automation reads the record again with the matching `gibti-get-*-info` command and creates every observable of the record with the built-in `createNewIndicator`, with the verdict, tags, malware family, TLP, geo data, ASN, file hashes and size, CVSS score and vector, CVE dates and description, and *GIB Collection* the record carries, related to the malware families (*indicator-of*) and threat actors (*related-to*) it names. A *Cryptocurrency Address* indicator gets no tags, malware family or TLP, and an *Email* or *CVE* indicator no malware family. It also returns the command's indicator entries to the War Room, for their tables and relationships. The observables are created explicitly, so they exist whatever the task's indicator extraction mode. The Malware / Threat Actor objects behind those relationships are created with the built-in `createNewIndicator`, so every relationship points at an existing object. Each object is tagged with the collection and stamped with *GIB Collection*. A new object gets the most restrictive TLP of the record's observables and of the incident's *GIB TLP*; an object that already exists keeps its own TLP. When the incident names a single threat actor, that object also gets its Group-IB ID and APT flag. The objects are Bad. The names on a *GIB Data Breach* incident are the leak's publishers, and the name on a defacement incident is the defacer's handle; neither is an attribution, so they make no object. A phishing group that Group-IB flags as a false positive or allow-listed gives no indicator and no object. *Email* indicators carry the tags and TLP of their record, and a Bitcoin wallet (base58check or `bc1`) is created as `bitcoin:<address>`, the value Cortex XSOAR's extraction gives a base58check wallet. The entries of a defacement lookup stay excluded from extraction, so the defaced site's host never becomes a *Domain* indicator.

When run inside a Group-IB incident, the script needs no arguments, except in an incident of a legacy type (a renamed or removed collection), where it returns a note and enriches nothing unless `collection` is passed. The pack's *Incident Postprocessing - Group-IB Threat Intelligence & Attribution* playbook, the default playbook of every Group-IB incident type, runs it first.

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | threat-intel, enrichment |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

Requires an enabled instance of the Group-IB Threat Intelligence integration (the `gibti-get-*-info` commands).

## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| gib_id | Group-IB record ID. Defaults to the GIB ID of the incident the script runs in. |
| collection | Group-IB collection the ID belongs to. Defaults to the collection behind the incident type the script runs in. |
| instance | Name of the Group-IB Threat Intelligence instance to read the record with. Defaults to the instance that fetched the incident, or to the only active instance; with several active instances and none of them the one that fetched the incident, the command runs on every instance. |
| create_objects | Create the Malware / Threat Actor objects the record names (with createNewIndicator), so that the relationships of the indicators point at existing objects. |

## Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GIBTI.IncidentEnrichment.gibId | Group-IB record ID the indicators were read from. | String |
| GIBTI.IncidentEnrichment.collection | Group-IB collection of the record. | String |
| GIBTI.IncidentEnrichment.command | The lookup command that read the record. | String |
| GIBTI.IncidentEnrichment.instance | The integration instance the record was read with (empty when the command ran on every instance). | String |
| GIBTI.IncidentEnrichment.indicators.value | Value of an enriched indicator. | String |
| GIBTI.IncidentEnrichment.indicators.type | Type of an enriched indicator. | String |
| GIBTI.IncidentEnrichment.objects.type | Type (Malware or Threat Actor) of an object the indicators are related to. | String |
| GIBTI.IncidentEnrichment.objects.name | Name of an object the indicators are related to. | String |
| GIBTI.IncidentEnrichment.objectsCreated.type | Type (Malware or Threat Actor) of an object the run created or updated. | String |
| GIBTI.IncidentEnrichment.objectsCreated.name | Name of an object the run created or updated. | String |
| GIBTI.IncidentEnrichment.errors | Indicators and objects that could not be created, with the error. | String |

## Command Example

```
!GIBTIEnrichIncidentIndicators
!GIBTIEnrichIncidentIndicators collection=malware/cnc gib_id=<record id>
```
