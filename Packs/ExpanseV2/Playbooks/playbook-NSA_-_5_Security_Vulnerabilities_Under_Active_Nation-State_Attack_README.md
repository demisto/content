Russian Foreign Intelligence Service (SVR) actors (also known as APT29, Cozy Bear, and The Dukes) frequently use publicly known vulnerabilities to conduct widespread scanning and exploitation.
This playbook should be trigger manually and includes the following tasks:
- Enrich related known CVEs used by the SVR.
- Search for unpatched endpoints vulnerable to the exploits.
- Search network facing system using Expanse for relevant connection.

Note: This is a beta playbook, which lets you implement and test pre-release software. Since the playbook is beta, it might contain bugs. Updates to the pack during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the pack to help us identify issues, fix them, and continually improve. 

More information:
[Cyber Security Advisory] (https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* CVE Enrichment - Generic v2
* Search Endpoint by CVE - Generic

### Integrations
* ExpanseV2

### Scripts
* SearchIncidentsV2

### Commands
* linkIncidents
* extractIndicators
* expanse-get-issues

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Related_CVEs | Known related CVEs to hunt | CVE-2018-13379, CVE-2019-9670, CVE-2019-11510, CVE-2019-19781, CVE-2020-4006 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![NSA - 5 Security Vulnerabilities Under Active Nation-State Attack](https://raw.githubusercontent.com/demisto/content/64a9d0358cabc26b7d5e945994d7b74a05263a2d/Packs/MajorBreachesInvestigationandResponse/doc_files/Russian_SVR_-_Publicly_Known_CVEs_Used.png)