 Shorter version of Handle Expanse Incident playbook with only the Attribution part.

There are several phases:
1. Enrichment: all the related information from the incident is extracted and related Indicators (of types IP, CIDR, Domain, DomainGlob, Certificate) are created and enriched.
2. Validation: the found IP and FQDN are correlated with the information available in other products:
  - Firewall logs from Cortex Data Lake, Panorama and Splunk
  - User information from Active Directory
  - Public IP address from AWS/GCP/Azure public IP feeds to identify the Public Cloud region and Service (i.e. us-west-1 on AWS EC2)
  - IP and FQDN from Prisma Cloud inventory
3. Shadow IT check: based on the information found, the playbook can suggest whether the discovered issue corresponds to an asset that is known to the InfoSec team (i.e. there are firewall logs present, or the asset is protected by Prisma Cloud, or is part of an IP range associated to the Company).
4. Attribution: based on the information collected above, the Analyst is prompted to assign this issue to an Organization Unit, that is a group within the Company with a specific owner. The Analyst can choose from existing Organization Units (stored in an XSOAR list) or define a new one.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Enrich Cloud Assets
* Expanse Load-Create List
* Prisma Cloud Correlate Alerts
* Extract and Enrich Expanse Indicators
* Attribution

### Integrations
* ExpanseV2

### Scripts
* ExpanseRefreshIssueAssets
* CopyNotesToIncident
* ToTable
* AddKeyToList
* Set
* ExpansePrintSuggestions
* SetAndHandleEmpty

### Commands
* expanse-create-tag
* expanse-update-issue
* createNewIncident
* expanse-get-issue-comments
* closeInvestigation
* expanse-get-risky-flows
* setIncident
* linkIncidents
* getList
* expanse-assign-tags-to-asset

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| TagPrefix | Prefix for XSOAR related Expanse tags | xsoar- | Optional |
| IPRangeLowConfidenceTagList | Comma separated list of tags to be used to identify IP ranges attributed with low confidence | low confidence | Optional |
| InvalidTag | Tag to be used for Expanse assets that do not belong to org \(set when the Analyst selects Invalid in the OU data collection\) | xsoar-invalid | Optional |
| WriteToExpanse | Write data back to Expanse? | True | Optional |
| OwnerNotificationSubject | Subject of the email to send to the OU Owner. | New security issue on a public service owned by your team | Optional |
| OwnerNotificationBody | Body of the email to send to the OU Owner. | Infosec identified a security issue on a service owned by your team and exposed on Internet. Please get in touch with your Infosec team to define proper remediation access. | Optional |
| UseBehavior | Enrich flows using Expanse Behavior. | True | Optional |
| OrganizationUnitsToOwnerName | Name of XSOAR List that contains the mapping between OU and Owners | ExpanseOrganizationUnitsToOwner | Optional |
| OrganizationUnitsToTagName | Name of XSOAR List that contains the mapping between OU and Tag names | ExpanseOrganizationUnitsToTag | Optional |
| NumberOfDaysInThePast | How many days to go back in time when searching logs | 7 | Optional |
| ShadowITIncidentType | If set, specifies the type of Incident that gets automatically created during the Shadow IT flow. If not set, the Incident is to be created manually. |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Handle Expanse Incident - Attribution Only](https://raw.githubusercontent.com/demisto/content/cfcd4dbc38cc4ec560202da62750c73c9452b553/Packs/ExpanseV2/Playbooks/playbook-Handle_Expanse_Incident_-_Attribution_Only.png)