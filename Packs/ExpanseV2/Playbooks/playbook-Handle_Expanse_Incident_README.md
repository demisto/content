Main Playbook to Handle Expanse Incidents.

There are several phases:
1. Enrichment: all the related information from the incident is extracted, and related indicators (IP, CIDR, Domain, DomainGlob, Certificate) are created and enriched.
2. Validation: the found IP and FQDN are correlated with the information available in other products:
   - Risky or non-compliant communications to and from the IP with external IPs as flagged in Expanse's Behavior.
   - Firewall logs from Cortex Data Lake, Panorama, and Splunk.
   - User information from Active Directory.
   - Public IP address from AWS/GCP/Azure public IP feeds to identify the Public Cloud region and service (i.e., us-west-1 on AWS EC2).
   - IP and FQDN from Prisma Cloud inventory.
3. Shadow IT check: based on the information found, the playbook can suggest whether the discovered issue corresponds to an asset that is known to the InfoSec team (i.e., there are firewall logs present, or the asset is protected by Prisma Cloud, or is part of an IP range associated to the company).
 4. Attribution: based on the information collected above, the analyst is prompted to assign this issue to an Organization Unit, which is a group within the company with a specific owner. The analyst can choose from existing Organization Units (stored in an XSOAR list) or define a new one.
  5. Response: depending on the issue type, several remediation actions can be automatically and manually performed, such as:
      - Tagging the asset in Expanse with a specific Organization Unit tag.
      - Blocking the service on PAN-OS (if a firewall is deployed in front of the service).
      - Creating a new Shadow IT issue (if the asset is detected to be Shadow IT and the analyst confirms it).
      - Adding the service to a Vulnerability Management system.
      - Linking the incident to a related Prisma Cloud alert for the asset (if the asset is found under Prisma Cloud inventory).

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* PAN-OS - Block Destination Service on Panorama
* Expanse Enrich Cloud Assets
* Extract and Enrich Expanse Indicators
* Prisma Cloud Correlate Alerts
* PAN-OS - Block Destination Service on Firewall
* Expanse Load-Create List
* Expanse Attribution
* Expanse VM Enrich
* Expanse Unmanaged Cloud

### Integrations
ExpanseV2

### Scripts
* CopyNotesToIncident
* ExpansePrintSuggestions
* ExpanseRefreshIssueAssets
* AddKeyToList
* Set
* SetAndHandleEmpty
* ToTable

### Commands
* expanse-assign-tags-to-asset
* expanse-get-issue-comments
* expanse-update-issue
* closeInvestigation
* setIncident
* panorama-show-device-version
* linkIncidents
* createNewIncident
* getList
* send-mail
* expanse-create-tag

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MinPriorityForAutoRemediation | Minimum Incident Priority for Auto Remediation:<br/>1 - Low<br/>2 - Medium<br/>3 - High<br/>4 - Critical<br/>5 - Disable AutoRemediation | 5 | Optional |
| FirewallTagListName | Name of Cortex XSOAR list that contains the mapping between Expanse tags and XSOAR PANOS instances. | ExpanseTagsToPANOSDeviceGroup | Optional |
| TagPrefix | Prefix for Cortex XSOAR related Expanse tags. | xsoar- | Optional |
| LogForwarding | PAN-OS Log Forwarding Profile Name. |  | Optional |
| AutoCommit | Panorama Auto Commit:<br/>True - enable AutoCommit<br/>False - disable AutoCommit | False | Optional |
| IPRangeLowConfidenceTagList | Comma-separated list of tags to be used to identify IP ranges attributed with low confidence | low confidence | Optional |
| InvalidTag | Tag to be used for Expanse assets that do not belong to org. \(Set when the analyst selects invalid in the OU data collection.\) | xsoar-invalid | Optional |
| WriteToExpanse | Write data back to Expanse? | True | Optional |
| OwnerNotificationSubject | Subject of the email to send to the OU Owner. | New security issue on a public service owned by your team | Optional |
| OwnerNotificationBody | Body of the email to send to the OU Owner. | Infosec identified a security issue on a service owned by your team and exposed on the internet. Get in touch with your Infosec team to define proper remediation access. | Optional |
| ShadowITIncidentType | If set, specifies the type of incident that gets automatically created during the Shadow IT flow. If not set, the incident is to be created manually. | Shadow IT | Optional |
| OrganizationUnitsToOwnerName | Name of the Cortex XSOAR list that contains the mapping between OU and owners. | ExpanseOrganizationUnitsToOwner | Optional |
| OrganizationUnitsToTagName | Name of the Cortex XSOAR list that contains the mapping between OU and tag names, | ExpanseOrganizationUnitsToTag | Optional |
| NumberOfDaysInThePast | The number of days to go back in time when searching logs. | 7 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Handle Expanse Incident](https://github.com/demisto/content/raw/6f6b91706ecfd8a193f98b711c108edde7ece906/Packs/ExpanseV2/doc_files/Handle_Expanse_Incident.png)