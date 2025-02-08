<p align="center">
<img alt="Accenture Security" src="doc_files/logo.png"/> 
</p>



# **Accenture CTI v2**
 
This pack has 2 sub-pack/integration namely:
- ACTI Indicator Query
- ACTI Vulnerability Query

This pack automates the detection of threats and the triage/investigation of incidents by importing **Accenture CTI (ACTI)** data and intelligence reports into the XSOAR platform. The incident-enrichment functionality not only alleviates tedious research tasks traditionally performed by analysts, but also automatically folds ACTI intelligence reports associated with a given incident into the incident. The result is a complete picture of what ACTI knows about any given threat the moment the analyst opens the XSOAR incident.
_____


## **What to expect from the Accenture Cyber Threat Intelligence (_Accenture CTI v2_) pack?**
- A playbook that automatically queries Accenture's IntelGraph API to pull context for IOC and associated intelligence reports into XSOAR incidents.
- Reputation Commands to query for network-level indicators (_IP, Domain, and URL_).
- Command to query for ACTI intelligence reports.
- Command to query ACTI Vulnerability database.
- The pack also includes a playbook which helps to enrich indicators present in incident with related ACTI Intelligence Alert, ACTI Intelligence Report, ACTI Malware Family, ACTI Threat Actor, ACTI Threat Campaign, ACTI Threat Group if present in Accenture IntelGraph.