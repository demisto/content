
Palo Alto Strata Logging Service provides customers with the ability to store, process, and analyze large data sets in a secure and compliant manner.

The Strata Logging Service integration facilitates network security visualization and threat identification, automates incident response, and meets regulatory compliance requirements.

#### What does this pack do?
- Perform queries on any field within the threat, traffic, URL, and file data firewall tables.
- Reset the authentication limit cache if a call-limit error occurs.

This pack includes the following playbooks:
- **Strata Logging Service - Traffic Indicators Hunting** - queries Strata Logging Service (SLS) for file indicators, including MD5 hashes, SHA256 hashes, SHA1 hashes, file names, and file types.
- **Strata Logging Service - File Indicators Hunting** - queries Strata Logging Service (SLS) for traffic indicators, including IP addresses, geolocations, URLs, domains, and ports.
- **Strata Logging Service - Indicators Hunting** - facilitates threat hunting and detection of IOCs within Strata Logging Service logs. The playbook and sub-playbooks query Strata Logging Service for files, traffic, HTTP requests, and execution flows indicators. Supported IOCs for this playbook are SHA256, MD5, SHA1, IP addresses, geolocations, URLs, domains, port Numbers, file Names, file Types, URIs, Applications.
