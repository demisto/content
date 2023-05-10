
Palo Alto Cortex Data Lake provides customers with the ability to store, process, and analyze large data sets in a secure and compliant manner.

The Cortex Data Lake integration facilitates network security visualization and threat identification, automates incident response, and meets regulatory compliance requirements.

#### What does this pack do?
- Perform queries on any field within the threat, traffic, URL, and file data firewall tables.
- Reset the authentication limit cache if a call-limit error occurs.

This pack includes the following playbooks:
- **Cortex Data Lake - Traffic Indicators Hunting** - queries Cortex Data Lake (CDL) for file indicators, including MD5 hashes, SHA256 hashes, SHA1 hashes, file names, and file types.
- **Cortex Data Lake - File Indicators Hunting** - queries Cortex Data Lake (CDL) for traffic indicators, including IP addresses, geolocations, URLs, domains, and ports.
- **Cortex Data Lake - Indicators Hunting** - facilitates threat hunting and detection of IOCs within Cortex Data Lake logs. The playbook and sub-playbooks query Cortex Data Lake for files, traffic, HTTP requests, and execution flows indicators. Supported IOCs for this playbook are SHA256, MD5, SHA1, IP addresses, geolocations, URLs, domains, port Numbers, file Names, file Types, URIs, Applications.
