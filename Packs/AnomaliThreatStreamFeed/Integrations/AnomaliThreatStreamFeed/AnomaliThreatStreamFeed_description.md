## Anomali ThreatStream Feed Integration Help

Anomali ThreatStream is a leading threat intelligence platform designed to help organizations collect, analyze, and act on vast amounts of threat data. 
This integration allows you to automatically fetch Indicators of Compromise (IOCs) such as IPs, domains, URLs, and file hashes directly into your security operations platform, enhancing your ability to detect and respond to cyber threats.

### How to Configure Your Integration in XSOAR
When configuring the Anomali ThreatStream Feed in your XSOAR environment, consider the following parameters for optimal performance and security:

General Configuration

API Key: Paste the API key you retrieved from your Anomali ThreatStream account into this field.

Base URL: Confirm that the pre-filled URL matches the correct API endpoint for your Anomali ThreatStream instance.

Indicator Fetching & Filtering
Fetch Indicators: Enable this checkbox to allow XSOAR to automatically pull indicators from Anomali ThreatStream at regular intervals.

Confidence Threshold: Set a minimum confidence score. Only indicators meeting or exceeding this threshold.
