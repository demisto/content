## Overview
---
Use Blueliv ThreatContext integration to get threats information

## To set up Blueliv ThreatContext to work with Cortex XSOAR:
---

You need the following information:

1. platform credentials
2. your tenant URL
3. Specify proxy server (if required)

## To set up the integration on Cortex XSOAR:
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Blueliv ThreatContext integration.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g., https://mytenant.blueliv.com)__
    * __Username__
    * __Password__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
	
4. Click __Test__ to validate the URLs, token, and connection.

## Fetched Incidents Data
---

## Use Cases
---
1. Get attack patterns information
2. Get malware campaigns information
3. Get information about specific CVE
4. Get information about crimeservers (C&C)
5. Get information about differnt indicators of compromise like IPs, FQDN,hashes...
6. Get information about malware signatures
7. Get information about threat actors
8. Get information about hacking tools

## Known Limitations
---
Currently is not possible to create a user with a passwod that doesn't expire, so you need to remember to change the password and update the integration credentials used to generate the token. 