Endpoint security is at the frontline to protect against malicious cybersecurity threats. It represents one of the first places organizations look to secure their enterprise networks.  
As the volume and sophistication of cybersecurity threats have increased, so has the need for more advanced endpoint security solutions.  
CrowdStrike Falcon is one of the leaders in the Endpoint Protection Platform (EPP) market, and the CrowdStrike Falcon content pack provides a holistic solution for protecting enterprise endpoints and servers from malicious attacks that can seriously impact your organization.  
This pack is designed to quickly detect, analyze, block, and contain malicious attacks in progress. It also gives administrators visibility into advanced threats to speed detection and remediation response times.  

## What Does This Pack Do?
- Mirrors incidents between Cortex XSOAR incidents and CrowdStrike Falcon incidents or detections
- Provides real-time response features
- Assesses vulnerability
- Contains endpoints (isolation/unisolation)
- Removes duplicate incidents
- Eliminates false positive incidents
- Enriches incidents

## Before You Start
Make sure you have the following content packs:
- Base
- Common Scripts
- Common Types

## Pack Configurations  
To get up and running with this pack, you must get an API client ID and secret from CrowdStrike support: support@crowdstrike.com.

#### Note
The parsing rules are targeting the data set crowdstrike_falcon_incident_raw that is created when ingesting logs from CrowdStrike Platform data source using CrowdStrike APIs and will be deprecated from XSIAM V2.5.
