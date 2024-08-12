Note: Support for this pack moved to the partner on March, 22, 2022.

ReliaQuest GreyMatter DRP minimizes digital risk by identifying unwanted exposure and protecting against external threats. The award-winning ReliaQuest GreyMatter DRP solution provides ongoing monitoring of a customer's unique assets and exposure across the open, deep, and dark web. This enables clients to detect data loss, brand impersonation, infrastructure risks, cyber threats, and much more.

## Overview
- Leader in Digital Risk Protection
- Combination of technology and analysts
- SaaS-based portal
- Integrates into existing technologies via API
- Lowest total cost of ownership
- Nine years of indexed data

**Data Leakage Detection**
Marked Documents
Customer Details
Employee Credentials

**Brand Protection**
Impersonating Domains
Phishing Sites
Spoof Social Media Profiles
Spoof Mobile Apps

**Technical Leakage Detection**
Exposed Access Keys
Unauthorized Code Commit
Leaked Sensitive Technology
Leaked Sensitive Code

**Dark Web Monitoring**
Accounts for Sale
Mentioned by Threat Actor
Phishing Kits

**Attack Surface Monitoring**
Exploitable Vulnerabilities
Certificate Issues
Open Ports
Misconfigured Devices

**Threat Intelligence**
Threat Actor Profiles/Tracking
Intelligence Incidents
Supplier/Vendor Monitoring
Vulnerability/Exploit Monitoring

## What makes ReliaQuest GreyMatter DRP unique

- Exposure monitoring  
  ReliaQuest GreyMatter DRP monitors for the exposure of these assets across the open, deep, and dark web. This includes code-sharing sites, file-sharing sites, criminal forums, chat messages, social media, and search engines. For additional enrichment and incident response, users can search across many of these sources via "Shadow Search". Furthermore, our Collections and Closed Sources teams focus on continually adding to these sources.

- Risk Identification
  Our technology reduces the mentions of these assets to only those instances that constitute a risk to your business. On average, this combination of technology and human analysis removes more than 95% of the total mentions of an organization's assets. Each alert has a risk score, ensuring your team is not overwhelmed by irrelevant mentions and can easily prioritize alerts.

- Take Action and Protect  
  Alerts provide you all the context you need to make quicker, better decisions. Users also benefit from playbooks for remediating the risk, including the ability to launch takedowns.

## Configuration Guide

## Request Digital Shadows API Credentials

To use the application you will need to request an API Key and secret from Digital Shadows Support. Email support@digitalshadows.com stating that you would like to utilize the Digital Shadows Cortex XSOAR Integration and your SearchLightTM account details to have a new API Key created and assigned to you. 

To find your SearchLightTM  account details; in the SearchLightTM  portal please navigate to: 
- ‘Learn’ > ‘API Documentation’  
- Use the left hand filter to select ‘Keywords’   
- Scroll down to ‘Account’ and the ID is displayed

## Configuration

To configure the Digital Shadows Integration with Cortex XSOAR, from your XSOAR instance, navigate to:
- Left navigation panel 
- ‘Settings’
- Type ‘ReliaQuest GreyMatter DRP’ in the search bar 
- Click on the gear icon 

Here you can give your settings a custom name and set up several settings: 

Input: 
- ‘Classifier’ - Recommended to select ‘ReliaQuest GreyMatter DRP Incidents Classifier’ 
- ‘Mapper’ - Recommended to select ‘Reliaquest GreyMatter DRP Incidents Mapper’ 
- ‘Server URL’ - API URL for calling, is https://api.searchlight.app
- accountId – Account ID obtained from Digital Shadows Portal 
- ‘API Key’ and ‘Secret’ - Obtained from Digital Shadows 
- Risk Types – ‘All’ is the default. These can also be selected individually.
- ‘Risk Level’ – ‘All’ is the default. These can also be selected individually. 
- ‘Ingest Rejected/Resolved/Closed Incidents’ – This is an optional check box.
- ‘Fetch Limit’ – The maximum number of Incidents to Fetch 
- ‘Incidents Fetch Interval’ - Scheduled time frame between polling Digital Shadows for data 
- ‘Start Date’ – Initial Date to start pulling data from. (Historical incidents)
- ‘Log Level’ – ‘Verbose’, ‘Debug’, or ‘Off’  

Click on the ‘Test results’ tab and click ‘Run test’ 
. If you receive a ‘Success’ message then the integration is configured and will begin populating the ‘Investigation’ > ‘Incidents’ dashboard 

Note: TAXII feeds can be set up in order to receive IOCs from Digital Shadows.  

Email: drpsupport@reliaquest.com
Call us at US 1-888-889-4143, UK +44 (0)203 393 7001

Visit www.reliaquest.com for more information

