The Unit 42 v2 feed provides access to published IOCs that contain known malicious indicators. You can configure the number of indicators to be returned. The default is 10.

The newest Unit 42 Feed V2 Pack introduces the STIX format and ingests more Threat Intel than before. All the Unit42 ATOM information now in your XSOAR Threat Intel Library.
- STIX object-oriented - we are now using: Report, Intrusion Set, Campaign, Attack Pattern, Course of Action, and of course IOCs
- The main Report object is associated to its related Intrusion Set and Campaigns
- Each Campaign has its specific Attack Patterns, Course of Actions and IOCs 
- Starting with version 6.2 - RELATIONSHIPS between objects is now supported!

In order to access the Unit 42 feed, you first must register for an account.

1. Go to https://stix2.unit42.org/ to sign up.
2. Log in and create an API key for the service using the 'API Keys' page.
3. Click the '+' button in the table header to create a new key.
4. Use the 'copy' icon in the new key's row to copy the full key to the clipboard.
