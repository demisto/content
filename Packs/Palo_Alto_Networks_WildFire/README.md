Use the Palo Alto Networks Wildfire integration to automatically identify unknown threats and stop attackers in their tracks by performing malware dynamic analysis.


## What does this pack do?
- Send a File sample to WildFire.
- Upload a file hosted on a website to WildFire.
- Submit a webpage to WildFire.
- Get a report regarding the sent samples using file hash.
- Get sample file from WildFire.
- Get verdict regarding multiple hashes (up to 500) using the wildfire-get-verdicts command.


The content pack contains 4 playbooks 
- WildFire - Detonate File / Detonate File From URL - WildFire - Detonate one or more files using the Wildfire integration. This playbook returns relevant reports to the War Room and file reputations to the context data.
- Detonate URL - WildFire v2.1 / Detonate URL - WildFire-v2 - Detonate a webpage or remote file using the WildFire integration. This playbook returns relevant reports to the War Room and file reputations to the context data.


## Create an integration instance
To create an instance of the integration, you need the WildFire API key
This API key is used in the API Key field in the integration configuration.

1. Navigate to and log into your WildFire Account.
2. Select the Account tab from the menu.
3. Copy the API key.

Note: If your API key comes from integrations such as Prisma Cloud or Prisma Access ensure that the API source is set in the instance config.