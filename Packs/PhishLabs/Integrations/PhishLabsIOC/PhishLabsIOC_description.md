The IOC feed in PhishLabs is divided into 2 endpoints:
### Global Feed
This is the PhishLabs global database for malicious indicators.
This feed consists of indicators that are classified as malicious by PhishLabs - 
URLs, domains, and attachments (MD5 hashes). All the indicators from this feed are classified as malicious in Cortex XSOAR.
To populate indicators from PhishLabs in Cortex XSOAR, use the **PhishLabsPopulateIndicators** script/playbooks.

### User Feed
This feed is exclusive for the user and consists of emails that were sent to PhishLabs and were classified as malicious emails. For each malicious email, an incident is created that contains the email details and the extracted indicators. These indicators are not necessarily malicious though. In Cortex XSOAR,
the user can choose whether to classify those indicators as malicious or suspicious. Incidents can be fetched by enabling fetch incidents in the integration configuration.
