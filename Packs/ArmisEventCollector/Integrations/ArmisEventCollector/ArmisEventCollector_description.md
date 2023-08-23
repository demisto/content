## Armis Event Collector

Agentless and passive security platform that sees, identifies, and classifies every device, tracks behavior, identifies threats, and takes action automatically to protect critical information and systems.

## Configuring the Armis Event Collector Instance

- Allocate a unique name for the instance.
- In *Server URL*, insert the instance URL of your Armis platform (e.g. https://example-instance.armis.com).
- In *API Key*, insert the generated API Key.
- Select *Trust any certificate*.
- Check *Fetches events* (for automatic ingestion of events from Armis into XSIAM).
- In *Number of events to fetch per type* insert the maximum number of events to fetch per type (per fetch), the default is 1,000.
- Select which log types to fetch from the *Log types to fetch* drop down menu in the Collect section.



## Armis API

- This integration supports the Armis API v.1.0.
- The Armis API has a maximum page size of 5,000 (Maximum number of events per fetch is 5,000).
  ##### Obtaining an API key from Armis:

  1. Log into the Armis platform and browse to **Settings** by clicking your account icon on the top right-hand side of the screen.
  2. Choose **Settings API Management**.
  3. Click **Create** and copy the generated key. (Do not share this key and do not create a non-encrypted copy of it.)
  - Refer to [Obtaining an API key from Armis](https://docs.ic.armis.com/docs/introduction_api-keys) for more details.