## Armis Event Collector

Agentless and passive security platform that sees, identifies, and classifies every device, tracks behavior, identifies threats, and takes action automatically to protect critical information and systems.

## Configuring the Armis Event Collector Instance
### Connect section
- Allocate a unique name for the instance.
- In *Server URL*, insert the instance URL of your Armis platform (e.g. https://example-instance.armis.com).
- In *API Key*, insert the generated API Key.
- Choose whether to *Trust any certificate*.
### Collect Section
- Check *Fetches events* (for automatic ingestion of events from Armis into XSIAM).
- Select which event types to fetch from the *Event types to fetch* drop down menu.
- *Events Fetch Interval* default value is 1 minute, this parameter can be found under "Advanced Settings".



## Armis API

- This integration supports the Armis API 1.8.0 version.
- The Armis API has a maximum response size of 5,000 events per API request.
  The event collector can handle a bigger number of events per fetch by sending multiple API requests if needed.
### Obtaining an API key from Armis:

1. Log into the Armis platform and browse to **Settings** by clicking your account icon on the top right-hand side of the screen.
2. Choose **Settings API Management**.
3. Click **Create** and copy the generated key. (Do not share this key and do not create a non-encrypted copy of it.)
4. Refer to [Obtaining an API key from Armis](https://docs.ic.armis.com/docs/introduction_api-keys) for more details.