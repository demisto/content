## Armis Event Collector

Agentless and passive security platform that sees, identifies, and classifies every device, tracks behavior, identifies threats, and takes action automatically to protect critical information and systems.

## Configuring the Armis Event Collector Instance

- Allocate a unique name for the instance.
- In *Server URL*, type in the URL of your Armis platform URL, for example: acme.armis.com/api/v1
- Generate an API key via the Armis platform. Refer to [Obtaining an API key from Armis](#obtaining-an-api-key-from-Armis) for details.
- In *API Key*, type the generated API Key
- Select *Trust any certificate*.
- Choose *Fetch events* (for automatic ingestion of alerts from Armis into XSIAM).
- Fetch Alerts AQL - see [Fetch Alert using an AQL](#fetch-alert-using-an-aql) for details.

## Obtaining an API key from Armis

1. Log into the Armis platform and browse to **Settings** by clicking your account icon on the top right-hand side of the screen.
2. Choose **Settings API Management**.
3. Click **Create** and copy the generated key. (Do not share this key and do not create a non-encrypted copy of it.)