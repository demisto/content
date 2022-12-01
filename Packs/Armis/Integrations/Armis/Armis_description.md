## Armis

Agentless and passive security platform that sees, identifies, and classifies every device, tracks behavior, identifies threats, and takes action automatically to protect critical information and systems.

## Configuring the Armis Instance

- Allocate a unique name for the instance.
- Choose *Fetch instances* (for automatic ingestion of alerts from Armis into XSOAR).
- Ensure *Classifier* is initialized with the Armis classifier provided.
- Ensure *Mapper* is initialized with the Armis mapper provided.
- In *Server URL*, type in the URL of your Armis platform URL, for example: acme.armis.com/api/v1
- Choose what type of Armis alerts XSOAR will fetch from the options provided
- Generate an API key via the Armis platform. Refer to [Obtaining an API key from Armis](#obtaining-an-api-key-from-Armis) for details.
- Select *Trust any certificate*.
- Fetch Alerts AQL - see [Fetch Alert using an AQL](#fetch-alert-using-an-aql) for details.

## Obtaining an API key from Armis

1. Log into the Armis platform and browse to **Settings** by clicking your account icon on the top right-hand side of the screen.
2. Choose **Settings API Management**.
3. Click **Create** and copy the generated key. (Do not share this key and do not create a non-encrypted copy of it.)

## Fetch Alert using an AQL

- Armis uses AQL syntax to query its database when presenting to the user meaningful information.
- As you navigate through the Armis GUI you will notice that in the top search bar an AQL string is created for each page displayed. By modifying the filters, the AQL changes accordingly.
- AQL syntax allows you to granularly choose sub-types of Armis alerts to ingest.
- If you have a fine-tuned alert that you want XSOAR to ingest through a fetch, type the AQL syntax in the top search bar.
