## Gurucul GRA

- Contact Gurucul support to obtain an API key for this integration.
- Cases are no longer fetched. Set **Fetch type** to Incidents or Alerts. Use a **separate instance** for each type.
- Leave **Classifier** as **None / Select**.
- **Incidents** instance: Fetch type Incidents, Incident type **GRAIncident**, Mapper (incoming) **GRAIncident-Mapper**.
- **Alerts** instance: Fetch type Alerts, Incident type **GRAAlert**, Mapper (incoming) **GRAAlert-Mapper**.
- After updating from a Cases-only setup: disable fetch, set the Incidents values above (Classifier still None / Select), then re-enable fetch.
- Incident and Alert fields use Data Source (GRA JSON key `datasourcename` on those APIs). Deprecated Resource account commands remain; prefer the Data Source replacements.
- **GRA server timezone** (fetch only): Set the timezone of the GRA server (IANA id). Default **UTC**. Not used for First fetch time.
