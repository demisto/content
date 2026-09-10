## Gurucul GRA

- This integration requires **GRA 14.5.0** or later.
- Contact Gurucul support to obtain an API key for this integration.
- Cases are no longer fetched. Set **Fetch type** to Incidents or Alerts. Use a **separate instance** for each type.
- Fetch imports incidents with statuses: Open, Reopened, In Progress, and On Hold.
- Fetch imports alerts with Open status only.
- **Incidents** instance: Set **Fetch type** to Incidents, **Classifier** to None / Select, **Incident type** to **GRAIncident**, and **Mapper (incoming)** to **GRAIncident-Mapper**.
- **Alerts** instance: Set **Fetch type** to Alerts, **Classifier** to None / Select, **Incident type** to **GRAAlert**, and **Mapper (incoming)** to **GRAAlert-Mapper**.
- If **Do not use by default** is unchecked, War Room commands with no `using` run on this instance and every other default-enabled instance. Check **Do not use by default** on all instances.
- After updating from a Cases-only setup: disable fetch, set the Incidents values above (Classifier still None / Select), then re-enable fetch.
- Incident and Alert fields use Data Source (GRA JSON key `datasourcename` on those APIs). Deprecated Resource account commands remain; prefer the Data Source replacements.
- **GRA server timezone** (fetch only): Set the timezone of the GRA server (IANA id). Default **UTC**. Not used for First fetch time.
