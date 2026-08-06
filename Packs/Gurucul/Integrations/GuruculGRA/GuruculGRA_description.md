## Gurucul GRA

- Please contact Gurucul for getting APIKEY.
- Cases are no longer fetched. Use **Fetch type** = Incidents (default) or Alerts.
- After updating the pack from a Cases-only setup: disable fetch → set Classifier / Mapper / Incident type for Incidents (`GRAIncident-Classifier`, `GRAIncident-Mapper`, `GRAIncident`) → re-enable fetch. See the integration README upgrade section.
- Use a separate instance for Alerts (`GRAAlert-Classifier`, `GRAAlert-Mapper`, `GRAAlert`).
