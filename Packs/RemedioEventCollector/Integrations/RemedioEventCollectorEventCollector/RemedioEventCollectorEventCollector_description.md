## Remedio Event Collector

Fetches all active misconfigurations from the Remedio Customer API and ingests them into XSIAM.

### Configuration

- **Server URL** — Your Remedio tenant URL (e.g., `https://acme.gytpol.com`)
- **API Key** — Generated from the Remedio portal (Settings > API Keys) with read access to the Customer API
- **Maximum misconfigurations per fetch** — Leave empty to fetch all. Set a number to cap results per run.

### Notes

- Each fetch performs a full snapshot of all active misconfigurations.
- Configure the fetch interval to run 1–2 times per day.

### Datasets

| Name | Dataset |
|------|---------|
| Misconfigurations | `remedio_misconfigurations_raw` |
