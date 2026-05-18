# Proofpoint Cloud Threat Response

Proofpoint Cloud Threat Response (CTR) is the cloud-based alternative to Proofpoint TRAP (Threat Response Auto-Pull). It automates post-detection incident response and remediation tasks.

## What does this pack do?

- Fetches Proofpoint Cloud Threat Response incidents into Cortex XSOAR for case management.
- Lists and filters incidents by source, verdict, disposition, confidence, state, time range, or specific IDs.
- Retrieves detailed metadata (activities, summary, dispositions) for a specific incident.

## Use Cases

- **Case management**: Fetch CTR incidents in order to work them inside Cortex XSOAR. Closure of incidents is performed in the CTR UI (the CTR API does not currently expose a close-incident endpoint).
