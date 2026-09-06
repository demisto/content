## Darkmon Feed

Darkmon TIP indicator feed integration for Cortex XSOAR.

This is the **feed half** of the Darkmon pack: it ingests indicators (IOCs)
from the Darkmon Threat Intelligence Platform into XSOAR's Threat Intel
Management module on a configurable interval.

For incident-side functionality (incident fetching, dynamic search,
reputation commands, monitoring playbooks), see the companion **Darkmon**
integration in the same pack.

### What this integration does

- Continuously fetches the Darkmon IOC firehose (IPs, URLs, domains, file
  hashes, emails, accounts) into the XSOAR Threat Intel Management module.
- Tags each indicator with its Darkmon classification, first-seen,
  last-seen, compromise sources, and stealer family where available.
- Routes each indicator to the correct indicator type via the
  `Darkmon - Feed Classifier` and populates fields via the
  `Darkmon - Feed Mapper`.
- Exposes a debug command (`darkmon-get-indicators`) for testing the feed
  pull without waiting for the next scheduled cycle.

### Configuration

Paste your Darkmon TIP API key. The default API base URL points at the
Darkmon TIP production endpoint; override only if your tenant uses a
non-default endpoint. Set the feed reputation, source reliability, and
expiration policy per your SOC's standards.