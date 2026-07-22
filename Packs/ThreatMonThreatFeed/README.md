# ThreatMon Threat Feed

Threatmon is a threat intelligence platform that publishes Indicators of Compromise (IOCs) collected from its own research and monitoring capabilities.

This pack contains the **Threatmon Threat Feed** integration, which periodically pulls IOCs from the Threatmon IOC API and creates them as indicators in Cortex XSOAR, so they can be used for enrichment, correlation and detection.

## What does this pack do?

- Ingests IP, domain, URL and file hash indicators from the Threatmon IOC platform.
- Enriches every indicator with the Threatmon metadata, such as severity, confidence level, ISP, geolocation, resolved IPs, categories and tags.
- Lets you narrow the fetch down to a specific IOC type, or to specific Threatmon collections.
- Applies the configured reputation, source reliability and TLP color to every ingested indicator.

The feed is incremental, so each run only ingests indicators that Threatmon published after the previous run.

## Requirements

- A Threatmon account with access to the IOC API.
- A Threatmon API token.
- Network connectivity from your Cortex XSOAR engine to the Threatmon IOC API.

---

This pack is community supported. For questions about the Threatmon platform or your API token, contact the Threatmon team at [integration@threatmonit.io](mailto:integration@threatmonit.io).
