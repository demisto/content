ThreatMon is a digital risk protection and threat intelligence platform. Its research and monitoring teams publish tens of thousands of Indicators of Compromise (IOCs) every day: malicious IP addresses, domains, URLs, file hashes, command and control servers and cryptocurrency wallets.

This pack brings the ThreatMon IOC feed into Cortex XSOAR and Cortex XSIAM, so the indicators can be used for enrichment, correlation, detection and blocking.

## What does this pack do?

- Ingests every ThreatMon IOC from the ThreatMon TAXII 2.1 server as Cortex indicators: IP addresses (with ports), domains, URLs, file hashes, C2 servers and cryptocurrency addresses.
- Reads every ThreatMon collection completely with TAXII 2.1 cursor paging, and resumes an interrupted fetch from the last saved page, so no indicator is missed.
- Corrects the indicator type of values that ThreatMon publishes in the wrong STIX type, for example `ip:port` values, URLs and Ethereum wallets published as domains.
- Adds the ThreatMon labels as tags and keeps the STIX ID, the first and last seen dates and the TLP marking of every indicator.
- Applies the configured reputation, source reliability and TLP color to every indicator.
- Runs incrementally: each fetch reads what ThreatMon published since the previous one, with a look-back window so late-published indicators are not missed, and without creating duplicates.
- Provides troubleshooting commands to list the collections, sample indicators and inspect or reset the fetch state.

## Content

| Item | Name |
| --- | --- |
| Integration | ThreatMon Threat Feed |

## Before you start

- A ThreatMon subscription with access to the IOC feed, and its **IOC API token**. This token is different from the External API Key of the ThreatMon Incident Management pack.
- Network access from the Cortex server or engine to `https://ioc.threatmonit.io`.

To bring ThreatMon alarms into Cortex as incidents, submit takedowns and enrich CVEs, also install the **ThreatMon Incident Management** pack.

## Support

Contact [support@threatmonit.io](mailto:support@threatmonit.io) or visit [threatmon.io](https://www.threatmon.io).
