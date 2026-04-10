Cyware Threat Intelligence eXchange (CTIX) is an advanced threat intelligence platform (TIP) designed for the ingestion, enrichment, analysis, and bi-directional sharing of threat data across trusted information-sharing networks. CTIX supports end-to-end tactical and technical threat intelligence automation, enabling collaborative analysis and accelerated response to emerging threats.

The CTIX content pack includes the CTIX Enrichment Integration, which allows direct enrichment of Indicators of Compromise (IOCs) using the user-configured CTIX instance. This integration enriches IP addresses, URLs, domains, and file hashes, providing a complete enrichment suite for orchestration workflows across detection and response use cases.

# What does this pack do?

This pack provides XSOAR playbooks and CLI actions that support end-to-end enrichment and contextualization of threat intelligence indicators. It enables users to automate enrichment, validation, and intel lifecycle operations through CTIX.

Key capabilities include:

- Enrich indicators using CTIX's signature-based scoring algorithm.
- Contextualize IPs, domains, URLs, and file hashes with correlated intelligence from multiple data sources aggregated within CTIX.
- Manage indicator status across environments by checking whether an indicator is blocked, deprecated, or added to an allowed list on devices integrated with CTIX.
- Create intel records in CTIX (supported for CTIX v2.9.3 and above).

# For more information

- [Visit the CTIX website](https://www.cyware.com/products/threat-intelligence-platform-tip)
- [See the open-api page](https://ctixapiv3.cyware.com/intel-exchange-api-reference)
