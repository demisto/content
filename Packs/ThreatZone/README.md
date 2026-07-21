# ThreatZone Cortex XSOAR Integration Pack

Threat.Zone enrichments integrate into sandbox, static-scan, CDR, URL-analysis, and open-in-browser workflows. The integration uses the official ThreatZone Python SDK for configuration discovery, submissions, granular report and bounded telemetry retrieval, and streamed file downloads.

## Supported commands

- Configuration: discover metafields, sandbox environments, and workspace network configurations.
- Submission: submit sandbox, static, CDR, URL-analysis, and open-in-browser jobs; list submissions or search by SHA256.
- Results: retain the existing summary, indicator, IOC, matched-YARA, artifact, and extracted-config commands, plus dedicated SDK report sections for overview, EML, MITRE ATT&CK, static scan, CDR, signatures, processes, process tree, and URL analysis.
- Telemetry: retrieve bounded behaviour and syscall pages, network summaries, and bounded DNS, HTTP, TCP, UDP, and network-threat windows.
- Files: stream HTML, CDR, strings, original sample, artifact, PCAP, and generated-YARA downloads; retrieve URL screenshots and analysis media.
- Account: inspect current plan quotas, enabled modules, and workspace metadata.

Use `tz-get-result details=true` for the existing inline sections, or call the dedicated commands for the additional SDK reports and telemetry. Existing command names, polling semantics, and context paths remain compatible.

## Ready-to-Use Playbooks

- Analyze File - Sandbox - ThreatZone
- Analyze File - Static Scan - ThreatZone
- Sanitize File - CDR - ThreatZone
- Analyze URL - ThreatZone
