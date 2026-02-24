# ThreatZone Cortex XSOAR Integration Pack

Threat.Zone enrichments are adaptable and can seamlessly integrate into various playbooks, such as sandbox, static-scan, and CDR playbooks, along with incidents and related files marked as indicators for threat intelligence. The integration now supports URL submissions, granular report retrieval, and richer plan metadata coverage.

## Supported commands

- `tz-sandbox-upload-sample` — submit files for dynamic analysis with optional module toggles and execution controls.
- `tz-static-upload-sample` — perform static analysis of files without executing them in the sandbox.
- `tz-cdr-upload-sample` — sanitize files using ThreatZone CDR workflows.
- `tz-url-analysis` — submit URLs for detonation and reputation assessment.
- `tz-get-result` — retrieve the submission verdict alongside the raw ThreatZone response payload.
- `tz-get-indicator-result` — retrieve dynamic behaviour indicators via the dedicated endpoint.
- `tz-get-ioc-result` — retrieve Indicators of Compromise for a submission using the dedicated API endpoint.
- `tz-get-yara-result` — retrieve matched YARA rules using the dedicated API endpoint.
- `tz-get-artifact-result` — retrieve analysis artifacts generated during execution.
- `tz-get-config-result` — retrieve configuration extractor results exposed by ThreatZone.
- `tz-get-sanitized` — download the sanitized artifact generated during CDR processing.
- `tz-download-html-report` — fetch the rendered HTML report for a submission.
- `tz-check-limits` — inspect current plan quotas, enabled modules, and workspace metadata.

Use `tz-get-result details=true` to embed inline sections in the readable output, or call the dedicated commands when you need the enriched objects in context.

## Ready-to-Use Playbooks

- Analyze File - Sandbox - ThreatZone
- Analyze File - Static Scan - ThreatZone
- Sanitize File - CDR - ThreatZone
- Analyze URL - ThreatZone
