# Deprecation Notice

As part of our ongoing commitment to platform performance, reliability, and standardization, the four integrations and commands within the "Core" pack listed below will be officially deprecated in mid-January 2027:

- Indicators detection (Cortex Core - IOC)
- Investigation & Response (Cortex Core - IR)
- XQL Query Engine
- Cortex Platform - Core

## What this means for you

- **Existing custom playbooks:** Automations and playbooks currently using commands from these integrations will continue to function as expected. No existing workflows will abruptly break upon deprecation. We recommend migrating them to the native Cortex built-in commands, which offer higher execution performance and unified platform syntax.
- **Out-of-the-box Cortex playbooks:** All out-of-the-box playbooks shipped with the platform will be updated by Palo Alto Networks to use built-in commands natively. No action is required on your part for uncustomized, standard playbooks.
- **Maintenance and support:** Following the deprecation date, these integrations will no longer receive feature updates, enhancements, or bug fixes.

For detailed command-by-command replacement mappings and usage examples, please refer to the [Cortex Built-In Commands Guide](https://cortex-docs.paloaltonetworks.com/cortex-commands-guide), or see the [Command mapping](#command-mapping) section at the end of this page.

[Cortex XSIAM](https://www.paloaltonetworks.com/cortex/cortex-xsiam) is an intelligent data foundation, where high-quality telemetry across the security infrastructure, threat intelligence, external attack surface data and user response actions are ingested and integrated automatically. Unlike SIEM, Cortex XSIAM ingests granular data – not just alerts and logs – to fuel many layers of machine learning that automate critical threat detection and remediation steps downstream.

## What does this pack do?

The playbooks included in this pack help you respond to Cortex XSIAM alerts in a timely manner. They also help automate repetitive tasks associated with Cortex XSIAM alerts:

- Syncs and updates Cortex XSIAM alerts.
- Triggers a sub-playbook to handle each alert by type.
- Extracts and enriches all relevant indicators from the source alert.
- Hunts for related IOCs.
- Calculates the severity of the alert.
- Interacts with the analyst to choose a remediation path or close the incident as a false positive based on the gathered information and incident severity.
- Remediates the incident by blocking malicious indicators and isolating infected endpoints.
- Run XQL Queries as part of an automation, or in a playbook (consumes compute units).

![Cortex XSIAM Video](doc_files/XSIAM.png)

![T1036 - Masquerading](doc_files/T1036_-_Masquerading.png)

## Command mapping

The following tables map each command in the deprecated integrations to its Cortex built-in command. Argument names and output paths can differ between a command and its built-in replacement, so review the built-in command's arguments before migrating. See the [Cortex Built-In Commands Guide](https://cortex-docs.paloaltonetworks.com/cortex-commands-guide) for details.

### Indicators detection (Cortex Core - IOC)

| Deprecated command | Built-in command | Category |
|---|---|---|
| `core-iocs-push` | `pushIOCs` | indicators |
| `core-iocs-enable` | `enableIOCs` | indicators |
| `core-iocs-disable` | `disableIOCs` | indicators |

### Investigation & Response (Cortex Core - IR)

| Deprecated command | Built-in command | Category |
|---|---|---|
| `core-isolate-endpoint` | `isolateEndpoint` | endpoints |
| `core-unisolate-endpoint` | `unisolateEndpoint` | endpoints |
| `core-get-endpoints` | `getEndpoints` | endpoints |
| `core-endpoint-alias-change` | `setEndpointAlias` | endpoints |
| `core-get-distribution-versions` | `getDistributionVersions` | distributions |
| `core-create-distribution` | `createDistribution` | distributions |
| `core-get-distribution-url` | `getDistributionURL` | distributions |
| `core-get-create-distribution-status` | `getDistributionStatus` | distributions |
| `core-get-audit-management-logs` | `getAuditManagementLogs` | audit |
| `core-get-audit-agent-reports` | `getAuditAgentReports` | audit |
| `core-blocklist-files` | `addFileToBlocklist` | hash_exceptions |
| `core-allowlist-files` | `addFileToAllowlist` | hash_exceptions |
| `core-quarantine-files` | `quarantineFile` | files |
| `core-get-quarantine-status` | `getFileQuarantineStatus` | files |
| `core-restore-file` | `restoreFile` | files |
| `core-endpoint-scan` | `endpointScan` | endpoints |
| `core-endpoint-scan-abort` | `abortEndpointScan` | endpoints |
| `core-get-policy` | `getEndpointPolicy` | endpoints |
| `core-get-scripts` | `getScripts` | scripts |
| `core-delete-endpoints` | `deleteEndpoints` | endpoints |
| `core-get-endpoint-device-control-violations` | `getEndpointDeviceControlViolations` | endpoints |
| `core-retrieve-files` | `retrieveFiles` | endpoints |
| `core-retrieve-file-details` | `retrieveFileDetails` | actions |
| `core-get-script-metadata` | `getScriptMetadata` | scripts |
| `core-get-script-code` | `getScriptCode` | scripts |
| `core-action-status-get` | `getActionStatus` | actions |
| `core-run-script` | `scriptRun` | scripts |
| `core-run-snippet-code-script` | `runSnippetCodeScript` | scripts |
| `core-get-script-execution-status` | `getScriptExecutionStatus` | scripts |
| `core-get-script-execution-results` | `getScriptExecutionResults` | scripts |
| `core-get-script-execution-result-files` | `getScriptExecutionResultFiles` | scripts |
| `core-run-script-execute-commands` | `runScriptExecuteCommands` | scripts |
| `core-run-script-delete-file` | `runScriptDeleteFile` | scripts |
| `core-run-script-file-exists` | `runScriptFileExists` | scripts |
| `core-run-script-kill-process` | `runScriptKillProcess` | scripts |
| `endpoint` | `endpoint` | endpoints |
| `core-report-incorrect-wildfire` | `reportIncorrectWildfire` | files |
| `core-remove-allowlist-files` | `removeFileFromAllowlist` | hash_exceptions |
| `core-remove-blocklist-files` | `removeFileFromBlocklist` | hash_exceptions |
| `core-add-exclusion` | `addExclusion` | exclusions |
| `core-delete-exclusion` | `deleteExclusion` | exclusions |
| `core-get-exclusion` | `getExclusions` | exclusions |
| `core-get-cloud-original-alerts` | `getRawAlerts` | issues |
| `core-get-dynamic-analysis` | `getRawAlerts` | issues |
| `core-get-hash-analytics-prevalence` | `getHashAnalyticsPrevalence` | prevalence |
| `core-get-IP-analytics-prevalence` | `getIPAnalyticsPrevalence` | prevalence |
| `core-get-domain-analytics-prevalence` | `getDomainAnalyticsPrevalence` | prevalence |
| `core-get-process-analytics-prevalence` | `getProcessAnalyticsPrevalence` | prevalence |
| `core-get-registry-analytics-prevalence` | `getRegistryAnalyticsPrevalence` | prevalence |
| `core-get-cmd-analytics-prevalence` | `getCmdAnalyticsPrevalence` | prevalence |
| `core-add-endpoint-tag` | `addEndpointTag` | endpoints |
| `core-remove-endpoint-tag` | `removeEndpointTag` | endpoints |
| `core-list-users` | `getSystemUsers` | users |
| `core-list-risky-users` | `getRiskyUsers` | risk |
| `core-list-risky-hosts` | `getRiskyHosts` | risk |
| `core-list-user-groups` | `getUserGroups` | users |
| `core-script-run` | `scriptRun` | scripts |
| `core-terminate-process` | `terminateProcess` | endpoints |
| `core-terminate-causality` | `terminateCausality` | endpoints |
| `core-execute-command` | `runScriptExecuteCommands` | scripts |
| `core-add-indicator-rule` | `addIOCRule` | indicators |
| `core-get-contributing-event` | `getContributingEvents` | correlations |
| `core-block-ip` | `blockIPs` | endpoints |
| `core-get-asset-details` | `getAssets` | assets |

### XQL Query Engine

| Deprecated command | Built-in command | Category |
|---|---|---|
| `xdr-xql-generic-query` | `runXQLQuery` | xql |
| `xdr-xql-get-quota` | `getXQLQuota` | xql |
| `xdr-xql-get-query-results` | `getXQLQueryResults` | xql |
| `xdr-xql-file-event-query` | `runXQLFileEventQuery` | xql |
| `xdr-xql-process-event-query` | `runXQLProcessEventQuery` | xql |
| `xdr-xql-dll-module-query` | `runXQLDllModuleQuery` | xql |
| `xdr-xql-network-connection-query` | `runXQLNetworkConnectionQuery` | xql |
| `xdr-xql-registry-query` | `runXQLRegistryQuery` | xql |
| `xdr-xql-event-log-query` | `runXQLEventLogQuery` | xql |
| `xdr-xql-dns-query` | `runXQLDNSQuery` | xql |
| `xdr-xql-file-dropper-query` | `runXQLFileDropperQuery` | xql |
| `xdr-xql-process-instance-network-activity-query` | `runXQLProcessInstanceNetworkActivityQuery` | xql |
| `xdr-xql-process-causality-network-activity-query` | `runXQLProcessCausalityNetworkActivityQuery` | xql |

### Cortex Platform - Core

| Deprecated command | Built-in command | Category |
|---|---|---|
| `core-get-asset-details` | `getAssets` | assets |
| `core-get-asset-coverage-histogram` | `getAssetCoverageHistogram` | coverage |
| `core-get-asset-coverage` | `getAssetCoverage` | coverage |
| `core-get-issues` | `listIssues` | issues |
| `core-get-case-extra-data` | `getCases` | cases |
| `core-update-issue` | `updateIssue` | issues |
| `core-search-assets` | `getAssets` | assets |
| `core-search-asset-groups` | `getAssetGroup` | assets |
| `core-get-vulnerabilities` | `getVulnerabilities` | vulnerabilities |
| `core-get-issue-recommendations` | `getIssueRecommendations` | issues |
| `core-appsec-remediate-issue` | `appsecRemediateIssue` | appsec |
| `core-enable-scanners` | `enableScanners` | scanners |
| `core-create-appsec-policy` | `createAppSecPolicy` | appsecpolicies |
| `core-get-cases` | `getCases` | cases |
| `core-get-appsec-issues` | `getAppSecIssues` | appsec |
| `core-update-case` | `setCase` | cases |
| `core-get-endpoint-update-version` | `getEndpointUpdateVersion` | endpoints |
| `core-update-endpoint-version` | `setEndpointVersion` | endpoints |
