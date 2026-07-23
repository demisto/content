# Tenable.sc Advanced Analysis

## Overview

Tenable.sc Advanced Analysis extends Cortex XSOAR vulnerability-management capabilities by providing direct access to detailed vulnerability information from the Tenable.sc Analysis API.

The integration is intended for reporting, remediation tracking, vulnerability enrichment, SLA monitoring, and other workflows that require more detailed information than standard vulnerability summaries.

## Key Capabilities

- Retrieve detailed vulnerability records from the Tenable.sc Analysis API.
- Filter findings by repository, severity, source type, First Seen, and Last Seen ranges.
- Support cumulative and individual vulnerability analysis.
- Retrieve vulnerability and asset details, including:
  - Plugin ID and plugin name
  - Plugin output
  - CVE information
  - Description and solution
  - IP address and DNS name
  - Repository
  - Port and protocol
  - First Discovered
  - Last Observed
  - Last Mitigated
  - Current vulnerability status
  - Previous mitigation history
- Retrieve large datasets using configurable pagination.
- Deduplicate records using plugin, asset, port, and protocol.
- Generate configurable SLA summaries by severity.
- Return total, within-SLA, and overdue vulnerability counts.
- Preserve UTC or epoch values for internal API calculations while providing human-readable date output.

## Commands

### tenable-sc-analysis-test

Tests connectivity to the Tenable.sc Analysis API and validates that analysis queries can be executed.

### tenable-sc-vulnerability-details

Retrieves detailed vulnerability information using configurable repository, severity, source-type, and date filters.

### tenable-sc-get-vulnerability-dataset

Retrieves a paginated and deduplicated vulnerability dataset for one or more repositories and severity levels.

The output can be used by Cortex XSOAR playbooks, dashboards, reporting automations, CSV-generation scripts, and enrichment workflows.

### tenable-sc-get-external-sla-summary

Generates vulnerability SLA statistics by severity.

The command returns:

- Total vulnerabilities
- Vulnerabilities within SLA
- Overdue vulnerabilities
- SLA threshold
- Repository and date-range information
- Last update time

SLA thresholds and vulnerability date ranges are configurable command arguments.

## Common Use Cases

- Daily, weekly, and monthly vulnerability reporting
- External vulnerability reporting
- Vulnerability remediation tracking
- SLA and overdue-finding monitoring
- Asset and vulnerability enrichment
- Vulnerability dashboards
- CSV report generation
- Email notification workflows
- Identification of active and previously mitigated findings

## Requirements

- A reachable Tenable.sc server
- A valid Tenable.sc access key and secret key
- Permission to access the required repositories
- Permission to query vulnerability analysis data
- Network connectivity between the Cortex XSOAR engine and Tenable.sc

## Configuration

Configure an integration instance with:

- Tenable.sc server URL
- Access key
- Secret key
- Certificate verification preference
- Request timeout

Repository IDs, severity filters, date ranges, page size, maximum pages, and SLA thresholds are supplied as command arguments.

## Security Considerations

- Store access and secret keys only in protected Cortex XSOAR credential fields.
- Use certificate verification in production.
- Apply least-privilege permissions to the Tenable.sc service account.
- Do not expose credentials, internal URLs, customer information, or confidential asset data in playbook outputs or logs.
- Validate repository access before using the integration in production reporting workflows.

## Limitations

- Results depend on the permissions assigned to the Tenable.sc account.
- Large repositories may require increased pagination and request timeout values.
- Tenable.sc cumulative and individual analysis views may return different result populations.
- SLA results depend on the configured First Seen and Last Seen ranges.
- The integration does not remediate or modify vulnerabilities; it retrieves and analyzes vulnerability information.

## Support

This is a community-supported integration.

Issues and improvement requests can be submitted through the Cortex XSOAR content contribution pull-request process.