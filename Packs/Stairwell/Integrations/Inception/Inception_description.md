## Stairwell Integration for Cortex XSOAR

Stairwell continuously collects, stores, and analyzes threat intelligence and artifacts in a private vault to accelerate security investigations.

### Key Capabilities
- Reanalyze files continuously as new threat intelligence is identified.
- Correlate threat and signal intelligence with your existing artifacts.
- Perform retrospective analysis to investigate alerts regardless of when they occurred.
- Identify file variants and hidden relationships across your environment.
- Gain definitive visibility into the presence or absence of specific files within your enterprise.

## Configuration

### Prerequisite
1. **API Key** — Obtain from Stairwell platform under Settings → API Keys.

### Optional Settings
- Select **Use system proxy settings** to leverage Cortex XSOAR proxy configuration.
- Select **Trust any certificate (not secure)** to skip verification of SSL certificates. This is not recommended for production environments.

> **Note:** For multi-line YARA rule definitions, use backticks (`` ` ``) instead of quotes to prevent parsing errors in the Cortex XSOAR CLI.

## Common Workflows

### File Analysis
1. Enrich file → `stairwell-file-enrichment`
2. Discover variants → `stairwell-variant-discovery`
3. Get AI analysis → `stairwell-ai-triage-summarize`
4. Check sightings → `stairwell-object-sightings`

### Threat Hunting
1. Create YARA rule → `stairwell-yara-create-rule`
2. Query matches → `stairwell-yara-query-matches`
3. Analyze matches → `stairwell-file-enrichment`

Not a customer? Request access at [stairwell.com/contact](https://stairwell.com/contact/).
