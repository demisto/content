# ClearAndReEnrichIndicatorsBySource

## Description

This script collects all indicators from a specific source (instance name), clears their source data, and then re-enriches them. This is useful for refreshing indicator data when you want to clear old enrichment data and get fresh results from threat intelligence sources.

## Use Cases

- Refresh indicator enrichment data after updating threat intelligence feeds
- Clear stale or incorrect enrichment data from a specific source
- Re-process indicators after fixing integration configuration issues
- Bulk refresh of indicators from a specific threat intelligence provider

## Script Flow

1. **Search Indicators**: Searches for all indicators that originated from the specified source
2. **Extract Values**: Extracts the indicator values from the search results
3. **Clear Source Data**: Executes `clearIndicatorSourceData` command to remove existing source data
4. **Re-enrich**: Executes `enrichIndicators` command to get fresh enrichment data

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| source | String | Yes | - | The name of the source/instance to collect indicators from |
| limit | Number | No | 1000 | Maximum number of indicators to process |

## Outputs

| Context Path | Type | Description |
|--------------|------|-------------|
| ClearAndReEnrichIndicatorsBySource.Source | String | The source name that was processed |
| ClearAndReEnrichIndicatorsBySource.ProcessedCount | Number | Number of indicators that were processed |
| ClearAndReEnrichIndicatorsBySource.IndicatorValues | Array | List of indicator values that were processed |
| ClearAndReEnrichIndicatorsBySource.ClearResult | Object | Result from the clearIndicatorSourceData command |
| ClearAndReEnrichIndicatorsBySource.EnrichResult | Object | Result from the enrichIndicators command |

## Example Usage

### Basic Usage

```
!ClearAndReEnrichIndicatorsBySource source="VirusTotal"
```

### With Custom Limit

```
!ClearAndReEnrichIndicatorsBySource source="ThreatGrid" limit=500
```

## Prerequisites

- The script requires permissions to execute the following commands:
  - `searchIndicators`
  - `clearIndicatorSourceData`
  - `enrichIndicators`
- The specified source must exist and have indicators associated with it

## Error Handling

The script includes comprehensive error handling for:

- Invalid or missing source parameter
- Failed indicator searches
- Command execution failures
- Empty result sets

## Notes

- The script processes indicators in batches based on the limit parameter
- All indicator values are logged for debugging purposes
- The script uses the DBotWeakRole for execution
- Progress is logged at each step for monitoring purposes
