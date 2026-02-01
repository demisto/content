Unit 42 Feed integration provides threat intelligence from Palo Alto Networks Unit 42 research team.

## Configure Unit 42 Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators | Select this check box to fetch indicators \(default selected\). | True |
| Feed Types | Choose the requested indicator feeds. Indicators feed and Threat Objects \(actors, malware, campaigns, techniques, etc.\) feed \(default is both\). | True |
| Indicator Types | Comma-separated list of indicator types to fetch \(File, IP, URL, Domain\). If not specified, all indicator types are fetched. | False |
| Source Reliability | Reliability of the source providing the intelligence context. | True |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color (TLP). | The Traffic Light Protocol \(TLP\) designation is to apply to indicators fetched from the feed. | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | True |
| Feed Expiration Policy | The feed's expiration policy. | True |
| Indicator Expiration Interval | The indicator's expiration policy. | False |
| Create relationships | Create relationships with other indicators. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## How the Limit Parameter Works

The **Limit** parameter controls the maximum number of indicators fetched per type during each fetch cycle. The integration enforces a total limit of **100,000 indicators** across all types to ensure optimal performance.

### Limit Calculation Algorithm

The limit per type is calculated using the following logic:

1. **If limit is not specified or is negative**:
   - Default limit per type = `100,000 / total_number_of_types`

2. **If limit × total_number_of_types > 100,000**:
   - Adjusted limit per type = `100,000 / total_number_of_types`

3. **Otherwise**:
   - Use the specified limit per type

### Examples

#### Example 1: No Limit Specified with 4 Types

- **Configuration**: Threat Objects + 3 indicator types (IP, Domain, URL)
- **Total types**: 4
- **Calculation**: `100,000 / 4 = 25,000` per type
- **Result**: Fetches up to 25,000 of each type (100,000 total)

#### Example 2: Limit Exceeds Total

- **Configuration**: Limit = 30,000, with 4 types selected
- **Calculation**: `30,000 × 4 = 120,000 > 100,000` (exceeds total limit)
- **Adjusted**: `100,000 / 4 = 25,000` per type
- **Result**: Fetches up to 25,000 of each type (100,000 total)

#### Example 3: Limit Within Total

- **Configuration**: Limit = 20,000, with 4 types selected
- **Calculation**: `20,000 × 4 = 80,000 ≤ 100,000` (within total limit)
- **Result**: Fetches up to 20,000 of each type (80,000 total)

#### Example 4: Single Type

- **Configuration**: Limit not specified, only IP indicators selected
- **Total types**: 1
- **Calculation**: `100,000 / 1 = 100,000` per type
- **Result**: Fetches up to 100,000 IP indicators

### Fetch Priority Order

When multiple types are configured, the integration fetches in the following priority order:

1. **Threat Objects** (if enabled)
2. **IP** indicators
3. **Domain** indicators
4. **URL** indicators
5. **File** indicators

If any type returns fewer indicators than its allocated limit, the unused quota is added to the last type in the priority order, allowing it to fetch additional indicators up to the total limit of 100,000.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### unit42-get-indicators

***
Gets indicators from the feed.

#### Base Command

`unit42-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_types | Comma-separated list of indicator types to fetch (File, IP, URL, Domain). If not specified, all indicator types are fetched. Possible values are: File, IP, URL, Domain. Default is File,IP,URL,Domain. | Optional |
| limit | The maximum number of indicators to return. The default is 10. The maximum is 5000. Default is 10. | Optional |

#### Context Output

There is no context output for this command.

### unit42-get-threat-objects

***
Gets threat objects from the feed.

#### Base Command

`unit42-get-threat-objects`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of threat objects to return. The default is 10. The maximum is 5000. Default is 10. | Optional |

#### Context Output

There is no context output for this command.
