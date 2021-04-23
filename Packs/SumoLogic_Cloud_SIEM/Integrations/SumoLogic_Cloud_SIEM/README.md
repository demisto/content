The integration in this pack enables interactions with Sumo Logic Cloud SIEM. It can be used to fetch Incidents via Insights, update status of an Insight, add items to match list, search Entities/Signals/Insights/Threat Intel indicators, and more.

## What does this pack do?
This pack enables you to run commands that:
- Fetch Incidents via Insights
- Search Entities, Signals, Insights and Threat Intel indicators
- Change status of Insight
- Get Insight comments
- Add items to match list
- Add Threat Intel Indicators to Threat Intel Sources

## Prerequisites
Only use this integration if your Cloud SIEM portal url ends with `.sumologic.net` - this can be verified via the url in your browser when logged into Cloud SIEM.

You'll need an access key in order to complete the instance setup. Instructions on how to generate access keys can be found [here](https://help.sumologic.com/Manage/Security/Access-Keys).

## API documentation and query examples

For commands with query parameter input the available fields and operators are documented in API docs. These docs are useful when executing queries using the following commands:
- `sumologic-sec-insight-search`
- `sumologic-sec-signal-search`
- `sumologic-sec-entity-search`

To access the API documentation, select the link for your deployment from [here](https://help.sumologic.com/APIs#documentation). Add `sec` to the end of the url to access Cloud SIEM API docs - e.g. `https://api.us2.sumologic.com/docs/sec/`.

Example: Insight search query ['q' parameter](https://api.us2.sumologic.com/docs/sec/#/paths/~1insights/get): 

> The search query string in our custom DSL that is used to filter the results.
> 
> Operators:
> - `exampleField:"bar"`: The value of the field is equal to "bar".
> - `exampleField:in("bar", "baz", "qux")`: The value of the field > is equal to either "bar", "baz", or "qux".
> - `exampleTextField:contains("foo bar")`: The value of the field > contains the phrase "foo bar".
> - `exampleNumField:>5`: The value of the field is greater than 5. There are similar `<`, `<=`, and `>=` operators.
> - `exampleNumField:5..10`: The value of the field is between 5 and 10 (inclusive).
> - `exampleDateField:>2019-02-01T05:00:00+00:00`: The value of the date field is after 5 a.m. UTC time on February 2, 2019.
> - `exampleDateField:2019-02-01T05:00:00+00:00..2019-02-01T08:00:00+00:00`: The value of the date field is between 5 a.m. and 8 a.m. UTC time on February 2, 2019.
> 
> Fields:
> - `id`
> - `readableId`
> - `status`
> - `name`
> - `insightId`
> - `description`
> - `created`
> - `timestamp`
> - `closed`
> - `assignee`
> - `entity.ip`
> - `entity.hostname`
> - `entity.username`
> - `entity.type`
> - `enrichment`
> - `tag`
> - `severity`
> - `resolution`
> - `ruleId`
> - `records`

## Migrating from JASK content pack

The table below shows differences between this integration and the legacy JASK integration:

| JASK (legacy) | Sumo Logic Cloud SIEM | Notes |
| - | - | - |
| jask-get-insight-details | sumologic-sec-insight-get-details | |
| jask-get-insight-comments | sumologic-sec-insight-get-comments | |
| jask-get-signal-details | sumologic-sec-signal-get-details | |
| jask-get-entity-details | sumologic-sec-entity-get-details | |
| ~~jask-get-related-entities~~ | | Depreacted |
| ~~jask-get-whitelisted-entities~~ | | Deprecated - use command `sumologic-sec-entity-search` with filter `whitelisted:"true"` |
| jask-search-insights | sumologic-sec-insight-search | |
| jask-search-entities | sumologic-sec-entity-search | |
| jask-search-signals | sumologic-sec-signal-search | |

### New commands introduced in Sumo Logic Cloud SIEM pack

 - `sumologic-sec-insight-set-status`
 - `sumologic-sec-match-list-get`
 - `sumologic-sec-match-list-update`
 - `sumologic-sec-threat-intel-search-indicators`
 - `sumologic-sec-threat-intel-get-sources`
 - `sumologic-sec-threat-intel-update-source`