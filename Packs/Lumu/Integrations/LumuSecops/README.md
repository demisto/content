SecOps operations for the new Lumu Defender API. Fetch, investigate, and manage Lumu incidents from Cortex XSOAR with bidirectional mirroring.
This integration was integrated and tested with version xx of LumuSecops.

## Configure Lumu Secops in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The URL of the Public Lumu Defender Base URL. | True |
| Use system proxy settings | Whether to use the system proxy settings for network requests. | False |
| Trust any certificate (not secure) | Whether to trust any SSL certificate, even if it is not secure. | False |
| Password | The API key used to authenticate with the Lumu Defender API. | True |
| Lumu incident fetch offset | The offset to start fetching Lumu incidents from. | False |
| Size of Lumu incident records per Lumu fetch | The number of Lumu incident records to fetch per request. | False |
| Max Seconds waiting for fetching Lumu incidents | The maximum number of seconds to wait for fetching Lumu incidents. | False |
| Fetch incidents |  | False |
| Incident type | The incident type for Lumu SecOps incidents. | False |
| Incidents Fetch Interval | The interval in minutes at which to fetch Lumu incidents. | False |
| Mirror tags | Comments and files tagged with this value are mirrored to Lumu. | False |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from Lumu to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to Lumu\), or Incoming and Outgoing \(from/to Cortex XSOAR and Lumu\). Cortex XSOAR only parameter. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### lumusecops-retrieve-labels

***
Gets a paginated list of all the labels created for the company and its details such as ID, name, and business relevance. The items are sorted by the label ID in ascending order.

#### Base Command

`lumusecops-retrieve-labels`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page requested. | Optional |
| limit | The items limit requested. Default is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.RetrieveLabels.labels.id | Number | The label ID. |
| LumuSecops.RetrieveLabels.labels.name | String | The label name. |
| LumuSecops.RetrieveLabels.labels.relevance | Number | The label relevance. |
| LumuSecops.RetrieveLabels.paginationInfo.page | Number | The current page. |
| LumuSecops.RetrieveLabels.paginationInfo.items | Number | The current items. |
| LumuSecops.RetrieveLabels.paginationInfo.next | Number | The next page. |
| LumuSecops.RetrieveLabels.paginationInfo.prev | Number | The previous page. |

#### Command example

```!lumusecops-retrieve-labels```

#### Context Example

```json
{
    "LumuSecops": {
        "RetrieveLabels": {
            "labels": [
                {
                    "id": 51,
                    "name": "Mi Ofi",
                    "relevance": 1
                },
                {
                    "id": 112,
                    "name": "Lab1",
                    "relevance": 1
                },
                {
                    "id": 113,
                    "name": "Lab2",
                    "relevance": 1
                },
                {
                    "id": 134,
                    "name": "cd test",
                    "relevance": 1
                },
                {
                    "id": 147,
                    "name": "cd",
                    "relevance": 1
                },
                {
                    "id": 173,
                    "name": "VA 3.1.2 Test",
                    "relevance": 1
                },
                {
                    "id": 218,
                    "name": "acastaneda",
                    "relevance": 1
                },
                {
                    "id": 227,
                    "name": "VA 1.3.3 Label",
                    "relevance": 1
                },
                {
                    "id": 280,
                    "name": "client test",
                    "relevance": 1
                },
                {
                    "id": 331,
                    "name": "VA 3.1.3",
                    "relevance": 1
                }
            ],
            "paginationInfo": {
                "items": 10,
                "next": 2,
                "page": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Labels
>
>| Id  | Name           | Relevance |
>| --- | -------------- | --------- |
>| 51  | Mi Ofi         | 1         |
>| 112 | Lab1           | 1         |
>| 113 | Lab2           | 1         |
>| 134 | cd test        | 1         |
>| 147 | cd             | 1         |
>| 173 | VA 3.1.2 Test  | 1         |
>| 218 | acastaneda     | 3         |
>| 227 | VA 1.3.3 Label | 1         |
>| 280 | client test    | 1         |
>| 331 | VA 3.1.3       | 1         |
>
>### paginationInfo
>
>|Items|Next|Page|
>|---|---|---|
>| 10 | 2 | 1 |

### lumusecops-retrieve-a-specific-label

***
Gets details such as id, name and business relevance from a specific label.

#### Base Command

`lumusecops-retrieve-a-specific-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label_id | The label ID requested. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.RetrieveASpecificLabel.id | Number | The label ID. |
| LumuSecops.RetrieveASpecificLabel.name | String | The label name. |
| LumuSecops.RetrieveASpecificLabel.relevance | Number | The label relevance. |

#### Command example

```!lumusecops-retrieve-a-specific-label label_id=51```

#### Context Example

```json
{
    "LumuSecops": {
        "RetrieveASpecificLabel": {
            "id": 51,
            "name": "Mi Ofi",
            "relevance": 1
        }
    }
}
```

#### Human Readable Output

>### Label
>
>|Id|Name|Relevance|
>|---|---|---|
>| 51 | Mi Ofi | 1 |

### lumusecops-get-all-incidents

***
Gets a paginated list of all incidents.

#### Base Command

`lumusecops-get-all-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number. | Optional |
| items | The number of incidents per page. | Optional |
| status | The incident status filter values: open, muted, closed. | Optional |
| adversary_types | The adversary type filter values. | Optional |
| labels | The label ID filter values. | Optional |
| from_date | The start date/time filter in ISO 8601 format. | Optional |
| to_date | The end date/time filter in ISO 8601 format. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetAllIncidents.id | String | The incident ID. |
| LumuSecops.GetAllIncidents.statusTimestamp | Date | The date the incident status was updated in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetAllIncidents.status | String | The incident status. |
| LumuSecops.GetAllIncidents.timestamp | Date | The date the incident was created in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetAllIncidents.detectorType | String | The detector type. |
| LumuSecops.GetAllIncidents.incidentType | String | The incident type category. |
| LumuSecops.GetAllIncidents.totalEvents | Number | The total number of events. |
| LumuSecops.GetAllIncidents.firstEvent.timestamp | Date | The date the first related event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetAllIncidents.firstEvent.id | String | The first related event ID. |
| LumuSecops.GetAllIncidents.lastEvent.timestamp | Date | The date the last related event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetAllIncidents.lastEvent.id | String | The last related event ID. |
| LumuSecops.GetAllIncidents.adversaryTypes | String | The adversary types associated with the incident. |
| LumuSecops.GetAllIncidents.description | String | The incident description. |
| LumuSecops.GetAllIncidents.eventsGroupingsCount | Number | The number of event groupings. |
| LumuSecops.GetAllIncidents.incidentGroupingFields.adversary | String | The grouping adversary value. |
| LumuSecops.GetAllIncidents.incidentGroupingFields.src_ip | String | The source IP from grouping fields. |
| LumuSecops.GetAllIncidents.incidentGroupingFields.src_label | String | The source label from grouping fields. |
| LumuSecops.GetAllIncidents.incidentGroupingFields.domain | String | The domain from grouping fields. |
| LumuSecops.GetAllIncidents.incidentGroupingFields.user_name | String | The username from grouping fields. |
| LumuSecops.GetAllIncidents.counts.totalTargetsCount | Number | The total number of targets. |
| LumuSecops.GetAllIncidents.counts.endpointTargetsCount | Number | The total endpoint targets. |
| LumuSecops.GetAllIncidents.counts.userTargetsCount | Number | The total user targets. |
| LumuSecops.GetAllIncidents.counts.otherTargetsCount | Number | The total other targets. |
| LumuSecops.GetAllIncidents.counts.offendersCount | Number | The total number of offenders. |
| LumuSecops.GetAllIncidents.environmentStats | Unknown | The environment stats collection. |
| LumuSecops.GetAllIncidents.environmentStats.environment.id | String | The environment ID. |
| LumuSecops.GetAllIncidents.environmentStats.environment.type | String | The environment type. |
| LumuSecops.GetAllIncidents.environmentStats.count | Number | The event count per environment. |
| LumuSecops.GetAllIncidents.offendersSamples._id | String | The offender sample identifier. |
| LumuSecops.GetAllIncidents.offendersSamples.type | String | The offender sample type. |
| LumuSecops.GetAllIncidents.offendersSamples.name | String | The offender sample name. |
| LumuSecops.GetAllIncidents.offendersSamples.value | String | The offender sample value. |
| LumuSecops.GetAllIncidents.offendersSamples.endpoint_ip | String | The offender sample endpoint IP. |
| LumuSecops.GetAllIncidents.offendersSamples.label | String | The offender sample label. |
| LumuSecops.GetAllIncidents.targetsSamples._id | String | The target sample identifier. |
| LumuSecops.GetAllIncidents.targetsSamples.type | String | The target sample type. |
| LumuSecops.GetAllIncidents.targetsSamples.name | String | The target sample name. |
| LumuSecops.GetAllIncidents.targetsSamples.value | String | The target sample value. |
| LumuSecops.GetAllIncidents.targetsSamples.endpoint_ip | String | The target sample endpoint IP. |
| LumuSecops.GetAllIncidents.targetsSamples.label | String | The target sample label. |
| LumuSecops.GetAllIncidents.targetsSamples.realm | String | The target sample realm. |
| LumuSecops.GetAllIncidents.lastAssignee | Number | The last assignee user ID. |
| LumuSecops.GetAllIncidents.autopilotOperation | Unknown | The autopilot operation metadata. |
| LumuSecops.GetAllIncidents.integrationsThatResponded | Unknown | The integrations that responded. |
| LumuSecops.GetAllIncidents.builtInResponseTypes | Unknown | The built-in response types. |
| LumuSecops.GetAllIncidents.accumulators | Unknown | The aggregation accumulator collection. |
| LumuSecops.GetAllIncidents.accumulators.type | String | The accumulator type. |
| LumuSecops.GetAllIncidents.accumulators.key | String | The accumulator key. |
| LumuSecops.GetAllIncidents.accumulators.value | Number | The accumulator value. |
| LumuSecops.GetAllIncidents.unread | Boolean | The indicator of whether the incident is unread. |
| LumuSecops.GetAllIncidents.hasPlaybackEvents | Boolean | The indicator of whether playback events exist. |

### lumusecops-get-open-incidents

***
Gets a paginated list of open incidents.

#### Base Command

`lumusecops-get-open-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number. | Optional |
| items | The number of incidents per page. | Optional |
| adversary_types | The comma-separated list of adversary type values. | Optional |
| labels | The comma-separated list of label IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetOpenIncidents.id | String | The incident ID. |
| LumuSecops.GetOpenIncidents.statusTimestamp | Date | The date the incident status was last updated in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetOpenIncidents.status | String | The incident status. |
| LumuSecops.GetOpenIncidents.timestamp | Date | The date the incident was created in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetOpenIncidents.detectorType | String | The detector type. |
| LumuSecops.GetOpenIncidents.incidentType | String | The incident type category. |
| LumuSecops.GetOpenIncidents.totalEvents | Number | The total number of events. |
| LumuSecops.GetOpenIncidents.firstEvent.timestamp | Date | The date the first related event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetOpenIncidents.firstEvent.id | String | The first related event ID. |
| LumuSecops.GetOpenIncidents.lastEvent.timestamp | Date | The date the last related event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetOpenIncidents.lastEvent.id | String | The last related event ID. |
| LumuSecops.GetOpenIncidents.description | String | The incident description. |
| LumuSecops.GetOpenIncidents.adversaryTypes | String | The adversary types associated with the incident. |
| LumuSecops.GetOpenIncidents.incidentGroupingFields.adversary | String | The grouping adversary value. |
| LumuSecops.GetOpenIncidents.environmentStats.environment.id | String | The environment ID. |
| LumuSecops.GetOpenIncidents.environmentStats.environment.type | String | The environment type. |
| LumuSecops.GetOpenIncidents.environmentStats.count | Number | The event count per environment. |
| LumuSecops.GetOpenIncidents.counts.endpointTargetsCount | Number | The total endpoint targets. |
| LumuSecops.GetOpenIncidents.counts.userTargetsCount | Number | The total user targets. |
| LumuSecops.GetOpenIncidents.counts.otherTargetsCount | Number | The total other targets. |
| LumuSecops.GetOpenIncidents.counts.totalTargetsCount | Number | The total number of targets. |
| LumuSecops.GetOpenIncidents.counts.offendersCount | Number | The total number of offenders. |
| LumuSecops.GetOpenIncidents.offendersSamples._id | String | The offender sample identifier. |
| LumuSecops.GetOpenIncidents.offendersSamples.type | String | The offender sample type. |
| LumuSecops.GetOpenIncidents.offendersSamples.value | String | The offender sample value. |
| LumuSecops.GetOpenIncidents.targetsSamples._id | String | The target sample identifier. |
| LumuSecops.GetOpenIncidents.targetsSamples.type | String | The target sample type. |
| LumuSecops.GetOpenIncidents.targetsSamples.label | String | The target sample label. |
| LumuSecops.GetOpenIncidents.targetsSamples.name | String | The target sample name. |
| LumuSecops.GetOpenIncidents.targetsSamples.endpoint_ip | String | The target sample endpoint IP. |
| LumuSecops.GetOpenIncidents.lastAssignee | Number | The last assignee user ID. |
| LumuSecops.GetOpenIncidents.autopilotOperation | Unknown | The autopilot operation metadata. |
| LumuSecops.GetOpenIncidents.integrationsThatResponded | Unknown | The integrations that responded. |
| LumuSecops.GetOpenIncidents.builtInResponseTypes | Unknown | The built-in response types. |
| LumuSecops.GetOpenIncidents.accumulators.type | String | The accumulator type. |
| LumuSecops.GetOpenIncidents.accumulators.key | String | The accumulator key. |
| LumuSecops.GetOpenIncidents.accumulators.value | Number | The accumulator value. |
| LumuSecops.GetOpenIncidents.eventsGroupingsCount | Number | The number of event groupings. |
| LumuSecops.GetOpenIncidents.unread | Boolean | The indicator of whether the incident is unread. |
| LumuSecops.GetOpenIncidents.hasPlaybackEvents | Boolean | The indicator of whether playback events exist. |

### lumusecops-get-muted-incidents

***
Gets a paginated list of muted incidents.

#### Base Command

`lumusecops-get-muted-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number. | Optional |
| items | The number of incidents per page. | Optional |
| adversary_types | The comma-separated list of adversary type values. | Optional |
| labels | The comma-separated list of label IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetMutedIncidents.id | String | The incident ID. |
| LumuSecops.GetMutedIncidents.statusTimestamp | Date | The date the incident status was last updated in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetMutedIncidents.status | String | The incident status. |
| LumuSecops.GetMutedIncidents.timestamp | Date | The date the incident was created in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetMutedIncidents.detectorType | String | The detector type. |
| LumuSecops.GetMutedIncidents.incidentType | String | The incident type category. |
| LumuSecops.GetMutedIncidents.totalEvents | Number | The total number of events. |
| LumuSecops.GetMutedIncidents.firstEvent.timestamp | Date | The date the first related event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetMutedIncidents.firstEvent.id | String | The first related event ID. |
| LumuSecops.GetMutedIncidents.lastEvent.timestamp | Date | The date the last related event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetMutedIncidents.lastEvent.id | String | The last related event ID. |
| LumuSecops.GetMutedIncidents.description | String | The incident description. |
| LumuSecops.GetMutedIncidents.adversaryTypes | String | The adversary types associated with the incident. |
| LumuSecops.GetMutedIncidents.incidentGroupingFields.adversary | String | The grouping adversary value. |
| LumuSecops.GetMutedIncidents.environmentStats.environment.id | String | The environment ID. |
| LumuSecops.GetMutedIncidents.environmentStats.environment.type | String | The environment type. |
| LumuSecops.GetMutedIncidents.environmentStats.count | Number | The event count per environment. |
| LumuSecops.GetMutedIncidents.counts.endpointTargetsCount | Number | The total endpoint targets. |
| LumuSecops.GetMutedIncidents.counts.userTargetsCount | Number | The total user targets. |
| LumuSecops.GetMutedIncidents.counts.otherTargetsCount | Number | The total other targets. |
| LumuSecops.GetMutedIncidents.counts.totalTargetsCount | Number | The total number of targets. |
| LumuSecops.GetMutedIncidents.counts.offendersCount | Number | The total number of offenders. |
| LumuSecops.GetMutedIncidents.offendersSamples._id | String | The offender sample identifier. |
| LumuSecops.GetMutedIncidents.offendersSamples.type | String | The offender sample type. |
| LumuSecops.GetMutedIncidents.offendersSamples.value | String | The offender sample value. |
| LumuSecops.GetMutedIncidents.targetsSamples._id | String | The target sample identifier. |
| LumuSecops.GetMutedIncidents.targetsSamples.type | String | The target sample type. |
| LumuSecops.GetMutedIncidents.targetsSamples.label | String | The target sample label. |
| LumuSecops.GetMutedIncidents.targetsSamples.name | String | The target sample name. |
| LumuSecops.GetMutedIncidents.targetsSamples.endpoint_ip | String | The target sample endpoint IP. |
| LumuSecops.GetMutedIncidents.lastAssignee | Number | The last assignee user ID. |
| LumuSecops.GetMutedIncidents.autopilotOperation | Unknown | The autopilot operation metadata. |
| LumuSecops.GetMutedIncidents.integrationsThatResponded | Unknown | The integrations that responded. |
| LumuSecops.GetMutedIncidents.builtInResponseTypes | Unknown | The built-in response types. |
| LumuSecops.GetMutedIncidents.accumulators.type | String | The accumulator type. |
| LumuSecops.GetMutedIncidents.accumulators.key | String | The accumulator key. |
| LumuSecops.GetMutedIncidents.accumulators.value | Number | The accumulator value. |
| LumuSecops.GetMutedIncidents.eventsGroupingsCount | Number | The number of event groupings. |
| LumuSecops.GetMutedIncidents.unread | Boolean | The indicator of whether the incident is unread. |
| LumuSecops.GetMutedIncidents.hasPlaybackEvents | Boolean | The indicator of whether playback events exist. |

### lumusecops-get-closed-incidents

***
Gets a paginated list of closed incidents.

#### Base Command

`lumusecops-get-closed-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number. | Optional |
| items | The number of incidents per page. | Optional |
| adversary_types | The comma-separated list of adversary type values. | Optional |
| labels | The comma-separated list of label IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetClosedIncidents.id | String | The incident ID. |
| LumuSecops.GetClosedIncidents.statusTimestamp | Date | The date the incident status was last updated in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetClosedIncidents.status | String | The incident status. |
| LumuSecops.GetClosedIncidents.timestamp | Date | The date the incident was created in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetClosedIncidents.detectorType | String | The detector type. |
| LumuSecops.GetClosedIncidents.incidentType | String | The incident type category. |
| LumuSecops.GetClosedIncidents.totalEvents | Number | The total number of events. |
| LumuSecops.GetClosedIncidents.firstEvent.timestamp | Date | The date the first related event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetClosedIncidents.firstEvent.id | String | The first related event ID. |
| LumuSecops.GetClosedIncidents.lastEvent.timestamp | Date | The date the last related event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetClosedIncidents.lastEvent.id | String | The last related event ID. |
| LumuSecops.GetClosedIncidents.description | String | The incident description. |
| LumuSecops.GetClosedIncidents.adversaryTypes | String | The adversary types associated with the incident. |
| LumuSecops.GetClosedIncidents.incidentGroupingFields.src_ip | String | The source IP from grouping fields. |
| LumuSecops.GetClosedIncidents.incidentGroupingFields.src_label | String | The source label from grouping fields. |
| LumuSecops.GetClosedIncidents.environmentStats.environment.id | String | The environment ID. |
| LumuSecops.GetClosedIncidents.environmentStats.environment.type | String | The environment type. |
| LumuSecops.GetClosedIncidents.environmentStats.count | Number | The event count per environment. |
| LumuSecops.GetClosedIncidents.counts.endpointTargetsCount | Number | The total endpoint targets. |
| LumuSecops.GetClosedIncidents.counts.userTargetsCount | Number | The total user targets. |
| LumuSecops.GetClosedIncidents.counts.otherTargetsCount | Number | The total other targets. |
| LumuSecops.GetClosedIncidents.counts.totalTargetsCount | Number | The total number of targets. |
| LumuSecops.GetClosedIncidents.counts.offendersCount | Number | The total number of offenders. |
| LumuSecops.GetClosedIncidents.offendersSamples.type | String | The offender sample type. |
| LumuSecops.GetClosedIncidents.offendersSamples.name | String | The offender sample name. |
| LumuSecops.GetClosedIncidents.offendersSamples.endpoint_ip | String | The offender sample endpoint IP. |
| LumuSecops.GetClosedIncidents.offendersSamples.label | String | The offender sample label. |
| LumuSecops.GetClosedIncidents.targetsSamples.type | String | The target sample type. |
| LumuSecops.GetClosedIncidents.targetsSamples.name | String | The target sample name. |
| LumuSecops.GetClosedIncidents.targetsSamples.endpoint_ip | String | The target sample endpoint IP. |
| LumuSecops.GetClosedIncidents.targetsSamples.label | String | The target sample label. |
| LumuSecops.GetClosedIncidents.lastAssignee | Number | The last assignee user ID. |
| LumuSecops.GetClosedIncidents.autopilotOperation | Unknown | The autopilot operation metadata. |
| LumuSecops.GetClosedIncidents.integrationsThatResponded | Unknown | The integrations that responded. |
| LumuSecops.GetClosedIncidents.builtInResponseTypes | Unknown | The built-in response types. |
| LumuSecops.GetClosedIncidents.accumulators.type | String | The accumulator type. |
| LumuSecops.GetClosedIncidents.accumulators.key | String | The accumulator key. |
| LumuSecops.GetClosedIncidents.accumulators.value | Number | The accumulator value. |
| LumuSecops.GetClosedIncidents.eventsGroupingsCount | Number | The number of event groupings. |
| LumuSecops.GetClosedIncidents.unread | Boolean | The indicator of whether the incident is unread. |
| LumuSecops.GetClosedIncidents.hasPlaybackEvents | Boolean | The indicator of whether playback events exist. |

### lumusecops-get-incident-events-groupings

***
Retrieves event groupings for a specific incident.

#### Base Command

`lumusecops-get-incident-events-groupings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Lumu incident ID. | Required |
| page | The page number. | Optional |
| items | The number of records per page. | Optional |
| status | The comma-separated list of grouping status values. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetIncidentEventsGroupings.incidentId | String | The incident ID. |
| LumuSecops.GetIncidentEventsGroupings.eventsGroupingId | String | The events grouping ID. |
| LumuSecops.GetIncidentEventsGroupings.eventsGroupingFields.label | String | The grouping label. |
| LumuSecops.GetIncidentEventsGroupings.eventsGroupingFields.endpoint | String | The grouping endpoint. |
| LumuSecops.GetIncidentEventsGroupings.totalEvents | Number | The total number of events in the grouping. |
| LumuSecops.GetIncidentEventsGroupings.firstEvent.timestamp | Date | The date the first event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetIncidentEventsGroupings.firstEvent.id | String | The first event ID. |
| LumuSecops.GetIncidentEventsGroupings.lastEvent.timestamp | Date | The date the last event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetIncidentEventsGroupings.lastEvent.id | String | The last event ID. |
| LumuSecops.GetIncidentEventsGroupings.targets | Number | The number of targets in grouping. |
| LumuSecops.GetIncidentEventsGroupings.offenders | Number | The number of offenders in grouping. |
| LumuSecops.GetIncidentEventsGroupings.environmentStats.environment.id | String | The environment ID. |
| LumuSecops.GetIncidentEventsGroupings.environmentStats.environment.type | String | The environment type. |
| LumuSecops.GetIncidentEventsGroupings.environmentStats.count | Number | The event count per environment. |
| LumuSecops.GetIncidentEventsGroupings.hasPlaybackEvents | Boolean | The indicator of whether playback events exist. |
| LumuSecops.GetIncidentEventsGroupings.accumulators.type | String | The accumulator type. |
| LumuSecops.GetIncidentEventsGroupings.accumulators.key | String | The accumulator key. |
| LumuSecops.GetIncidentEventsGroupings.accumulators.value | Number | The accumulator value. |

### lumusecops-get-incident-details

***
Gets details for a specific incident.

#### Base Command

`lumusecops-get-incident-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Lumu incident ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetIncidentDetails.id | String | The incident ID. |
| LumuSecops.GetIncidentDetails.timestamp | Date | The date the incident was created in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetIncidentDetails.isUnread | Boolean | The indicator of whether the incident is unread. |
| LumuSecops.GetIncidentDetails.hasPlaybackEvents | Boolean | The indicator of whether playback events exist. |
| LumuSecops.GetIncidentDetails.status | String | The incident status. |
| LumuSecops.GetIncidentDetails.statusTimestamp | Date | The date the incident status was last updated in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetIncidentDetails.description | String | The incident description. |
| LumuSecops.GetIncidentDetails.totalEvents | Number | The total number of events. |
| LumuSecops.GetIncidentDetails.eventsGroupingsCount | Number | The number of event groupings. |
| LumuSecops.GetIncidentDetails.incidentGroupingId | String | The incident grouping identifier. |
| LumuSecops.GetIncidentDetails.incidentGroupingFields.src_ip | String | The source IP from grouping fields. |
| LumuSecops.GetIncidentDetails.incidentGroupingFields.src_label | String | The source label from grouping fields. |
| LumuSecops.GetIncidentDetails.detectorType | String | The detector type. |
| LumuSecops.GetIncidentDetails.incidentType | String | The incident type category. |
| LumuSecops.GetIncidentDetails.offendersSamples.type | String | The offender sample type. |
| LumuSecops.GetIncidentDetails.offendersSamples.name | String | The offender sample name. |
| LumuSecops.GetIncidentDetails.offendersSamples.endpoint_ip | String | The offender sample endpoint IP. |
| LumuSecops.GetIncidentDetails.offendersSamples.label | String | The offender sample label. |
| LumuSecops.GetIncidentDetails.targetsSamples.type | String | The target sample type. |
| LumuSecops.GetIncidentDetails.targetsSamples.name | String | The target sample name. |
| LumuSecops.GetIncidentDetails.targetsSamples.endpoint_ip | String | The target sample endpoint IP. |
| LumuSecops.GetIncidentDetails.targetsSamples.label | String | The target sample label. |
| LumuSecops.GetIncidentDetails.adversaryTypes | String | The adversary types associated with the incident. |
| LumuSecops.GetIncidentDetails.environmentStats.environment.id | String | The environment ID. |
| LumuSecops.GetIncidentDetails.environmentStats.environment.type | String | The environment type. |
| LumuSecops.GetIncidentDetails.environmentStats.count | Number | The event count per environment. |
| LumuSecops.GetIncidentDetails.actions.datetime | Date | The date the action occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetIncidentDetails.actions.userId | Number | The action user ID. |
| LumuSecops.GetIncidentDetails.actions.action | String | The action name. |
| LumuSecops.GetIncidentDetails.actions.comment | String | The action comment. |
| LumuSecops.GetIncidentDetails.actions | Unknown | The incident actions. |
| LumuSecops.GetIncidentDetails.firstEvent.timestamp | Date | The date the first event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetIncidentDetails.firstEvent.id | String | The first event ID. |
| LumuSecops.GetIncidentDetails.lastEvent.timestamp | Date | The date the last event occurred in ISO 8601 format \(e.g., 2026-01-15T12:34:56Z\). |
| LumuSecops.GetIncidentDetails.lastEvent.id | String | The last event ID. |
| LumuSecops.GetIncidentDetails.lastAssignee | Number | The last assignee user ID. |
| LumuSecops.GetIncidentDetails.autopilotOperation | Unknown | The autopilot operation metadata. |
| LumuSecops.GetIncidentDetails.integrationsThatResponded | Unknown | The integrations that responded. |
| LumuSecops.GetIncidentDetails.builtInResponseTypes | Unknown | The built-in response types. |
| LumuSecops.GetIncidentDetails.counts.endpointTargetsCount | Number | The total endpoint targets. |
| LumuSecops.GetIncidentDetails.counts.userTargetsCount | Number | The total user targets. |
| LumuSecops.GetIncidentDetails.counts.otherTargetsCount | Number | The total other targets. |
| LumuSecops.GetIncidentDetails.counts.totalTargetsCount | Number | The total number of targets. |
| LumuSecops.GetIncidentDetails.counts.offendersCount | Number | The total number of offenders. |
| LumuSecops.GetIncidentDetails.accumulators.type | String | The accumulator type. |
| LumuSecops.GetIncidentDetails.accumulators.key | String | The accumulator key. |
| LumuSecops.GetIncidentDetails.accumulators.value | Number | The accumulator value. |

### lumusecops-mark-incident-as-read

***
Marks an incident as read.

#### Base Command

`lumusecops-mark-incident-as-read`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Lumu incident ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.MarkIncidentAsRead.statusCode | Number | The HTTP-like status code. |
| LumuSecops.MarkIncidentAsRead.message | String | The operation result message. |

#### Command example

```!lumusecops-mark-incident-as-read incident_id=17379140-c8a6-11f1-9a05-eba7016fc3f9```

#### Context Example

```json
{
    "LumuSecops": {
        "MarkIncidentAsRead": {
            "response": "Incident marked as read successfully. Visit Lumu",
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>Incident marked as read successfully. Visit Lumu

### lumusecops-begin-incident-work

***
Begins work on an incident.

#### Base Command

`lumusecops-begin-incident-work`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Lumu incident ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.BeginIncidentWork.statusCode | Number | The HTTP-like status code. |
| LumuSecops.BeginIncidentWork.message | String | The operation result message. |

#### Command example

```!lumusecops-begin-incident-work incident_id=17379140-c8a6-11f1-9a05-eba7016fc3f9```

#### Context Example

```json
{
    "LumuSecops": {
        "BeginIncidentWork": {
            "response": "Incident work started successfully. Visit Lumu",
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>Incident work started successfully. Visit Lumu

### lumusecops-comment-incident

***
Adds a comment to an incident.

#### Base Command

`lumusecops-comment-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Lumu incident ID. | Required |
| comment | The comment value. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.CommentIncident.statusCode | Number | The HTTP-like status code. |
| LumuSecops.CommentIncident.message | String | The operation result message. |

#### Command example

```!lumusecops-comment-incident incident_id=17379140-c8a6-11f1-9a05-eba7016fc3f9 comment="test comment"```

#### Context Example

```json
{
    "LumuSecops": {
        "CommentIncident": {
            "response": "Comment added successfully. Visit Lumu",
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>Comment added successfully. Visit Lumu

### lumusecops-mute-incident

***
Mutes an incident.

#### Base Command

`lumusecops-mute-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Lumu incident ID. | Required |
| comment | The comment value. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.MuteIncident.statusCode | Number | The HTTP-like status code. |
| LumuSecops.MuteIncident.message | String | The operation result message. |

#### Command example

```!lumusecops-mute-incident incident_id=17379140-c8a6-11f1-9a05-eba7016fc3f9 comment="manual test"```

#### Context Example

```json
{
    "LumuSecops": {
        "MuteIncident": {
            "response": "Incident muted successfully. Visit Lumu",
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>Incident muted successfully. Visit Lumu

### lumusecops-unmute-incident

***
Unmutes an incident.

#### Base Command

`lumusecops-unmute-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Lumu incident ID. | Required |
| comment | The comment value. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.UnmuteIncident.statusCode | Number | The HTTP-like status code. |
| LumuSecops.UnmuteIncident.message | String | The operation result message. |

#### Command example

```!lumusecops-unmute-incident incident_id=17379140-c8a6-11f1-9a05-eba7016fc3f9 comment="manual test"```

#### Context Example

```json
{
    "LumuSecops": {
        "UnmuteIncident": {
            "response": "Incident unmuted successfully. Visit Lumu",
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>Incident unmuted successfully. Visit Lumu

### lumusecops-close-incident

***
Closes an incident.

#### Base Command

`lumusecops-close-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Lumu incident ID. | Required |
| comment | The comment value. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.CloseIncident.statusCode | Number | The HTTP-like status code. |
| LumuSecops.CloseIncident.message | String | The operation result message. |

#### Command example

```!lumusecops-close-incident incident_id=17379140-c8a6-11f1-9a05-eba7016fc3f9 comment="manual test"```

#### Context Example

```json
{
    "LumuSecops": {
        "CloseIncident": {
            "response": "Incident closed successfully. Visit Lumu",
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>Incident closed successfully. Visit Lumu

### lumusecops-consult-incidents-updates

***
Obtains real-time updates on incident operations.

#### Base Command

`lumusecops-consult-incidents-updates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | The event stream offset. | Optional |
| items | The number of records per page. | Optional |
| time | The timeout in seconds. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.ConsultIncidentsUpdates.updates | Unknown | The incident update events. |
| LumuSecops.ConsultIncidentsUpdates.offset | Number | The next stream offset. |

### lumusecops-get-security-event-details

***
Retrieves raw data for one security event grouping in an incident.

#### Base Command

`lumusecops-get-security-event-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Lumu incident ID. | Required |
| event_id | The Lumu event ID. | Required |
| page | The page number. | Optional |
| items | The number of records per page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetSecurityEventDetails.items | Unknown | The event detail items. |
| LumuSecops.GetSecurityEventDetails.paginationInfo.page | Number | The requested page number. |
| LumuSecops.GetSecurityEventDetails.paginationInfo.items | Number | The requested items count. |
| LumuSecops.GetSecurityEventDetails.paginationInfo.count | Number | The total count of available records. |

### lumusecops-get-incident-security-events-details

***
Retrieves raw data for all security event groups in an incident.

#### Base Command

`lumusecops-get-incident-security-events-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The Lumu incident ID. | Required |
| page | The page number. | Optional |
| items | The number of records per page. | Optional |
| events_grouping_id | The event grouping ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetIncidentSecurityEventsDetails.items | Unknown | The event detail items. |
| LumuSecops.GetIncidentSecurityEventsDetails.paginationInfo.page | Number | The requested page number. |
| LumuSecops.GetIncidentSecurityEventsDetails.paginationInfo.items | Number | The requested items count. |
| LumuSecops.GetIncidentSecurityEventsDetails.paginationInfo.count | Number | The total count of available records. |

### get-modified-remote-data

***
Gets modified remote incident IDs for mirroring.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | The last update timestamp. | Optional |

#### Context Output

There is no context output for this command.

### get-remote-data

***
Gets remote incident data for mirroring.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | The last update timestamp. | Required |
| id | The remote incident ID. | Required |

#### Context Output

There is no context output for this command.

### get-mapping-fields

***
Gets mapping fields for mirroring.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### update-remote-system

***
Updates the remote system with incident changes.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | The incident delta payload. | Required |
| entries | The incident entries payload. | Optional |
| incident_changed | The indicator of whether the incident changed. | Optional |
| remote_incident_id | The remote incident ID. | Optional |

#### Context Output

There is no context output for this command.

### lumusecops-get-cache

***
Gets the Lumu Secops cache. For internal use.

#### Base Command

`lumusecops-get-cache`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetCache.users | string | The Lumu Users. |
| LumuSecops.GetCache.labels | string | The Lumu Labels. |
| LumuSecops.GetCache.cache | string | The Lumu cache. |
| LumuSecops.GetCache.lumu_secops_incident_ids | string | The Lumu Secops incident ids processed. |

### lumusecops-clear-cache

***
Clears the Lumu Secops cache. For internal use.

#### Base Command

`lumusecops-clear-cache`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.ClearCache | String | The cache clear operation result. |

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Lumu Secops corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Lumu Secops events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Lumu Secops events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and Lumu Secops events will be reflected in both directions. |

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Lumu Secops.
