SecOps operations for the new Lumu Defender API. Fetch, investigate, and manage Lumu incidents from Cortex XSOAR with bidirectional mirroring.
This integration was integrated and tested with new Lumu Defender SecOps API.

## Configure Lumu Secops in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| API Key |  | True |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| None |  | False |
| Incident Offset |  | False |
| Total incidents per fetch |  | False |
| Max time in seconds per fetch |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Incidents Fetch Interval |  | False |
| Mirror tags | Comments and files tagged with this value are mirrored to Lumu. | False |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from SentinelOne to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to SentinelOne\), or Incoming and Outgoing \(from/to Cortex XSOAR and SentinelOne\). Cortex XSOAR only parameter. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### lumusecops-retrieve-labels

***
Get a paginated list of all the labels created for the company and its details such as id, name and business relevance. The items are sorted by the label id in ascending order.

#### Base Command

`lumusecops-retrieve-labels`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page requested. | Optional |
| limit | items limit requested. Default is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.RetrieveLabels.labels.id | Number | label id. |
| LumuSecops.RetrieveLabels.labels.name | String | label name. |
| LumuSecops.RetrieveLabels.labels.relevance | Number | label relevance. |
| LumuSecops.RetrieveLabels.paginationInfo.page | Number | current page. |
| LumuSecops.RetrieveLabels.paginationInfo.items | Number | current items. |
| LumuSecops.RetrieveLabels.paginationInfo.next | Number | next page. |
| LumuSecops.RetrieveLabels.paginationInfo.prev | Number | previous page. |

### lumusecops-retrieve-a-specific-label

***
Get details such as id, name and business relevance from a specific label.

| `{label-id}` | ID of the specific label |
|---|---|.

#### Base Command

`lumusecops-retrieve-a-specific-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label_id | label id requested. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.RetrieveASpecificLabel.id | Number | label id. |
| LumuSecops.RetrieveASpecificLabel.name | String | label name. |
| LumuSecops.RetrieveASpecificLabel.relevance | Number | label relevance. |

### lumusecops-get-all-incidents

***
Get a paginated list of all incidents.

#### Base Command

`lumusecops-get-all-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number. | Optional |
| items | Number of incidents per page. | Optional |
| status | Filter by incident status values: open,muted,closed. | Optional |
| adversary_types | Filter by adversary type values. | Optional |
| labels | Filter by label IDs. | Optional |
| from_date | Filter incidents from this date/time (ISO 8601). | Optional |
| to_date | Filter incidents up to this date/time (ISO 8601). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetAllIncidents.id | String | Incident ID. |
| LumuSecops.GetAllIncidents.statusTimestamp | Date | Incident status update timestamp. |
| LumuSecops.GetAllIncidents.status | String | Incident status. |
| LumuSecops.GetAllIncidents.timestamp | Date | Incident creation time. |
| LumuSecops.GetAllIncidents.detectorType | String | Detector type. |
| LumuSecops.GetAllIncidents.incidentType | String | Incident type category. |
| LumuSecops.GetAllIncidents.totalEvents | Number | Total number of events. |
| LumuSecops.GetAllIncidents.firstEvent.timestamp | Date | First related event timestamp. |
| LumuSecops.GetAllIncidents.firstEvent.id | String | First related event ID. |
| LumuSecops.GetAllIncidents.lastEvent.timestamp | Date | Last related event timestamp. |
| LumuSecops.GetAllIncidents.lastEvent.id | String | Last related event ID. |
| LumuSecops.GetAllIncidents.adversaryTypes | String | Adversary types associated with the incident. |
| LumuSecops.GetAllIncidents.description | String | Incident description. |
| LumuSecops.GetAllIncidents.eventsGroupingsCount | Number | Number of event groupings. |
| LumuSecops.GetAllIncidents.incidentGroupingFields.adversary | String | Grouping adversary value. |
| LumuSecops.GetAllIncidents.incidentGroupingFields.src_ip | String | Source IP from grouping fields. |
| LumuSecops.GetAllIncidents.incidentGroupingFields.src_label | String | Source label from grouping fields. |
| LumuSecops.GetAllIncidents.incidentGroupingFields.domain | String | Domain from grouping fields. |
| LumuSecops.GetAllIncidents.incidentGroupingFields.user_name | String | Username from grouping fields. |
| LumuSecops.GetAllIncidents.counts.totalTargetsCount | Number | Total number of targets. |
| LumuSecops.GetAllIncidents.counts.endpointTargetsCount | Number | Total endpoint targets. |
| LumuSecops.GetAllIncidents.counts.userTargetsCount | Number | Total user targets. |
| LumuSecops.GetAllIncidents.counts.otherTargetsCount | Number | Total other targets. |
| LumuSecops.GetAllIncidents.counts.offendersCount | Number | Total number of offenders. |
| LumuSecops.GetAllIncidents.environmentStats | Unknown | Environment stats collection. |
| LumuSecops.GetAllIncidents.environmentStats.environment.id | String | Environment ID. |
| LumuSecops.GetAllIncidents.environmentStats.environment.type | String | Environment type. |
| LumuSecops.GetAllIncidents.environmentStats.count | Number | Event count per environment. |
| LumuSecops.GetAllIncidents.offendersSamples._id | String | Offender sample identifier. |
| LumuSecops.GetAllIncidents.offendersSamples.type | String | Offender sample type. |
| LumuSecops.GetAllIncidents.offendersSamples.name | String | Offender sample name. |
| LumuSecops.GetAllIncidents.offendersSamples.value | String | Offender sample value. |
| LumuSecops.GetAllIncidents.offendersSamples.endpoint_ip | String | Offender sample endpoint IP. |
| LumuSecops.GetAllIncidents.offendersSamples.label | String | Offender sample label. |
| LumuSecops.GetAllIncidents.targetsSamples._id | String | Target sample identifier. |
| LumuSecops.GetAllIncidents.targetsSamples.type | String | Target sample type. |
| LumuSecops.GetAllIncidents.targetsSamples.name | String | Target sample name. |
| LumuSecops.GetAllIncidents.targetsSamples.value | String | Target sample value. |
| LumuSecops.GetAllIncidents.targetsSamples.endpoint_ip | String | Target sample endpoint IP. |
| LumuSecops.GetAllIncidents.targetsSamples.label | String | Target sample label. |
| LumuSecops.GetAllIncidents.targetsSamples.realm | String | Target sample realm. |
| LumuSecops.GetAllIncidents.lastAssignee | Number | Last assignee user ID. |
| LumuSecops.GetAllIncidents.autopilotOperation | Unknown | Autopilot operation metadata. |
| LumuSecops.GetAllIncidents.integrationsThatResponded | Unknown | Integrations that responded. |
| LumuSecops.GetAllIncidents.builtInResponseTypes | Unknown | Built-in response types. |
| LumuSecops.GetAllIncidents.accumulators | Unknown | Aggregation accumulator collection. |
| LumuSecops.GetAllIncidents.accumulators.type | String | Accumulator type. |
| LumuSecops.GetAllIncidents.accumulators.key | String | Accumulator key. |
| LumuSecops.GetAllIncidents.accumulators.value | Number | Accumulator value. |
| LumuSecops.GetAllIncidents.unread | Boolean | Whether the incident is unread. |
| LumuSecops.GetAllIncidents.hasPlaybackEvents | Boolean | Whether playback events exist. |

### lumusecops-get-open-incidents

***
Get a paginated list of open incidents.

#### Base Command

`lumusecops-get-open-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number. | Optional |
| items | Number of incidents per page. | Optional |
| adversary_types | Filter by adversary type values. | Optional |
| labels | Filter by label IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetOpenIncidents.id | String | Incident ID. |
| LumuSecops.GetOpenIncidents.statusTimestamp | Date | Incident status update timestamp. |
| LumuSecops.GetOpenIncidents.status | String | Incident status. |
| LumuSecops.GetOpenIncidents.timestamp | Date | Incident creation time. |
| LumuSecops.GetOpenIncidents.detectorType | String | Detector type. |
| LumuSecops.GetOpenIncidents.incidentType | String | Incident type category. |
| LumuSecops.GetOpenIncidents.totalEvents | Number | Total number of events. |
| LumuSecops.GetOpenIncidents.firstEvent.timestamp | Date | First related event timestamp. |
| LumuSecops.GetOpenIncidents.firstEvent.id | String | First related event ID. |
| LumuSecops.GetOpenIncidents.lastEvent.timestamp | Date | Last related event timestamp. |
| LumuSecops.GetOpenIncidents.lastEvent.id | String | Last related event ID. |
| LumuSecops.GetOpenIncidents.description | String | Incident description. |
| LumuSecops.GetOpenIncidents.adversaryTypes | String | Adversary types associated with the incident. |
| LumuSecops.GetOpenIncidents.incidentGroupingFields.adversary | String | Grouping adversary value. |
| LumuSecops.GetOpenIncidents.environmentStats.environment.id | String | Environment ID. |
| LumuSecops.GetOpenIncidents.environmentStats.environment.type | String | Environment type. |
| LumuSecops.GetOpenIncidents.environmentStats.count | Number | Event count per environment. |
| LumuSecops.GetOpenIncidents.counts.endpointTargetsCount | Number | Total endpoint targets. |
| LumuSecops.GetOpenIncidents.counts.userTargetsCount | Number | Total user targets. |
| LumuSecops.GetOpenIncidents.counts.otherTargetsCount | Number | Total other targets. |
| LumuSecops.GetOpenIncidents.counts.totalTargetsCount | Number | Total number of targets. |
| LumuSecops.GetOpenIncidents.counts.offendersCount | Number | Total number of offenders. |
| LumuSecops.GetOpenIncidents.offendersSamples._id | String | Offender sample identifier. |
| LumuSecops.GetOpenIncidents.offendersSamples.type | String | Offender sample type. |
| LumuSecops.GetOpenIncidents.offendersSamples.value | String | Offender sample value. |
| LumuSecops.GetOpenIncidents.targetsSamples._id | String | Target sample identifier. |
| LumuSecops.GetOpenIncidents.targetsSamples.type | String | Target sample type. |
| LumuSecops.GetOpenIncidents.targetsSamples.label | String | Target sample label. |
| LumuSecops.GetOpenIncidents.targetsSamples.name | String | Target sample name. |
| LumuSecops.GetOpenIncidents.targetsSamples.endpoint_ip | String | Target sample endpoint IP. |
| LumuSecops.GetOpenIncidents.lastAssignee | Number | Last assignee user ID. |
| LumuSecops.GetOpenIncidents.autopilotOperation | Unknown | Autopilot operation metadata. |
| LumuSecops.GetOpenIncidents.integrationsThatResponded | Unknown | Integrations that responded. |
| LumuSecops.GetOpenIncidents.builtInResponseTypes | Unknown | Built-in response types. |
| LumuSecops.GetOpenIncidents.accumulators.type | String | Accumulator type. |
| LumuSecops.GetOpenIncidents.accumulators.key | String | Accumulator key. |
| LumuSecops.GetOpenIncidents.accumulators.value | Number | Accumulator value. |
| LumuSecops.GetOpenIncidents.eventsGroupingsCount | Number | Number of event groupings. |
| LumuSecops.GetOpenIncidents.unread | Boolean | Whether the incident is unread. |
| LumuSecops.GetOpenIncidents.hasPlaybackEvents | Boolean | Whether playback events exist. |

### lumusecops-get-muted-incidents

***
Get a paginated list of muted incidents.

#### Base Command

`lumusecops-get-muted-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number. | Optional |
| items | Number of incidents per page. | Optional |
| adversary_types | Filter by adversary type values. | Optional |
| labels | Filter by label IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetMutedIncidents.id | String | Incident ID. |
| LumuSecops.GetMutedIncidents.statusTimestamp | Date | Incident status update timestamp. |
| LumuSecops.GetMutedIncidents.status | String | Incident status. |
| LumuSecops.GetMutedIncidents.timestamp | Date | Incident creation time. |
| LumuSecops.GetMutedIncidents.detectorType | String | Detector type. |
| LumuSecops.GetMutedIncidents.incidentType | String | Incident type category. |
| LumuSecops.GetMutedIncidents.totalEvents | Number | Total number of events. |
| LumuSecops.GetMutedIncidents.firstEvent.timestamp | Date | First related event timestamp. |
| LumuSecops.GetMutedIncidents.firstEvent.id | String | First related event ID. |
| LumuSecops.GetMutedIncidents.lastEvent.timestamp | Date | Last related event timestamp. |
| LumuSecops.GetMutedIncidents.lastEvent.id | String | Last related event ID. |
| LumuSecops.GetMutedIncidents.description | String | Incident description. |
| LumuSecops.GetMutedIncidents.adversaryTypes | String | Adversary types associated with the incident. |
| LumuSecops.GetMutedIncidents.incidentGroupingFields.adversary | String | Grouping adversary value. |
| LumuSecops.GetMutedIncidents.environmentStats.environment.id | String | Environment ID. |
| LumuSecops.GetMutedIncidents.environmentStats.environment.type | String | Environment type. |
| LumuSecops.GetMutedIncidents.environmentStats.count | Number | Event count per environment. |
| LumuSecops.GetMutedIncidents.counts.endpointTargetsCount | Number | Total endpoint targets. |
| LumuSecops.GetMutedIncidents.counts.userTargetsCount | Number | Total user targets. |
| LumuSecops.GetMutedIncidents.counts.otherTargetsCount | Number | Total other targets. |
| LumuSecops.GetMutedIncidents.counts.totalTargetsCount | Number | Total number of targets. |
| LumuSecops.GetMutedIncidents.counts.offendersCount | Number | Total number of offenders. |
| LumuSecops.GetMutedIncidents.offendersSamples._id | String | Offender sample identifier. |
| LumuSecops.GetMutedIncidents.offendersSamples.type | String | Offender sample type. |
| LumuSecops.GetMutedIncidents.offendersSamples.value | String | Offender sample value. |
| LumuSecops.GetMutedIncidents.targetsSamples._id | String | Target sample identifier. |
| LumuSecops.GetMutedIncidents.targetsSamples.type | String | Target sample type. |
| LumuSecops.GetMutedIncidents.targetsSamples.label | String | Target sample label. |
| LumuSecops.GetMutedIncidents.targetsSamples.name | String | Target sample name. |
| LumuSecops.GetMutedIncidents.targetsSamples.endpoint_ip | String | Target sample endpoint IP. |
| LumuSecops.GetMutedIncidents.lastAssignee | Number | Last assignee user ID. |
| LumuSecops.GetMutedIncidents.autopilotOperation | Unknown | Autopilot operation metadata. |
| LumuSecops.GetMutedIncidents.integrationsThatResponded | Unknown | Integrations that responded. |
| LumuSecops.GetMutedIncidents.builtInResponseTypes | Unknown | Built-in response types. |
| LumuSecops.GetMutedIncidents.accumulators.type | String | Accumulator type. |
| LumuSecops.GetMutedIncidents.accumulators.key | String | Accumulator key. |
| LumuSecops.GetMutedIncidents.accumulators.value | Number | Accumulator value. |
| LumuSecops.GetMutedIncidents.eventsGroupingsCount | Number | Number of event groupings. |
| LumuSecops.GetMutedIncidents.unread | Boolean | Whether the incident is unread. |
| LumuSecops.GetMutedIncidents.hasPlaybackEvents | Boolean | Whether playback events exist. |

### lumusecops-get-closed-incidents

***
Get a paginated list of closed incidents.

#### Base Command

`lumusecops-get-closed-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number. | Optional |
| items | Number of incidents per page. | Optional |
| adversary_types | Filter by adversary type values. | Optional |
| labels | Filter by label IDs. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetClosedIncidents.id | String | Incident ID. |
| LumuSecops.GetClosedIncidents.statusTimestamp | Date | Incident status update timestamp. |
| LumuSecops.GetClosedIncidents.status | String | Incident status. |
| LumuSecops.GetClosedIncidents.timestamp | Date | Incident creation time. |
| LumuSecops.GetClosedIncidents.detectorType | String | Detector type. |
| LumuSecops.GetClosedIncidents.incidentType | String | Incident type category. |
| LumuSecops.GetClosedIncidents.totalEvents | Number | Total number of events. |
| LumuSecops.GetClosedIncidents.firstEvent.timestamp | Date | First related event timestamp. |
| LumuSecops.GetClosedIncidents.firstEvent.id | String | First related event ID. |
| LumuSecops.GetClosedIncidents.lastEvent.timestamp | Date | Last related event timestamp. |
| LumuSecops.GetClosedIncidents.lastEvent.id | String | Last related event ID. |
| LumuSecops.GetClosedIncidents.description | String | Incident description. |
| LumuSecops.GetClosedIncidents.adversaryTypes | String | Adversary types associated with the incident. |
| LumuSecops.GetClosedIncidents.incidentGroupingFields.src_ip | String | Source IP from grouping fields. |
| LumuSecops.GetClosedIncidents.incidentGroupingFields.src_label | String | Source label from grouping fields. |
| LumuSecops.GetClosedIncidents.environmentStats.environment.id | String | Environment ID. |
| LumuSecops.GetClosedIncidents.environmentStats.environment.type | String | Environment type. |
| LumuSecops.GetClosedIncidents.environmentStats.count | Number | Event count per environment. |
| LumuSecops.GetClosedIncidents.counts.endpointTargetsCount | Number | Total endpoint targets. |
| LumuSecops.GetClosedIncidents.counts.userTargetsCount | Number | Total user targets. |
| LumuSecops.GetClosedIncidents.counts.otherTargetsCount | Number | Total other targets. |
| LumuSecops.GetClosedIncidents.counts.totalTargetsCount | Number | Total number of targets. |
| LumuSecops.GetClosedIncidents.counts.offendersCount | Number | Total number of offenders. |
| LumuSecops.GetClosedIncidents.offendersSamples.type | String | Offender sample type. |
| LumuSecops.GetClosedIncidents.offendersSamples.name | String | Offender sample name. |
| LumuSecops.GetClosedIncidents.offendersSamples.endpoint_ip | String | Offender sample endpoint IP. |
| LumuSecops.GetClosedIncidents.offendersSamples.label | String | Offender sample label. |
| LumuSecops.GetClosedIncidents.targetsSamples.type | String | Target sample type. |
| LumuSecops.GetClosedIncidents.targetsSamples.name | String | Target sample name. |
| LumuSecops.GetClosedIncidents.targetsSamples.endpoint_ip | String | Target sample endpoint IP. |
| LumuSecops.GetClosedIncidents.targetsSamples.label | String | Target sample label. |
| LumuSecops.GetClosedIncidents.lastAssignee | Number | Last assignee user ID. |
| LumuSecops.GetClosedIncidents.autopilotOperation | Unknown | Autopilot operation metadata. |
| LumuSecops.GetClosedIncidents.integrationsThatResponded | Unknown | Integrations that responded. |
| LumuSecops.GetClosedIncidents.builtInResponseTypes | Unknown | Built-in response types. |
| LumuSecops.GetClosedIncidents.accumulators.type | String | Accumulator type. |
| LumuSecops.GetClosedIncidents.accumulators.key | String | Accumulator key. |
| LumuSecops.GetClosedIncidents.accumulators.value | Number | Accumulator value. |
| LumuSecops.GetClosedIncidents.eventsGroupingsCount | Number | Number of event groupings. |
| LumuSecops.GetClosedIncidents.unread | Boolean | Whether the incident is unread. |
| LumuSecops.GetClosedIncidents.hasPlaybackEvents | Boolean | Whether playback events exist. |

### lumusecops-get-incident-events-groupings

***
Retrieve event groupings for a specific incident.

#### Base Command

`lumusecops-get-incident-events-groupings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Lumu incident ID. | Required |
| page | Page number. | Optional |
| items | Number of records per page. | Optional |
| status | Filter by grouping status values. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetIncidentEventsGroupings.incidentId | String | Incident ID. |
| LumuSecops.GetIncidentEventsGroupings.eventsGroupingId | String | Events grouping ID. |
| LumuSecops.GetIncidentEventsGroupings.eventsGroupingFields.label | String | Grouping label. |
| LumuSecops.GetIncidentEventsGroupings.eventsGroupingFields.endpoint | String | Grouping endpoint. |
| LumuSecops.GetIncidentEventsGroupings.totalEvents | Number | Total number of events in the grouping. |
| LumuSecops.GetIncidentEventsGroupings.firstEvent.timestamp | Date | First event timestamp. |
| LumuSecops.GetIncidentEventsGroupings.firstEvent.id | String | First event ID. |
| LumuSecops.GetIncidentEventsGroupings.lastEvent.timestamp | Date | Last event timestamp. |
| LumuSecops.GetIncidentEventsGroupings.lastEvent.id | String | Last event ID. |
| LumuSecops.GetIncidentEventsGroupings.targets | Number | Number of targets in grouping. |
| LumuSecops.GetIncidentEventsGroupings.offenders | Number | Number of offenders in grouping. |
| LumuSecops.GetIncidentEventsGroupings.environmentStats.environment.id | String | Environment ID. |
| LumuSecops.GetIncidentEventsGroupings.environmentStats.environment.type | String | Environment type. |
| LumuSecops.GetIncidentEventsGroupings.environmentStats.count | Number | Event count per environment. |
| LumuSecops.GetIncidentEventsGroupings.hasPlaybackEvents | Boolean | Whether playback events exist. |
| LumuSecops.GetIncidentEventsGroupings.accumulators.type | String | Accumulator type. |
| LumuSecops.GetIncidentEventsGroupings.accumulators.key | String | Accumulator key. |
| LumuSecops.GetIncidentEventsGroupings.accumulators.value | Number | Accumulator value. |

### lumusecops-get-incident-details

***
Get details for a specific incident.

#### Base Command

`lumusecops-get-incident-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Lumu incident ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetIncidentDetails.id | String | Incident ID. |
| LumuSecops.GetIncidentDetails.timestamp | Date | Incident creation time. |
| LumuSecops.GetIncidentDetails.isUnread | Boolean | Whether the incident is unread. |
| LumuSecops.GetIncidentDetails.hasPlaybackEvents | Boolean | Whether playback events exist. |
| LumuSecops.GetIncidentDetails.status | String | Incident status. |
| LumuSecops.GetIncidentDetails.statusTimestamp | Date | Incident status update timestamp. |
| LumuSecops.GetIncidentDetails.description | String | Incident description. |
| LumuSecops.GetIncidentDetails.totalEvents | Number | Total number of events. |
| LumuSecops.GetIncidentDetails.eventsGroupingsCount | Number | Number of event groupings. |
| LumuSecops.GetIncidentDetails.incidentGroupingId | String | Incident grouping identifier. |
| LumuSecops.GetIncidentDetails.incidentGroupingFields.src_ip | String | Source IP from grouping fields. |
| LumuSecops.GetIncidentDetails.incidentGroupingFields.src_label | String | Source label from grouping fields. |
| LumuSecops.GetIncidentDetails.detectorType | String | Detector type. |
| LumuSecops.GetIncidentDetails.incidentType | String | Incident type category. |
| LumuSecops.GetIncidentDetails.offendersSamples.type | String | Offender sample type. |
| LumuSecops.GetIncidentDetails.offendersSamples.name | String | Offender sample name. |
| LumuSecops.GetIncidentDetails.offendersSamples.endpoint_ip | String | Offender sample endpoint IP. |
| LumuSecops.GetIncidentDetails.offendersSamples.label | String | Offender sample label. |
| LumuSecops.GetIncidentDetails.targetsSamples.type | String | Target sample type. |
| LumuSecops.GetIncidentDetails.targetsSamples.name | String | Target sample name. |
| LumuSecops.GetIncidentDetails.targetsSamples.endpoint_ip | String | Target sample endpoint IP. |
| LumuSecops.GetIncidentDetails.targetsSamples.label | String | Target sample label. |
| LumuSecops.GetIncidentDetails.adversaryTypes | String | Adversary types associated with the incident. |
| LumuSecops.GetIncidentDetails.environmentStats.environment.id | String | Environment ID. |
| LumuSecops.GetIncidentDetails.environmentStats.environment.type | String | Environment type. |
| LumuSecops.GetIncidentDetails.environmentStats.count | Number | Event count per environment. |
| LumuSecops.GetIncidentDetails.actions.datetime | Date | Action timestamp. |
| LumuSecops.GetIncidentDetails.actions.userId | Number | Action user ID. |
| LumuSecops.GetIncidentDetails.actions.action | String | Action name. |
| LumuSecops.GetIncidentDetails.actions.comment | String | Action comment. |
| LumuSecops.GetIncidentDetails.actions | Unknown | Incident actions. |
| LumuSecops.GetIncidentDetails.firstEvent.timestamp | Date | First event timestamp. |
| LumuSecops.GetIncidentDetails.firstEvent.id | String | First event ID. |
| LumuSecops.GetIncidentDetails.lastEvent.timestamp | Date | Last event timestamp. |
| LumuSecops.GetIncidentDetails.lastEvent.id | String | Last event ID. |
| LumuSecops.GetIncidentDetails.lastAssignee | Number | Last assignee user ID. |
| LumuSecops.GetIncidentDetails.autopilotOperation | Unknown | Autopilot operation metadata. |
| LumuSecops.GetIncidentDetails.integrationsThatResponded | Unknown | Integrations that responded. |
| LumuSecops.GetIncidentDetails.builtInResponseTypes | Unknown | Built-in response types. |
| LumuSecops.GetIncidentDetails.counts.endpointTargetsCount | Number | Total endpoint targets. |
| LumuSecops.GetIncidentDetails.counts.userTargetsCount | Number | Total user targets. |
| LumuSecops.GetIncidentDetails.counts.otherTargetsCount | Number | Total other targets. |
| LumuSecops.GetIncidentDetails.counts.totalTargetsCount | Number | Total number of targets. |
| LumuSecops.GetIncidentDetails.counts.offendersCount | Number | Total number of offenders. |
| LumuSecops.GetIncidentDetails.accumulators.type | String | Accumulator type. |
| LumuSecops.GetIncidentDetails.accumulators.key | String | Accumulator key. |
| LumuSecops.GetIncidentDetails.accumulators.value | Number | Accumulator value. |

### lumusecops-mark-incident-as-read

***
Mark an incident as read.

#### Base Command

`lumusecops-mark-incident-as-read`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Lumu incident ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.MarkIncidentAsRead.statusCode | Number | HTTP-like status code. |
| LumuSecops.MarkIncidentAsRead.message | String | Operation result message. |

### lumusecops-begin-incident-work

***
Begin work on an incident.

#### Base Command

`lumusecops-begin-incident-work`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Lumu incident ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.BeginIncidentWork.statusCode | Number | HTTP-like status code. |
| LumuSecops.BeginIncidentWork.message | String | Operation result message. |

### lumusecops-comment-incident

***
Add a comment to an incident.

#### Base Command

`lumusecops-comment-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Lumu incident ID. | Required |
| comment | Comment value. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.CommentIncident.statusCode | Number | HTTP-like status code. |
| LumuSecops.CommentIncident.message | String | Operation result message. |

### lumusecops-mute-incident

***
Mute an incident.

#### Base Command

`lumusecops-mute-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Lumu incident ID. | Required |
| comment | Comment value. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.MuteIncident.statusCode | Number | HTTP-like status code. |
| LumuSecops.MuteIncident.message | String | Operation result message. |

### lumusecops-unmute-incident

***
Unmute an incident.

#### Base Command

`lumusecops-unmute-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Lumu incident ID. | Required |
| comment | Comment value. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.UnmuteIncident.statusCode | Number | HTTP-like status code. |
| LumuSecops.UnmuteIncident.message | String | Operation result message. |

### lumusecops-close-incident

***
Close an incident.

#### Base Command

`lumusecops-close-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Lumu incident ID. | Required |
| comment | Comment value. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.CloseIncident.statusCode | Number | HTTP-like status code. |
| LumuSecops.CloseIncident.message | String | Operation result message. |

### lumusecops-consult-incidents-updates

***
Obtain real-time updates on incident operations.

#### Base Command

`lumusecops-consult-incidents-updates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | Event stream offset. | Optional |
| items | Number of records per page. | Optional |
| time | Timeout in seconds. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.ConsultIncidentsUpdates.updates | Unknown | Incident update events. |
| LumuSecops.ConsultIncidentsUpdates.offset | Number | Next stream offset. |

### lumusecops-get-security-event-details

***
Retrieve raw data for one security event grouping in an incident.

#### Base Command

`lumusecops-get-security-event-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Lumu incident ID. | Required |
| event_id | Lumu event ID. | Required |
| page | Page number. | Optional |
| items | Number of records per page. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetSecurityEventDetails.items | Unknown | Event detail items. |
| LumuSecops.GetSecurityEventDetails.paginationInfo.page | Number | Requested page number. |
| LumuSecops.GetSecurityEventDetails.paginationInfo.items | Number | Requested items count. |
| LumuSecops.GetSecurityEventDetails.paginationInfo.count | Number | Total count of available records. |

### lumusecops-get-incident-security-events-details

***
Retrieve raw data for all security event groups in an incident.

#### Base Command

`lumusecops-get-incident-security-events-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Lumu incident ID. | Required |
| page | Page number. | Optional |
| items | Number of records per page. | Optional |
| events_grouping_id | Event grouping ID. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetIncidentSecurityEventsDetails.items | Unknown | Event detail items. |
| LumuSecops.GetIncidentSecurityEventsDetails.paginationInfo.page | Number | Requested page number. |
| LumuSecops.GetIncidentSecurityEventsDetails.paginationInfo.items | Number | Requested items count. |
| LumuSecops.GetIncidentSecurityEventsDetails.paginationInfo.count | Number | Total count of available records. |

### get-modified-remote-data

***
Mirror process command.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Last update timestamp. | Optional |

#### Context Output

There is no context output for this command.

### get-remote-data

***
Mirror process command.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Last update timestamp. | Required |
| id | Remote incident ID. | Required |

#### Context Output

There is no context output for this command.

### get-mapping-fields

***
Mirror process command.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### update-remote-system

***
Mirror process command.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | Incident delta payload. | Required |
| entries | Incident entries payload. | Optional |
| incident_changed | Indicates if incident changed. | Optional |
| remote_incident_id | Remote incident ID. | Optional |

#### Context Output

There is no context output for this command.

### lumusecops-get-cache

***
Lumu get cache.

#### Base Command

`lumusecops-get-cache`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| LumuSecops.GetCache.users | string | Lumu Users. |
| LumuSecops.GetCache.labels | string | Lumu Labels. |
| LumuSecops.GetCache.cache | string | Lumu cache. |
| LumuSecops.GetCache.lumu_secops_incident_ids | string | Lumu Secops incident ids processed. |

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
