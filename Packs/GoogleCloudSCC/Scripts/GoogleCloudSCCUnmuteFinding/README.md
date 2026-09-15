Unmutes a Google Cloud Security Command Center finding by its finding name, using the `google-cloud-scc-finding-unmute` command of the Google Cloud SCC integration.

The script is designed to be used as an action button on the **Google Cloud SCC Finding** incident layout. When the `finding_name` argument is not provided, the finding name is taken from the **GoogleCloudSCC Finding Name** incident field, so the button can be clicked without providing any input.

After the finding is unmuted, the mute state returned by the command (`UNMUTED` when the response does not contain it) is written to the **GoogleCloudSCC Finding Mute Status** incident field using the `setIncident` command.

## Script Data

***

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | incident-action-button |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

***
This script uses the following commands and scripts.

* google-cloud-scc-finding-unmute
* setIncident

An enabled **Google Cloud SCC** integration instance is required. The **GoogleCloudSCC Finding Mute Status** incident field is part of this pack and must be associated with the incident type of the incident.

## Inputs

***

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| finding_name | The relative resource name of the finding to unmute.<br/>In the v2 API the name may include an optional "locations/{location}" segment. If no location is specified, the finding is assumed to be in "global".<br/><br/>Format: organizations/{organization_id}/sources/{source_id}/findings/{findingId} or organizations/{organization_id}/sources/{source_id}/locations/{location_id}/findings/{findingId}<br/><br/>Example: organizations/595779152576/sources/14801394649435054450/locations/global/findings/bc5a86da657611ebb979005056a5924e.<br/><br/>If not provided, the value of the "GoogleCloudSCC Finding Name" incident field is used. | Optional |

## Outputs

***

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleCloudSCC.FindingV2.name | String | 'The relative resource name of this finding. Format: organizations/\{organization\}/sources/\{source\}/locations/\{location\}/findings/\{finding\}.' |
| GoogleCloudSCC.FindingV2.canonicalName | String | The canonical name of the finding, always suffixed with the region-agnostic \(global\) resource path. |
| GoogleCloudSCC.FindingV2.parent | String | The relative resource name of the source the finding belongs to. |
| GoogleCloudSCC.FindingV2.resourceName | String | For findings on Google Cloud resources, the full resource name of the Google Cloud resource this finding is for. |
| GoogleCloudSCC.FindingV2.state | String | The state of the finding \(ACTIVE or INACTIVE\). |
| GoogleCloudSCC.FindingV2.category | String | The additional taxonomy group within findings from a given source. |
| GoogleCloudSCC.FindingV2.severity | String | The severity of the finding \(CRITICAL, HIGH, MEDIUM, LOW\). |
| GoogleCloudSCC.FindingV2.mute | String | Indicates the mute state of the finding \(MUTED, UNMUTED, UNDEFINED\). |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.state | String | The static mute state. |
| GoogleCloudSCC.FindingV2.muteInfo.staticMute.applyTime | String | When the static mute was applied. |
| GoogleCloudSCC.FindingV2.eventTime | String | The time at which the event took place, or when an update to the finding occurred. |
| GoogleCloudSCC.FindingV2.createTime | String | The time at which the finding was created in Security Command Center. |
| GoogleCloudSCC.FindingV2.externalUri | String | The URI that, if available, points to a web page outside of Security Command Center where additional information about the finding can be found. |

## Use as an Incident Action Button

***

The script is already wired to the **Unmute Finding** button of the **Google Cloud SCC Finding** incident layout. To add the button to a different layout:

1. Go to **Settings > Objects Setup > Incidents > Layouts** and edit the required layout.
2. Drag a **Buttons** section item to the required section.
3. Set **Label** to `Unmute Finding`.
4. Set **Script** to `GoogleCloudSCCUnmuteFinding`.
5. Leave the script arguments empty to unmute the finding of the incident, or set `finding_name` to `${incident.googlecloudsccfindingname}` explicitly.
6. Save the layout.

Clicking the button unmutes the finding of the incident and posts the result to the incident War Room.

## Script Example

```!GoogleCloudSCCUnmuteFinding finding_name="organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a"```

## Context Example

```json
{
    "GoogleCloudSCC": {
        "FindingV2": {
            "name": "organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "canonicalName": "organizations/1094826489209/sources/5629340921983475201/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
            "parent": "organizations/1094826489209/sources/5629340921983475201",
            "resourceName": "//compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01",
            "state": "ACTIVE",
            "category": "Malware: Cryptomining Bad IP",
            "severity": "CRITICAL",
            "mute": "UNMUTED",
            "muteInfo": {
                "staticMute": {
                    "state": "UNMUTED",
                    "applyTime": "2026-07-29T09:15:20.123Z"
                }
            },
            "eventTime": "2020-02-18T07:26:42Z",
            "createTime": "2020-02-19T13:37:43.858Z",
            "externalUri": "https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917"
        }
    }
}
```

## Human Readable Output

>### The finding has been unmuted successfully
>
>|Organization ID|Name|Mute|State|Severity|Category|Event Time (In UTC)|Create Time (In UTC)|External Uri|Resource Name|
>|---|---|---|---|---|---|---|---|---|---|
>| 1094826489209 | [organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a](https://console.cloud.google.com/security/command-center/findings?organizationId=1094826489209&resourceId=organizations/1094826489209/sources/5629340921983475201/locations/global/findings/6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a) | UNMUTED | ACTIVE | CRITICAL | Malware: Cryptomining Bad IP | February 18, 2020 at 07:26:42 AM | February 19, 2020 at 01:37:43 PM | [https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917](https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/web-server-01?project=prod-webapp-284917) | //compute.googleapis.com/projects/prod-webapp-284917/zones/us-central1-a/instances/web-server-01 |
