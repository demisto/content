Used by the Manage Private App Segment modify flow. ***netskopev2-update-private-app*** (PATCH) always replaces `host`/`protocols`/`tags` wholesale rather than merging - there's no append/remove operation for private apps like there is for Destination/Network Profiles. This script fetches the app's current host/protocols/tags and applies the requested add/remove deltas, so Modify can add or remove a single value without discarding the rest.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Netskope |

## Dependencies

---
This script uses the following commands and scripts.

* netskopev2-list-private-apps

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| app_id | ID of the private app to read current host/protocols/tags from. Required only if hosts_to_add, ports_to_add, hosts_to_remove, ports_to_remove, tags_to_add, or tags_to_remove is provided. |
| host | Direct-replace host value - passed through unchanged unless hosts_to_add or hosts_to_remove is also provided. |
| protocols_json | Direct-replace protocols JSON - passed through unchanged unless ports_to_add or ports_to_remove is also provided. |
| tags | Direct-replace comma-separated tags value - passed through unchanged unless tags_to_add or tags_to_remove is also provided. |
| hosts_to_add | Comma-separated hosts to add to the app's existing host list without discarding the current ones. |
| ports_to_add | Comma-separated ports to add to the app's existing protocols without discarding the current ones. |
| hosts_to_remove | Comma-separated hosts to remove from the app's existing host list without discarding the rest. |
| ports_to_remove | Comma-separated ports to remove from the app's existing protocols without discarding the rest. |
| tags_to_add | Comma-separated tags to add to the app's existing tags without discarding the current ones. |
| tags_to_remove | Comma-separated tags to remove from the app's existing tags without discarding the rest. |
| protocol_type | Transport protocol used for any newly added ports in ports_to_add. Default is "tcp". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MergedPrivateAppFields.host | Final host value to send. | String |
| MergedPrivateAppFields.protocols_json | Final protocols JSON to send. | String |
| MergedPrivateAppFields.tags | Final comma-separated tags value to send. | String |
