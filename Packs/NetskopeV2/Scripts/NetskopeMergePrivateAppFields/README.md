Fetches a private app's current host, protocols, and tags, then applies the requested additions or removals without discarding the other values. This supports the Manage Private App Segment modify flow because ***netskopev2-update-private-app*** (PATCH) replaces host, protocols, and tags wholesale rather than merging them.

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
| app_id | The ID of the private app to read current host/protocols/tags from. Required only if hosts_to_add, ports_to_add, hosts_to_remove, ports_to_remove, tags_to_add, or tags_to_remove is provided. |
| host | The direct-replace host value (from the Host input) - passed through unchanged unless hosts_to_add or hosts_to_remove is also provided, in which case those win and this is ignored. |
| protocols_json | The direct-replace protocols JSON (from Netskope.BuiltProtocols.ProtocolsJson) - passed through unchanged unless ports_to_add or ports_to_remove is also provided, in which case those win and this is ignored. |
| tags | The direct-replace comma-separated tags value (from the Tags input) - passed through unchanged unless tags_to_add or tags_to_remove is also provided, in which case those win and this is ignored. |
| hosts_to_add | The comma-separated hosts to add to the app's existing host list (e.g. "10.0.0.5") - fetches the app's current host first and merges, deduplicating case-insensitively. |
| ports_to_add | The comma-separated ports to add to the app's existing protocols (e.g. "8080") - fetches the app's current protocols first and merges, skipping ports already present. |
| hosts_to_remove | The comma-separated hosts to remove from the app's existing host list (e.g. "10.0.0.5") - fetches the app's current host first and removes just these entries. |
| ports_to_remove | The comma-separated ports to remove from the app's existing protocols (e.g. "8080") - fetches the app's current protocols first and removes just the matching port entries. |
| tags_to_add | The comma-separated tags to add to the app's existing tags (e.g. "test") - fetches the app's current tags first and merges, deduplicating case-insensitively. |
| tags_to_remove | The comma-separated tags to remove from the app's existing tags (e.g. "test") - fetches the app's current tags first and removes just these entries. |
| protocol_type | The transport protocol used for any newly added ports in ports_to_add. Default is "tcp". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Netskope.MergedPrivateAppFields.Host | The final host value to send - merged with hosts_to_add/hosts_to_remove if provided, otherwise the direct-replace value passed through unchanged. | String |
| Netskope.MergedPrivateAppFields.ProtocolsJson | The final protocols JSON to send - merged with ports_to_add/ports_to_remove if provided, otherwise the direct-replace value passed through unchanged. | String |
| Netskope.MergedPrivateAppFields.Tags | The final comma-separated tags value to send - with tags_to_add/tags_to_remove applied if provided, otherwise the direct-replace value passed through unchanged. | String |
