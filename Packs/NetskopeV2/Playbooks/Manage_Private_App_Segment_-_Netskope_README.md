Creates, modifies, or deletes a Netskope private application (ZTNA/NPA) "segment". Netskope's own API models this as one Private App object (a host + its protocol/port entries + publishers) - there is no separate "segment" sub-resource, so this playbook manages the whole private app object.

Branches on the `Action` input:
- **create**: creates a new private app using AppName, Host, Ports/ProtocolType, PublisherNames, and Tags.
- **modify**: updates an existing private app (identified by AppID, or by AppName) - only the fields you provide are changed, the rest are left as-is. `HostsToAdd`/`PortsToAdd`/`TagsToAdd` append to the current host/protocols/tags instead of replacing them; `HostsToRemove`/`PortsToRemove`/`TagsToRemove` remove specific values instead of requiring you to retype everything else.
- **delete**: permanently deletes the private app identified by AppID or AppName.

There's no "replace" (full PUT) action - ***netskopev2-replace-private-app*** exists as a command in the pack, but the API's write validation silently no-ops the whole request when any field's shape doesn't exactly match, which makes it unreliable to drive from a playbook. "modify" (PATCH) covers add/remove of individual fields instead.

For modify/delete, you can provide AppID directly or leave it blank and provide AppName instead - ***netskopev2-list-private-apps*** has no name filter argument, so the playbook fetches every private app and resolves AppName to an ID itself. Similarly, PublisherNames takes plain publisher names instead of requiring you to already know each publisher_id, and Ports takes a plain comma-separated port list instead of requiring hand-written JSON.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Netskope - Direct to Zero Trust

### Scripts

* NetskopeResolvePrivateAppId
* NetskopeResolvePublishers
* NetskopeBuildProtocolsJson
* NetskopeMergePrivateAppFields

### Commands

* netskopev2-create-private-app
* netskopev2-update-private-app
* netskopev2-delete-private-app

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Action | One of "create", "modify", or "delete" - which private app operation to perform. |  | Required |
| AppID | ID of the existing private app to modify or delete. Optional if AppName is provided instead. Ignored for Action=create. |  | Optional |
| AppName | Name of the private app. Required for Action=create. For modify/delete, use with AppID blank to look up which app to act on by name. |  | Optional |
| Host | IP address or hostname of the private app segment - comma-separated for multiple hosts. Required for Action=create, optional for Action=modify. |  | Optional |
| Ports | Comma-separated port numbers (e.g. "443,8080,22"). Required for Action=create, optional for Action=modify. |  | Optional |
| ProtocolType | Transport protocol applied to every port in Ports. | tcp | Optional |
| HostsToAdd | Action=modify only. Comma-separated hosts to add to the app's existing host list without discarding the current ones. |  | Optional |
| PortsToAdd | Action=modify only. Comma-separated ports to add to the app's existing protocols without discarding the current ones. |  | Optional |
| HostsToRemove | Action=modify only. Comma-separated hosts to remove from the app's existing host list without discarding the rest. |  | Optional |
| PortsToRemove | Action=modify only. Comma-separated ports to remove from the app's existing protocols without discarding the rest. |  | Optional |
| PublisherNames | Comma-separated publisher names (e.g. "AWS-NPA"). Required for Action=create, optional for Action=modify. |  | Optional |
| Tags | Comma-separated tag names to associate with the app. For Action=modify, this replaces the app's entire tag list - use TagsToAdd/TagsToRemove instead to change individual tags. |  | Optional |
| TagsToAdd | Action=modify only. Comma-separated tags to add to the app's existing tags without discarding the current ones. |  | Optional |
| TagsToRemove | Action=modify only. Comma-separated tag names to remove from the app's existing tags without discarding the rest. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.
