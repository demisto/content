**Deprecated. Use KELA Monitor instead.** RaDark is now KELA Monitor (KELA renamed the module). For new deployments, use the KELA Monitor pack. If you move a monitor to KELA Monitor, disable the RaDark instance before you enable fetching in KELA Monitor, otherwise every incident is created twice.

#### Differences from KELA Monitor

| | KELA RaDark (this pack) | KELA Monitor |
| --- | --- | --- |
| Fetch | One incident per RaDark aggregation, incident type **RaDark** | One incident per KELA Monitor incident, one incident type per KELA incident type |
| Incident fields, mapper, layout | RaDark fields and grids, **RaDark - Incoming Mapper**, **RaDark Layout** | Own **KELA Monitor** fields, classifier, incoming mapper and layouts |
| Context | `Radark.*` | `KELA.Monitor.*` |
| Enrichment (`radark-email-enrich`, `radark-incident-get-items`) | Yes | No replacement; use `kela-monitor-incident-list` with `text` |
| Manage incidents in KELA (`radark-item-handle`, `radark-item-purchase`) | Yes | No replacement (read-only) |
| Playbooks | Get RaDark Detailed Items and 5 grid sub-playbooks (deprecated) | None |

This content pack was created to allow KELA's customers an integration with RaDark.

#### What does this pack do?

* Fetches incidents from RaDark into your Cortex XSOAR.
* Supports enrichment for existing data from RaDark.
* Manages incidents in RaDark from your Cortex XSOAR.

The content pack consists of several content items including mappers, classifiers, incident types, incident fields, and layouts which provide a playbook for RaDark items. These create a complete pack that supports full integration with KELA's RaDark platform.
