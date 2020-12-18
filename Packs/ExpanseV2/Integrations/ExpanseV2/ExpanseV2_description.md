## Expanse V2 Instance Configuration

### Basic Information

The API Key can be retrieved by contacting your Expanse Engagement Manager.

### Additional Options

You can determine several filters (**Priority**, **Activity Status**, **Progress Status**, **Business Units**, **Tags**, **Issue Types**) to fetch a subset of the Expanse Issue and generate Cortex XSOAR Incidents out of them.

### Mirroring

This integration supports bidirectional mirroring to keep Expanse Issues in sync with XSOAR Incidents. Enable mirroring by selecting the appropriate **Incident Mirroring Direction** (Incoming, Outgoing or Both).

The following flags will determine the behavior of the mirroring:
- **Tag(s) for mirrored comments (incoming_tags**): when comments are created in an Expanse Issue, they are replicated in the War Room of the corresponding Cortex XSOAR incident if incoming mirroring is enabled. These Cortex XSOAR tags are added to the entries: they must be different from the sync_tags to prevent loops in case bidirectional mirroring is used.
- **Mirror out Entries with tag(s) (sync_tags)**: All the Cortex XSOAR entries of an Expanse Incident marked with these tags are automatically mirrored to the corresponding Expanse Issue as comments if outgoing mirroring is enabled. The tags be different from the incoming_tags to prevent loops in case bidirectional mirroring is used.
- **Sync Incident Owners**: if enabled, Cortex XSOAR will try to match the Owner of the Expanse Incident in XSOAR to the Assignee in the corresponding Expanse Issue, and vice-versa (depending on the mirroring direction). The match is based on the user's email address. If the *Owner* is removed in Cortex XSOAR, the Expanse Issue is set to *Unassigned*, and vice-versa.

**Mirroring Notes**: 
 - The inbound mirroring will synchronize only the following fields: Comments, Assignee, Progress Status, Activity Status and Priority.
 - For outbound mirroring, to change the *Priority* of an Expanse Issue, you must change the *Severity* in the corresponding Cortex XSOAR Incident.
 - For outbound mirroring, to change the *Assignee* of an Expanse Issue, you must change the *Owner* in the corresponding Cortex XSOAR Incident (and **Sync Incident Owners** must be enabled).
 - Cortex XSOAR fetches details for the Expanse Assets associated to your incidents, such as tags and attribution reasons, but they are not automatically mirrored. You can always collect/refresh this information manually by clicking on the **Refresh Assets** button in the Expanse Incident layout.
