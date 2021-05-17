Assigns an analyst to an incident.
By default, the analyst is picked randomly from the available users, according to the provided roles. However, if no roles are provided, this will fetch all users.
The analyst will be picked according to the `assignBy` arguments.

Machine-Learning: DBot will calculate and decide who is the best analyst for the job.
 * top-user: The user that is most commonly owns this type of incident.
 * less-busy-user: The less busy analyst will be picked to be the incident owner.
 * online: The analyst is picked randomly from all online analysts, according to the provided roles (if no roles are provided, this will fetch all users).
 * current: The user that executed the command.

When the chosen  `assignBy` argument is either: machine-learning, top-user or  less-busy-user, 
the selection of the analyst will not take into consideration the given role.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| roles | The optional list of roles to assign users from. Can accept arrays or comma-separated list. Leave this empty to fetch all users. |
| assignBy | The owner to assign. Can be, "random", "online", "current", "machine-learning", "top-user", or "less-busy-user". The default is random.  |
| username | The provided user who will be assigned as the incident owner (optional). |
| email | The user of the provided email who is assigned as the incident owner (optional). |
| onCall | Set to true to assign only a user that is currently on shift (optional, default: false). Requires Cortex XSOAR v5.5 or later. |

## Outputs
---
There are no outputs for this script.
