XSOAR Lab Updates
---
#### Main Use-Case
Send weekly notifications of new packs to a dedicated Slack channel.

#### What does this pack do?
We update on new packs once every week.
New packs are being retrieved from the public index by the "created" field, along with other fields from the pack marketplace metadata.

We use a XSOAR list (`NewPacksNotifierLastRun`) to cache last run times. In each playbook run the last run time is retrieved from the list, and in the end of the run, being set to the updated last run time.

Slack message is built, showing the 10 "top" packs in full preview and all others as a list.
For each pack in full preview we show:
- author
- support
- description
- price / "FREE"
- \[name\]\(xsoar.pan.dev link\)


#### Pack Contents
- `BuildSlackBlocksFromIndex` Script - calculate the new packs from the last run and build the corresponding Slack message.
- `NewPacksNotifier` Playbook - The playbook maintains the last run times of the script and executes it. Recommended to configure a job to run this playbook.

#### Integrations Used
- Slack V2