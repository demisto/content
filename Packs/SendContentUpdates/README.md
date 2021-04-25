### This pack sends content-updates to DFIR Channel.
---
#### Flow
We update on new packs once every week.
New packs are being retrieved from the public index by the "created" field, along with other fields from the pack marketplace metadata.

We use a XSOAR list (`ContentUpdatesLastRun`) to cache last run times. In each playbook run the last run time is retrieved from the list, and in the end of the run, being set to the updated last run time.

Slack message is being build, showing the 5 "top" packs in full preview and all others as a list.
For each pack in full preview we show:
- author
- support
- description
- price / "FREE"
- \[name\]\(xsoar.pan.dev link\)

---
#### Integrations Used
- Google Cloud Storage
- Slack V2