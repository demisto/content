## tLab Anti-APT Feed

Publishes observables seen during tLab Anti-APT sandbox analysis to Threat Intel Management.

### What this feed emits

For every finished sample report the feed creates a **File** indicator for the sample itself, and then mines the report's threat indicators for network and host observables: IPs, domains, URLs, email addresses, hashes and registry keys. With **Fetch MITRE ATT&CK techniques** enabled it also creates Attack Pattern indicators, and with **Create relationships** it links the sample to everything observed with it.

### What it deliberately does not emit

File names, process names and antivirus signature names are **not** indicators. Nothing in Cortex XSOAR can match on them, so publishing them would fill Threat Intel Management with values that can never fire. File names are attached to the sample indicator instead when **Record observed file names** is on.

Private, link-local and multicast addresses are excluded by default. A sandbox VM's traffic is mostly RFC1918 noise, and publishing it as threat intel is worse than publishing nothing. **Add your sandbox's own simulated network ranges to Excluded networks** — the built-in list cannot know them.

### Required permissions

Read-only: the feed never submits anything. Use the default **tLab account (tlab-auth)** mode with an `admin` or `developer` account. A source key does not work here — it covers submissions only.

### Choosing a starting point

The first fetch starts at **First sample report id**. On an installation with a long analysis history, leaving it empty means backfilling everything, one or two API calls per report. Set it to a recent report id unless you actually want the whole archive.

### Late completions

The sandbox finishes analyses out of id order, so a report can complete after a higher-numbered one already has. A cursor alone would step past it permanently. Each run therefore also re-scans reports updated within **Late completion lookback**. Re-submitted indicators are merged by Threat Intel Management, so this costs API calls, not duplicates.
