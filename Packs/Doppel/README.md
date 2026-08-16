# Doppel XSOAR Pack

## Overview

Doppel is a Modern Digital Risk Protection Solution, that detects the phishing and brand cyber attacks on the emerging channels. Doppel scans millions of channels online which includes, social media, domains, paid ads, dark web, emerging channels, etc. Doppel can identify the malicious content and cyber threats, and enables their customers to take down the digital risks proactively.

## Features supported by the Doppel XSOAR pack

1. Mirror Incidents : Alerts from Doppel are mirrored as per the configured schedule.
2. Command: create-alert : Command to create an alert in Doppel.
3. Command: get-alert : Command to fetch alert details from Doppel.
4. Command: get-alerts : Command to fetch list of alerts from Doppel.
5. Command: update-alert : Command to update alert details from Doppel.
6. Command: create-abuse-alert : Command to create abuse alert details from Doppel.

## Keeping alerts in sync without native mirroring (Cortex XSIAM)

Native incident mirroring is available on Cortex XSOAR only. On platforms without it, such as Cortex XSIAM, the pack provides an equivalent polling-based sync:

1. The **Doppel - Sync Alerts** job (disabled by default, every 15 minutes) triggers the **Doppel - Sync Alerts** playbook.
2. The **DoppelSyncAlerts** script applies Doppel-side changes (queue state, entity state, severity, notes, and audit logs) to the matching incidents/issues.
3. The **DoppelPushUpdates** script archives Doppel alerts whose incidents/issues were closed by analysts, optionally sending the close notes as the alert comment.

To enable the sync, configure the Doppel integration instance with fetching enabled, then enable the **Doppel - Sync Alerts** job. On Cortex XSOAR, prefer the integration's native mirroring and leave the job disabled.
