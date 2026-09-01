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

## Incident types and fields

The pack classifies Doppel alerts into dedicated incident types per product vertical: **Doppel Alert Domains**, **Doppel Alert Social_Media**, **Doppel Alert Mobile_Apps**, **Doppel Alert Ecommerce**, **Doppel Alert Crypto**, **Doppel Alert Email**, **Doppel Alert Paid_Ads**, and **Doppel Alert Telco**.

Each incident type displays the alert's entity content in a dedicated grid field matching its product shape:

- **Doppel Entity Content** - domain alerts (registrar, IP address, nameservers, and more).
- **Doppel Entity Content Social Media** - social media users, posts, and groups.
- **Doppel Entity Content Mobile Apps** - mobile app listings.
- **Doppel Entity Content Ecommerce** - ecommerce listings.
- **Doppel Entity Content Telco** - telco entities.

The **Doppel Audit Logs** grid field records the alert's change history from Doppel.

## Mirroring

Incoming mirroring keeps the queue state, entity state, severity, notes, audit logs, and entity content of existing incidents in sync with Doppel, including alerts that have no audit log history and incidents that have never synced before. Outgoing mirroring archives the Doppel alert when the incident is closed in Cortex XSOAR and sends the incident close notes to Doppel as an alert comment. See the integration README for configuration details and the full list of mirrored fields.
