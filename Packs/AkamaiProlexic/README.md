# Akamai Prolexic

This pack provides the **Akamai Prolexic** event collector for Cortex XSIAM.

## What does this pack do?

Akamai Prolexic is a cloud-based DDoS protection service. The integration
collects DDoS detection critical events and general events from the Akamai
Prolexic Analytics API and forwards them to Cortex XSIAM as the
`akamai_prolexic_raw` dataset (vendor=`akamai`, product=`prolexic`).

Two complementary event streams are collected:

* **Critical Events** — DDoS attack detections and high-severity alerts.
  Prolexic updates these records in place, so each entry carries an
  `_ENTRY_STATUS` field set to either `new` or `updated`.
* **Events** — General activity, traffic patterns, and network behavior
  anomalies.

Each source is fetched and deduplicated independently, so a burst in one
stream does not delay or crowd out the other.

## Authentication

Akamai Prolexic uses the EdgeGrid HMAC-SHA-256 authentication scheme. You
will need an Akamai API client with READ-ONLY access to the Prolexic Analytics
API. See the integration **Help** section for full setup instructions.

## Rate limits

The Prolexic Analytics API is limited to 1000 requests per hour. Tune the
**Maximum events per fetch** and **Events Fetch Interval** parameters to stay
below that ceiling.
