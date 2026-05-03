# Akamai Prolexic

This pack provides the **Akamai Prolexic Event Collector** for Cortex XSIAM.

## What does this pack do?

Akamai Prolexic is a cloud-based DDoS protection service. The integration
collects two complementary event streams from the Prolexic Analytics API:

* **Critical Events** — DDoS attack detections and high-severity alerts.
* **Events**          — General activity, traffic patterns and network behaviour
  anomalies.

Events are forwarded to the ``akamai_prolexic_raw`` dataset
(vendor=``akamai``, product=``prolexic``) and can be modeled and queried
in XQL.

## Authentication

Akamai Prolexic uses the EdgeGrid HMAC-SHA-256 authentication scheme. You
will need an Akamai API client with read access to the Prolexic Analytics
API. See the integration **Help** section for full setup instructions.
