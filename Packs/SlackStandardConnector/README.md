# Slack (Standard Connector)

Satellite pack of Slack used by the Slack Enterprise connector. Shares its logic with the Slack pack via
the SlackV3ApiModule, SlackIAMApiModule and SlackEventCollectorApiModule. Configure it from the connector
page, not directly.

## Moving from the legacy Slack integrations

Slack Socket Mode delivers each event to one connection per app token, so a legacy Slack v3 instance and
a Slack Enterprise connector instance that use the same bot cannot run side by side: messages, mirroring
and SlackAsk replies would reach only one of them. Move over in this order:

1. **Stage**: create the Slack Enterprise connector instance with its capabilities disabled, or with only
   the capabilities that do not use Socket Mode (provisioning, Log Collection).
2. **Finish open SlackAsk tasks**: let pending SlackAsk questions be answered, or close them, on the
   legacy instance. Replies to questions sent by the legacy instance are not received by the new one.
3. **Disable the legacy instances**: Slack v3, Slack IAM and Slack Event Collector.
4. **Enable the connector capabilities**: Send messages, mirror investigations and manage channels;
   Provision and manage users and groups (SCIM); Log Collection; Fetch Issues.
5. **Validate**: send a test message, check mirroring on an open investigation, and confirm new audit
   logs arrive in the `slack_slack_raw` dataset.

To avoid gaps or duplicates in audit logs, set the Log Collection **First fetch time interval** (`oldest`) value to
the time the legacy Slack Event Collector last fetched. Provisioning (IAM) has no fetch state and can be
switched in the same step as the other capabilities.
