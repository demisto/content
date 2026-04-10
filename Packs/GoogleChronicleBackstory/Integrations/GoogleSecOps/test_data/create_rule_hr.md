### Rule Details
|Rule ID|Version ID|Author|Rule Name|Description|Version Creation Time|Compilation Status|Rule Text|Allowed Run Frequencies|
|---|---|---|---|---|---|---|---|---|
| dummy_rule_id | dummy_rule_id@dummy_revicion_id | securityuser | singleEventRule2 | single event rule that should generate detections | 2025-01-02T00:00:00.000000z | SUCCEEDED | rule singleEventRule2 { meta: author = "securityuser" description = "single event rule that should generate detections" events: $e.metadata.event_type = "NETWORK_DNS" condition: $e }<br> | LIVE,<br>HOURLY,<br>DAILY |
