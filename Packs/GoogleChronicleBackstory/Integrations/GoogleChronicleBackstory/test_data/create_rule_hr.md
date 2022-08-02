### Rule Detail
|Rule ID|Version ID|Author|Rule Name|Description|Version Creation Time|Compilation Status|Rule Text|
|---|---|---|---|---|---|---|---|
| ru_test-rule-id | ru_test-rule-id@v_test_version_id | testuser | demoRuleCreatedFromAPI | single event rule that should generate detections | 2022-05-24T07:12:00.267007Z | SUCCEEDED | rule demoRuleCreatedFromAPI {<br>        meta:<br>        author = "testuser"<br>        description = "single event rule that should generate detections"<br><br>        events:<br>        $e.metadata.event_type = "NETWORK_DNS"<br><br>        condition:<br>        $e<br>    }<br> |
