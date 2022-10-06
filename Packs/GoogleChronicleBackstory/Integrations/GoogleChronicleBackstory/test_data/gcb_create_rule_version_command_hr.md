### New Rule Version Details
|Rule ID|Version ID|Author|Rule Name|Description|Version Creation Time|Compilation Status|Rule Text|
|---|---|---|---|---|---|---|---|
| ru_52eea093-acc0-438a-8867-ece16e65fc0c | ru_52eea093-acc0-438a-8867-ece16e65fc0c@v_1653549695_141983000 | securityuser2 | demoRuleCreatedFromAPIVersion2 | double event rule that should generate detections | 2022-05-26T07:21:35.141983Z | SUCCEEDED | rule demoRuleCreatedFromAPIVersion2 {<br>        meta:<br>        author = "securityuser2"<br>        description = "double event rule that should generate detections"<br><br>        events:<br>        $e.metadata.event_type = "NETWORK_DNS"<br><br>        condition:<br>        $e<br>    }<br> |
