### Rule Details
|Rule ID|Version ID|Author|Rule Name|Description|Version Creation Time|Compilation Status|Rule Text|
|---|---|---|---|---|---|---|---|
| ru_de273fa1-e60b-481c-aa87-7f9b4b77f3cb | ru_de273fa1-e60b-481c-aa87-7f9b4b77f3cb@v_1653309550_550015000 | securityuser2 | demoRuleCreatedFromAPIVersion2 | double event rule that should generate detections | 2022-05-23T12:39:10.550015Z | SUCCEEDED | rule demoRuleCreatedFromAPIVersion2 {<br>        meta:<br>        author = "securityuser2"<br>        description = "double event rule that should generate detections"<br><br>        events:<br>        $e.metadata.event_type = "NETWORK_DNS"<br><br>        condition:<br>        $e<br>    }<br> |
