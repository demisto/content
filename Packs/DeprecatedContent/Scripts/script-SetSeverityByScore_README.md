Calculates a weighted score based on the number of malicious indicators involved in the incident. Each indicator type can have a different weight. If the score exceeds certain thresholds, the incident severity will increase. Thresholds can be overriden by providing them in arguments.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | url, ip, hash |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| bad_url_weight | The points added to the score per malicious URL in the incident context (float). |
| bad_ip_weight | The points added to score per malicious IP address in the incident context (float). |
| bad_hash_weight | The points added to score per malicious hash in the incident context (float). |
| threshold_critical | The minimal score to raise the severity to Critical (int). |
| threshold_high | The minimal score to raise the severity to High (int). |
| threshold_medium | The minimal score to raise the severity to Medium (int). |
| initialscore | The starting score to add on to. This can be set manually or mapped from context in playbooks. |

## Outputs
---
There are no outputs for this script.
