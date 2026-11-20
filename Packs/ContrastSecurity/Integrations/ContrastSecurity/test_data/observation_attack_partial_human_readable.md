### Observation Information
|Observation ID|Type|Severity|Rule Name|Rule ID|Result|Application Name|Application Language|Server|Server ID|Environment|HTTP Route|Target|Technique|MITRE Tactics|Agent Version|Application Metadata|Detected|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [A-D-22222222-3333-4444-5555-666666666666-1234567890](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/observations/A-D-22222222-3333-4444-5555-666666666666-1234567890) | Attack | Critical | Command Injection | cmd-injection | Suspicious | sample-webhook-service | JAVA | sample-server-agent | 1001 | DEVELOPMENT | /login | Code | Runtime | Impact, Execution | 6.35.1 | framework: spring | 2026-10-13T16:28:24.255Z |
### Attack Value
|Source IP|URL|Attack Payload Value|
|---|---|---|
| 192.168.0.10 | http://example.com/login | /bin/sh -c whoami |
### Vector Analysis
|Vector Fields|Call Location|
|---|---|
| command: /bin/sh -c whoami, ruleUuid: cmd-injection | org.apache.commons.collections4.functors.InvokerTransformer.transform(InvokerTransformer.java:129) |
### Request Details
|Request Details|
|---|
| GET /login?user=admin HTTP/1.1<br>host: example.com<br>x-request-id: sample-request-id<br>x-empty:  |
### Code Location
|File|Line|Snippet|
|---|---|---|
| java.lang.ProcessImpl | 42 | Runtime.exec(command) |
