### Observation Information
|Observation ID|Issue ID|Type|Severity|Rule Name|Rule ID|Result|Application Name|Application ID|Application Language|Server|Server ID|Environment|HTTP Route|Target|Technique|MITRE Tactics|Agent Version|Detected|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [A-D-11111111-2222-3333-4444-555555555555-1234567890](https://test.contrast.com/Contrast/cs/index.html#/11111111-aaaa-bbbb-cccc-111111111111/observations/A-D-11111111-2222-3333-4444-555555555555-1234567890) | [ISS-2026-0001](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-0001) | Attack | Critical | Command Injection | cmd\-injection | Suspicious | [sample-webhook-service](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=app-12345678-aaaa-bbbb-cccc-1234567890ab) | app\-12345678\-aaaa\-bbbb\-cccc\-1234567890ab | JAVA | sample\-server\-agent | 1001 | DEVELOPMENT | /login | Code | Runtime | Impact, Execution | 6.35.1 | 2026\-10\-13T16:28:24.255Z |
### Attack Value
|Source IP|URL|Attack Payload Value|
|---|---|---|
| 192.168.0.10 | http://example.com/login | /bin/sh \-c whoami |
### Vector Analysis
|Vector Fields|Call Location|
|---|---|
| command: /bin/sh \-c whoami, ruleUuid: cmd\-injection | org.apache.commons.collections4.functors.InvokerTransformer.transform\(InvokerTransformer.java:129\) |
### Request Details
|Request Details|
|---|
| POST /login HTTP/1.1<br>accept: \*/\*<br>accept\-encoding: gzip, deflate<br>content\-length: 42<br>content\-type: application/json<br>Cookie: JSESSIONID=SAMPLESESSIONID<br>host: example.com<br>user\-agent: python\-requests/2.31.0<br>x\-forwarded\-host: example.com<br>x\-forwarded\-port: 80<br>x\-forwarded\-proto: http<br>x\-forwarded\-scheme: http<br>x\-real\-ip: 192.168.0.10<br>x\-request\-id: sample\-request\-id<br>x\-scheme: http<br><br>\{"username":"admin","password":"password"\} |
### Code Location
|File|
|---|
| java.lang.ProcessImpl |
