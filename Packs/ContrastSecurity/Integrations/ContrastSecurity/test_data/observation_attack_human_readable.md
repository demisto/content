### Observation Information
|Observation ID|Issue ID|Type|Application ID|Application Name|Event Time|
|---|---|---|---|---|---|
| [A-D-b78412a9-2a35-4683-1777670053](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/observations/A-D-b78412a9-2a35-4683-1777670053) | [ISS-2026-2](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-2) | ATTACK | 12345678-1234-1234-1234-123456789012 | test-app-service | 2024-01-15T10:30:00.000Z |
### Attack Information
|Summary|Rule UUID|URL|Recommended Actions|
|---|---|---|---|
| Contrast observed an XML external entity being declared in the prolog of the following XML document:<br><?xml version="1.0" encoding="UTF-8" standalone="yes"?> <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///dummy/path"> | xxe | /api/test | We did not block this attack because blocking was not enabled for test-app-service in development.<br>Add an exclusion for this attack event. |
### Attack Value
|Attack Value Text|Attack Payload Value|Attacker Input Name|Attacker Input Type|
|---|---|---|---|
| Contrast observed an XML external entity being declared in the prolog of the following XML document: | <?xml version="1.0" encoding="UTF-8" standalone="yes"?> <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///dummy/path"> | XML Prolog | UNKNOWN |
### Vector Analysis
|Vector Analysis Context Text|Vector Analysis Code Text|
|---|---|
| The XML parser would have resolved the following resources and placed them into the XML document | <?xml version="1.0" encoding="UTF-8" standalone="yes"?> <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///dummy/path"> |
### Request Details
|Request Details|
|---|
| POST /api/process http/1.1<br>Accept: text/plain, application/json<br>Host: localhost:8080<br>User-Agent: Java/11.0.0 |
### Code Location
|File|Method|
|---|---|
| sample.py | parse_xml() |
### Stack Trace
|Description|Type|
|---|---|
| /app/sample.py.parse_xml(sample.py:100) | frameSink |
| /app/sample.py.handle_request(sample.py:200) | frameCustom |
