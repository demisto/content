interactions:
- request:
    body: '{"artifact_name": "205.210.31.208", "artifact_type": "URL", "scan_config":
      "more-time", "community": "default"}'
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      Content-Length:
      - '111'
      Content-Type:
      - application/json
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: POST
    uri: https://api.polyswarm.network/v3//instance
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/instance">https://api.polyswarm.network/v3/instance</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '269'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:19 GMT
      Location:
      - https://api.polyswarm.network/v3/instance
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: '{"artifact_name": "205.210.31.208", "artifact_type": "URL", "scan_config":
      "more-time", "community": "default"}'
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      Content-Length:
      - '111'
      Content-Type:
      - application/json
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: POST
    uri: https://api.polyswarm.network/v3/instance
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[],"bounty_state":0,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":null,"failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":null,"metadata":[],"mimetype":null,"permalink":"https://polyswarm.network/scan/results/file/None/86207359749085905","polyscore":null,"result":null,"sha1":null,"sha256":null,"size":null,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '1011'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:20 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: !!python/object/new:_io.BytesIO
      state: !!python/tuple
      - !!binary |
        MjA1LjIxMC4zMS4yMDg=
      - 0
      - null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      Content-Length:
      - '14'
      User-Agent:
      - python-requests/2.32.3
    method: PUT
    uri: https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIADEADBEEFCREDENTIAL&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-Signature=2345678deadbeefdeadbeef2345678deadbeefdeadbeef2345678deadbeef&X-Amz-SignedHeaders=host
  response:
    body:
      string: ''
    headers:
      Content-Length:
      - '0'
      Date:
      - Mon, 09 Jun 2025 17:35:22 GMT
      ETag:
      - '"95e7a55577ed2ac25638ef224789d8e6"'
      Server:
      - AmazonS3
      x-amz-checksum-crc64nvme:
      - V5g1egZE1UY=
      x-amz-checksum-type:
      - FULL_OBJECT
      x-amz-expiration:
      - expiry-date="Wed, 11 Jun 2025 00:00:00 GMT", rule-id="artifact-index_0-instances"
      x-amz-id-2:
      - as67WfUyaRt9h96toQFV/gq0bwKMyquMmZlOV9fCeZ8qiUu2+Q8YsTgvrhjfXX0sycukspdv+Ew=
      x-amz-request-id:
      - JBGQVF5C0TEZDNYB
      x-amz-server-side-encryption:
      - AES256
    status:
      code: 200
      message: OK
- request:
    body: '{"community": "default"}'
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      Content-Length:
      - '24'
      Content-Type:
      - application/json
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: PUT
    uri: https://api.polyswarm.network/v3//instance?id=86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/instance?id=86207359749085905">https://api.polyswarm.network/v3/instance?id=86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '311'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:21 GMT
      Location:
      - https://api.polyswarm.network/v3/instance?id=86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: '{"community": "default"}'
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      Content-Length:
      - '24'
      Content-Type:
      - application/json
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: PUT
    uri: https://api.polyswarm.network/v3/instance?id=86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[],"bounty_state":0,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":null,"failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":null,"metadata":[],"mimetype":null,"permalink":"https://polyswarm.network/scan/results/file/None/86207359749085905","polyscore":null,"result":null,"sha1":null,"sha256":null,"size":null,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '1011'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:22 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:23 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '1933'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:23 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:25 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '3247'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:26 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:27 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4036'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:28 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:30 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4036'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:30 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:32 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:33 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:34 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:35 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:37 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:37 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:39 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:40 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:42 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:42 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:44 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:45 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:47 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:47 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:49 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:50 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:51 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:52 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:54 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:55 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:56 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:57 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:35:58 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:35:59 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:36:00 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:36:01 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:36:03 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:36:03 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:36:05 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:36:06 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:36:07 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:36:08 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:36:10 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:36:11 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:36:13 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:36:13 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:36:15 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:36:16 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:36:17 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":2,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:36:18 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:36:20 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":3,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":null,"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":null,"last_seen":null,"md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":null,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":false},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4439'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:36:20 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3//consumer/submission/default/86207359749085905
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905">https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905</a>.
        If not, click the link.

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '343'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:36:22 GMT
      Location:
      - https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
    status:
      code: 308
      message: PERMANENT REDIRECT
- request:
    body: null
    headers:
      Accept:
      - '*/*'
      Accept-Encoding:
      - gzip, deflate
      Connection:
      - keep-alive
      User-Agent:
      - polyswarm-api/3.13.0 (x86_64-Linux-CPython-3.10.18)
      authorization:
      - XDEADBEEFDEADBEEFDEADBEEFX
    method: GET
    uri: https://api.polyswarm.network/v3/consumer/submission/default/86207359749085905
  response:
    body:
      string: '{"result":{"artifact_id":"86207359749085905","assertions":[{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":false},{"author":"973526140535311","author_name":"Criminal
        IP","bid":"1500000000000000","engine":{"description":"A threat intelligence
        search engine that scans the whole internet and uncovers all kinds of information
        on any internet connected device. \r\nPowered by AI and Machine Learning,
        Criminal IP detects and assesses the risks and vulnerabilities associated
        with internet connected devices in real-time. With powerful Lookup capabilities
        by IP address, Domain/URL, IOT, product name, and various other filters, it
        presents a comprehensive view that shows you all that you need to see.","name":"Criminal
        IP"},"mask":true,"metadata":{"malware_family":"","product":"criminalip","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"}},"verdict":true},{"author":"1570342234717548","author_name":"Notmining","bid":"2500000000000000","engine":{"description":"Website
        threat detection, URL scanning","name":"Notmining"},"mask":true,"metadata":{"product":"Notmining"},"verdict":false},{"author":"8287892299604143","author_name":"Phishtank","bid":"0","engine":{"description":"PhishTank
        is a free community site where anyone can submit, verify, track and share
        phishing data. PhishTank provides accurate, actionable information to anyone
        trying to identify bad actors, whether for themselves or for others.","name":"Phishtank"},"mask":true,"metadata":{"product":"phishtank"},"verdict":null},{"author":"218093623534239","author_name":"CRDF","bid":"2500000000000000","engine":{"description":"Hosted
        and paid by Polyswarm","name":"CRDF"},"mask":true,"metadata":{"product":"crdf"},"verdict":false},{"author":"32559741969883812","author_name":"Quttera","bid":"0","engine":{"description":"A
        service that lets client applications scan websites for malicious and suspicious
        activity as well as check URLs against Quttera''s regularly updated Threat
        Intelligence database.","name":"Quttera"},"mask":true,"metadata":{"comments":["SKIPPED"],"product":"quttera","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"3","version":"0.0.1"}},"verdict":null}],"bounty_state":3,"community":"mainnet1","country":"BR","created":"2025-06-09T17:35:20.540245+00:00","detections":{"benign":3,"malicious":1,"total":4},"extended_type":"ASCII
        text, with no line terminators","failed":false,"filename":"205.210.31.208","first_seen":"2025-06-09T17:35:20.540245+00:00","id":"86207359749085905","last_scanned":"2025-06-09T17:35:20.540245+00:00","last_seen":"2025-06-09T17:35:20.540245+00:00","md5":"95e7a55577ed2ac25638ef224789d8e6","metadata":[{"created":"2025-06-09T17:36:21.893469+00:00","tool":"polyunite","tool_metadata":{"labels":[],"malware_family":null,"operating_system":[]},"updated":"2025-06-09T17:36:21.893469+00:00"},{"created":"2025-06-09T17:35:24.499586+00:00","tool":"hash","tool_metadata":{"md5":"95e7a55577ed2ac25638ef224789d8e6","sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","sha3_256":"4f04bda599e85106459f10e4fa9ec52908443a1870db7ea231e888367a3b9722","sha3_512":"bb87db3e2d868dfaf12fa8baa7a219b3bf311710c524cab8cfd3a67d09abb031cd30b4763e9ad9f2d3baf6960aa466c10735c8365a8ece540553fb33291b7fbc","sha512":"0d9524a11de044e5308b5c0de19a8fc88b85b5ee313f7c942338a8c0d5c4841abb1148929d91fb3e82034ba4a5842614bd2aba801cf8ed86c8d6689580c7b254","ssdeep":"3:qSLn:qC","tlsh":""},"updated":"2025-06-09T17:35:24.499586+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2/86207359749085905","polyscore":0.33460048640798623,"result":null,"sha1":"34d54281d94ff22c7a4e871f5647fa5f44021fc8","sha256":"af0169d053b43eb83b886fd65a8bc7df1d76bcc2b068c862ec1048e8cf1df8a2","size":14,"type":"URL","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/6e/0c/2a/6e0c2afa-90c3-471f-924c-0d3a66012191?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173520Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=af7e721580061014562acb1913434819d18bfe5f3b74abc0544b90273362b155","votes":[],"window_closed":true},"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '4730'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:36:23 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
version: 1
