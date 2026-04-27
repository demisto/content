interactions:
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
    uri: https://api.polyswarm.network/v3//search/hash/sha256?community=default&hash=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  response:
    body:
      string: '<!doctype html>

        <html lang=en>

        <title>Redirecting...</title>

        <h1>Redirecting...</h1>

        <p>You should be redirected automatically to the target URL: <a href="https://api.polyswarm.network/v3/search/hash/sha256?hash=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f&amp;community=default">https://api.polyswarm.network/v3/search/hash/sha256?hash=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f&amp;community=default</a>.
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
      - '473'
      Content-Type:
      - text/html; charset=utf-8
      Date:
      - Mon, 09 Jun 2025 17:38:11 GMT
      Location:
      - https://api.polyswarm.network/v3/search/hash/sha256?hash=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f&community=default
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
    uri: https://api.polyswarm.network/v3/search/hash/sha256?community=default&hash=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  response:
    body:
      string: '{"has_more":false,"limit":50,"result":[{"artifact_id":"86322903773365692","assertions":[{"author":"82454256513644328","author_name":"SecureAge","bid":"2500000000000000","engine":{"description":"The
        SecureAge APEX Engine harnesses the power of artificial intelligence (AI)
        to take on the threats of today and tomorrow. Leveraging on the power of big
        data, the APEX engine goes beyond traditional scanners by effectively and
        reliably spotting malicious patterns to allow for quick decisions based on
        prior experience. It can adaptively update its knowledge against newer and
        unseen malware variants that may attempt to infect endpoints during an outbreak.
        This approach makes it incredibly faster at detecting zero-day threats while
        having minimal footprint regarding performance and disk space when compared
        to traditional anti-malware engines.","name":"SecureAge"},"mask":true,"metadata":{"malware_family":"EICAR
        Anti-Virus Test File","product":"secureage","scanner":{"definition_version":"6.223","engine_version":"5.5.1"}},"verdict":true},{"author":"32946093848101608","author_name":"Filseclab","bid":"2500000000000000","engine":{"description":"","name":"Filseclab"},"mask":true,"metadata":{"malware_family":"Virus.44D88612FEA8A8F3","product":"filseclab","scanner":{"engine_version":"1.0.2.2108","signatures_timestamp":"Tuesday,
        March 29, 2022 11:26:41 PM","signatures_version":"34.3.21873"}},"verdict":true},{"author":"21584326519540048","author_name":"XVirus","bid":"1500000000000000","engine":{"description":"Xvirus
        is a project that started in 2010. Our objective is to provide to consumers
        with simple but powerful products to keep their computers protected, clean
        and at top performance.","name":"XVirus"},"mask":true,"metadata":{"product":"xvirus","scanner":{"vendor_version":"3.0.2.0"}},"verdict":true},{"author":"84695705209944120","author_name":"Crowdstrike
        Falcon ML","bid":"0","engine":{"description":"CrowdStrike Falcon ML protects
        customers against all cyber attacks, using sophisticated signatureless artificial
        intelligence/machine learning and Indicator of Attack (IOA) based threat prevention
        to stop known and unknown threats in real-time.","name":"Crowdstrike Falcon
        ML"},"mask":true,"metadata":{"product":"crowdstrike-falcon","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"2","version":"0.0.1"},"vendor_api_version":"2","vendor_endpoint":"https://www.hybrid-analysis.com/api/v2/quick-scan"},"verdict":null},{"author":"33148585565356292","author_name":"Jiangmin","bid":"2500000000000000","engine":{"description":"Specializes
        in malicious files and business documents scanning","name":"Jiangmin"},"mask":true,"metadata":{"malware_family":"EICAR-Test-File","product":"jiangmin","scanner":{"signatures_version":"16.0.100","vendor_vendor":"1.0.0.0","version":"0.0.1"}},"verdict":true},{"author":"14106784725859115","author_name":"DrWeb","bid":"2500000000000000","engine":{"description":"A
        anti-virus offering preventive protection against the latest active threats,
        targeted attacks, and infiltration attempts that take advantage of vulnerabilities","name":"DrWeb"},"mask":true,"metadata":{"malware_family":"EICAR
        Test File (NOT a Virus!)","product":"drweb","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"signatures_version":"5FE29EEFAB4D56A9090BBEC830148F09,
        2025-Jun-09 15:33:02","vendor_version":"7.00.67.02170","version":"0.0.1"}},"verdict":true},{"author":"55328652711226799","author_name":"Alibaba","bid":"500000000000000","engine":{"description":"Engine
        based on cloud computing, big data technologies and a database with massive
        collection of confirmed malware and safe files. Multiple subsystems included,
        such as preprocessing, static analysis, dynamic analysis, and counterfeit
        software detection.","name":"Alibaba"},"mask":true,"metadata":{"comments":["REPORT_TYPE=eicar"],"malware_family":"Dos.EICAR-test-file","product":"Alibaba","scanner":{"signatures_version":"20180921112649","vendor_version":"0.2.0.3"}},"verdict":true},{"author":"61602204071113521","author_name":"RedDrip
        APT Scanner - RAS","bid":"2500000000000000","engine":{"description":"RAS can
        scan files then determine APT group who is using the files for attacking purpose.To
        achieve that goal, RAS engine uses custom pattern file which contains malware
        pattern and its corresponding APT Group. The knowledge behind pattern file
        is from daily APT tracking conducted by RedDrip Team researchers and analysis
        system.","name":"RedDrip APT Scanner - RAS"},"mask":true,"metadata":{"comments":["THREAT_NAME=THREAT_EICAR_TEST"],"malware_family":"TestFile.Win32.Eicar.Gen","product":"reddrip"},"verdict":true},{"author":"44916051751992551","author_name":"NanoAV","bid":"2500000000000000","engine":{"description":"Russian
        advanced cyber security threat protection with high speed comprehensive threat
        scanning that provides protection from all types of malware and includes real-time
        file and network protection and remediation.","name":"NanoAV"},"mask":true,"metadata":{"malware_family":"Marker.Dos.EICAR-Test-File.dyb","product":"NANO
        Antivirus","scanner":{"signatures_version":"0.14.48.26934","vendor_version":"1.0.146.91124"}},"verdict":true},{"author":"71222207979378669","author_name":"ClamAV","bid":"2500000000000000","engine":{"description":"ClamAV
        is an open source, signature-based, anti-virus engine capable of scanning
        a wide variety of common file types.","name":"ClamAV"},"mask":true,"metadata":{"malware_family":"Win.Test.EICAR_HDB-1","product":"clamav","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"vendor_version":"ClamAV
        1.4.2/27614/Sun Apr 20 08:54:57 2025","version":"0.0.1"}},"verdict":true},{"author":"71533258252366147","author_name":"Ikarus","bid":"2500000000000000","engine":{"description":"Protects
        effectively against viruses, trojans, spyware, spam, and malware that threaten
        the security of your devices and data.","name":"Ikarus"},"mask":true,"metadata":{"malware_family":"EICAR-Test-File","product":"ikarus","scanner":{"environment":{"architecture":"x86_64","operating_system":"Linux"},"version":"0.0.1"},"signatures_version":"09.06.2025
        12:05:21 (108233)","vendor_version":"6.4.12.0"},"verdict":true}],"bounty_state":3,"community":"mainnet1","country":"BR","created":"2025-06-09T17:37:31.719645+00:00","detections":{"benign":0,"malicious":10,"total":10},"extended_type":"EICAR
        virus test files","failed":false,"filename":"MaliciousFile.exe","first_seen":"2019-05-17T01:14:26.512624+00:00","id":"86322903773365692","last_scanned":"2025-06-09T17:37:31.719645+00:00","last_seen":"2025-06-09T17:37:31.719645+00:00","md5":"44d88612fea8a8f36de82e1278abb02f","metadata":[{"created":"2025-06-09T17:38:10.651390+00:00","tool":"polyunite","tool_metadata":{"labels":["nonmalware","virus"],"malware_family":"EICAR","operating_system":[]},"updated":"2025-06-09T17:38:10.651390+00:00"},{"created":"2025-06-09T17:37:38.309513+00:00","tool":"exiftool","tool_metadata":{"directory":"/tmp","exiftoolversion":12.76,"fileaccessdate":"2025:06:09
        17:37:34+00:00","fileinodechangedate":"2025:06:09 17:37:36+00:00","filemodifydate":"2025:06:09
        17:37:36+00:00","filename":"tmp72oj94kp","filepermissions":"-rw-r--r--","filesize":"68
        bytes","filetype":"TXT","filetypeextension":"txt","linecount":1,"mimeencoding":"us-ascii","mimetype":"text/plain","newlines":"(none)","sourcefile":"/tmp/tmp72oj94kp","wordcount":1},"updated":"2025-06-09T17:37:38.309513+00:00"},{"created":"2025-06-09T17:37:35.111433+00:00","tool":"hash","tool_metadata":{"md5":"44d88612fea8a8f36de82e1278abb02f","sha1":"3395856ce81f2b7382dee72602f798b642f14140","sha256":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","sha3_256":"8b4c4e204a8a039198e292d2291f4c451d80e4c38bf0cc04ad3841fea8755bd8","sha3_512":"a20290c6ebf01dc5182bb57718250f61ab11b418466714632a7d1474a02849641f7b78e4093e19ad12fdbedbe02f3bec4ca3ec3235557e82ab5ac02d061e7007","sha512":"cc805d5fab1fd71a4ab352a9c533e65fb2d5b885518f4e565e68847223b8e6b85cb48f3afad842726d99239c9e36505c64b0dc9a061d9e507d833277ada336ab","ssdeep":"3:a+JraNvsgzsVqSwHq9:tJuOgzsko","tlsh":"41a022003b0eee2ba20b00200032e8b00808020e2ce00a3820a020b8c83308803ec228"},"updated":"2025-06-09T17:37:35.111433+00:00"}],"mimetype":"text/plain","permalink":"https://polyswarm.network/scan/results/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/86322903773365692","polyscore":0.9999997956061133,"result":null,"sha1":"3395856ce81f2b7382dee72602f798b642f14140","sha256":"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f","size":68,"type":"FILE","upload_url":"https://s3.us-east-2.amazonaws.com/ps-storage-prodv2-artifact-index/instances/fb/81/46/fb814687-fb3f-4442-a058-bfe159580e5e?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARD7S6WCVBXF6ZSO5%2F20250609%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20250609T173731Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=41e8b5b877191686d91258d6a663954a3243746762cd06f1ca7841a2c9abd602","votes":[],"window_closed":true}],"status":"OK"}

        '
    headers:
      Access-Control-Allow-Origin:
      - '*'
      Access-Control-Expose-Headers:
      - Authorization
      Connection:
      - keep-alive
      Content-Length:
      - '9052'
      Content-Type:
      - application/json
      Date:
      - Mon, 09 Jun 2025 17:38:12 GMT
      Strict-Transport-Security:
      - max-age=31536000; includeSubDomains
      X-Billing-ID:
      - '876543218765'
    status:
      code: 200
      message: OK
version: 1
