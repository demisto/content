# How to configure an API account
To configure an API account:

1. Signup with WootCloud to deploy a solution.
www.wootcloud.com
2. All WootCloud customers have access to the WootCloud API
All WootCloud API base is:  https://api.wootuno.wootcloud.com/v1/

All API calls need basic authentication, provided as Authroization HTTP header.

API Keys
Key Details
"client_id": <client-key-here>
"secret_key": <client-secret-key>


Key Management APIs
List All Account Keys
HTTP Method	GET
URL	/keys
Header	Accept: applicaton/json
Example Request

List Account Keys
curl -X GET \
  https://api.wootuno.wootcloud.com/v1/keys \
  -H 'Accept: application/json' \
  -H 'Authorization: REDACTED_HEADER
Example Response

List Keys Response
[
    {
        "id": "5bb4e26c41815b6454eea167",
        "created": "2018-10-03T15:38:20.523Z",
        "key": "key-JLBvyjc8mGLo3UJQuDM094ZS1N9s5h5O"
    }
]
Fetch Single Account Key
HTTP Method	GET
URL	/v1/keys/{key-id}
Headers	Accept: application/json
Example Request

Request
curl -X GET \
  https://api.wootuno.wootcloud.com/v1/keys/5bb4e26c41815b6454eea167 \
  -H 'Accept: application/json' \
  -H 'Authorization: Basic REDACTED' \
  -H 'Host: api.wootuno.wootcloud.com'
Example Response

{
    "id": "5bb4e26c41815b6454eea167",
    "created": "2018-10-03T15:38:20.523Z",
    "key": "key-JLBvyjc8mGLo3UJQuDM094ZS1N9s5h5O"
}
Regenerate Secret Key
Allows rotating account key by generating a new private key for the account. The old key remains valid for 24 hrs. Either the old key or new key can be used to authenticate during the 24 hr period.

HTTP Method	POST
URL	/v1/keys/regen
Example Request

curl -X POST \
  https://api.wootuno.wootcloud.com/v1/keys/regen \
  -H 'Accept: */*' \
  -H 'Authorization: Basic REDACTED' \
  -H 'Host: api.wootuno.wootcloud.com' \
  -H 'User-Agent: PostmanRuntime/7.15.0'
Example Response

[
    {
        "id": "5bc7c2b7edcb98674052ff88",
        "created": "2018-10-17T23:16:07.878Z",
        "expires": "2018-10-01T18:46:40.449Z",
        "key": REDACTED-OLD-KEY
    },
    {
        "id": "5d190390c49f8700017f4750",
        "created": "2019-06-30T18:46:40.441Z",
        "key": REDACTED-NEW-KEY
    }
]


Delete Old Secret Key
After regenerating secret key, it is possible to delete the old key, before its expiration time.

HTTP Method	DELETE
URL	/v1/keys/{key-id}
Request Example

curl -X DELETE \
  http://api.wootuno.wootcloud.com/v1/keys/5ba93ae4e7fc42eef6861b4d \
  -H 'Accept: */*' \
  -H 'Authorization: Basic REDACTED' \
  -H 'Host: api.wootuno.wootcloud.com' \
  -H 'User-Agent: PostmanRuntime/7.15.0'
Response Example

There is no response to this API, just 200 OK

**Packet Alerts**
Lists packet alerts generated in requested time span.

HTTP Method	POST
URL	/v1/events/packetalerts
Headers	Accept: application/json
Content-Type: application/json
Request expects a JSON request body with following parameters

starttime (required)	"2019-06-26T08:00:00Z"
endtime (required)	"2019-06-26T08:00:00Z"
severity (optional)	Possible values: "notice", "warning", "critical"
skip (optional)	Integer value for pagination. Default value: 0
limit (optional)	Integer value for pagination. Default value: 10. Max Value: 500
site_id (optional)	Array of site ids. Only entered if you want results for a particular site(s) (building, city, region)
Example Request

curl -X POST \
  https://api.wootuno.wootcloud.com/v1/events/packetalerts \
  -H 'Accept: application/json' \
  -H 'Authorization: Basic REDACTED' \
  -H 'Content-Type: application/json' \
  -H 'Host: api.wootuno.wootcloud.com' \
  -H 'content-length: 93' \
  -d '{
    "starttime": "2019-06-26T08:00:00Z",
    "endtime": "2019-06-27T08:00:00Z",
    "limit": 1000
}'
Example Response

`{
    "total": 16,
    "packet_alerts": [
        {
            "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxXzEzMzIxNThfMDAwIiwidCI6IjIwMTktMDYtMjZUMjA6MjQ6MjZaIn0=",
            "timestamp": "2019-06-26T20:24:26Z",
            "severity": "warning",
            "category": "Adminstrator Privilege gain attempted",
            "signature": "ET POLICY IP Check Domain (whatismyip in HTTP Host)",
            "source": {
                "city": "Unknown",
                "continent": "Unknown",
                "country": "Unknown",
                "ip": "192.168.1.193",
                "latitude": -1,
                "longitude": -1,
                "mac": "cc:cc:cc:cc:7c:01",
                "network": "internal",
                "port": 61079,
                "state": "Unknown",
                "subnet": "192.168.1.0/24",
                "time_zone": "Unknown",
                "zip": "Unknown",
                "inferred": {
                    "device_id": "5b4c3c91072c98142d308c31",
                    "asset": "managed",
                    "managed": true,
                    "category": "mobile_phone",
                    "control": "user",
                    "host_name": "Shahabs-iPhone",
                    "os": "ios",
                    "os_version": "12.1.4",
                    "ownership": "corporate",
                    "total_risk": 18.188051551163394,
                    "type": "smart phone",
                    "username": "",
                    "managed_info": {
                        "host_name": "Shahabs-iPhone"
                    }
                }
            },
            "destination": {
                "city": "Cambridge",
                "continent": "North America",
                "country": "United States",
                "ip": "192.168.1.23",
                "latitude": 42.3626,
                "longitude": -71.0843,
                "mac": "cc:cc:cc:c5:23:c0",
                "network": "external",
                "port": 80,
                "state": "Massachusetts",
                "subnet": "",
                "time_zone": "America/New_York",
                "zip": "02142",
                "inferred": {
                    "device_id": "",
                    "asset": "unmanaged",
                    "managed": false,
                    "category": "",
                    "control": "",
                    "host_name": "",
                    "os": "",
                    "os_version": "",
                    "ownership": "",
                    "total_risk": 0,
                    "type": "",
                    "username": "",
                    "managed_info": {
                        "host_name": ""
                    }
                }
            },
            "payload": "GET / HTTP/1.1\r\nHost: whatismyip.akamai.com\r\nAccept: */*\r\nAccept-Language: en-us\r\nConnection: keep-alive\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Security/1314 CFNetwork/976 Darwin/18.2.0\r\n\r\n",
            "http": {
                "hostname": "whatismyip.akamai.com",
                "http_method": "GET",
                "http_user_agent": "Security/1314 CFNetwork/976 Darwin/18.2.0",
                "length": 12,
                "protocol": "HTTP/1.1",
                "redirect": "",
                "http_refer": "",
                "status": 200,
                "url": "/"
            }
        }`
]


**Single Packet Alert**

Fetch a single packet alert based on its ID

HTTP Method	GET
URL	/v1/events/packetalerts/{alert-id}
site_id	Array of site ids. Only entered if you want results for a particular site(s) (building, city, region)
Request

curl -X GET \
  https://api.wootuno.wootcloud.com/v1/events/packetalerts/eyJpIjoiU05XT09UQVBQUFJPRDAxXzIwMDM1NjdfMDAwIiwidCI6IjIwMTgtMDktMjdUMDA6Mzk6MjJaIn0= \
  -H 'Accept: application/json' \
  -H 'Authorization: Basic REDACTED' \
  -H 'Host: api.wootuno.wootcloud.com' \
  -H 'User-Agent: PostmanRuntime/7.15.0' \
  -H 'accept-encoding: gzip, deflate'
Response

{
            "id": "eyJpIjoiU05XT09UQVBQUFJPRDAxXzEzMzIxNThfMDAwIiwidCI6IjIwMTktMDYtMjZUMjA6MjQ6MjZaIn0=",
            "timestamp": "2019-06-26T20:24:26Z",
            "severity": "warning",
            "category": "Adminstrator Privilege gain attempted",
            "signature": "ET POLICY IP Check Domain (whatismyip in HTTP Host)",
            "source": {
                "city": "Unknown",
                "continent": "Unknown",
                "country": "Unknown",
                "ip": "192.168.1.193",
                "latitude": -1,
                "longitude": -1,
                "mac": "cc:cc:cc:cc:7c:01",
                "network": "internal",
                "port": 61079,
                "state": "Unknown",
                "subnet": "192.168.1.0/24",
                "time_zone": "Unknown",
                "zip": "Unknown",
                "inferred": {
                    "device_id": "5b4c3c91072c98142d308c31",
                    "asset": "managed",
                    "managed": true,
                    "category": "mobile_phone",
                    "control": "user",
                    "host_name": "Shahabs-iPhone",
                    "os": "ios",
                    "os_version": "12.1.4",
                    "ownership": "corporate",
                    "total_risk": 18.188051551163394,
                    "type": "smart phone",
                    "username": "",
                    "managed_info": {
                        "host_name": "Shahabs-iPhone"
                    }
                }
            },
            "destination": {
                "city": "Cambridge",
                "continent": "North America",
                "country": "United States",
                "ip": "192.168.1.23",
                "latitude": 42.3626,
                "longitude": -71.0843,
                "mac": "cc:cc:cc:c5:23:c0",
                "network": "external",
                "port": 80,
                "state": "Massachusetts",
                "subnet": "",
                "time_zone": "America/New_York",
                "zip": "02142",
                "inferred": {
                    "device_id": "",
                    "asset": "unmanaged",
                    "managed": false,
                    "category": "",
                    "control": "",
                    "host_name": "",
                    "os": "",
                    "os_version": "",
                    "ownership": "",
                    "total_risk": 0,
                    "type": "",
                    "username": "",
                    "managed_info": {
                        "host_name": ""
                    }
                }
            },
            "payload": "GET / HTTP/1.1\r\nHost: whatismyip.akamai.com\r\nAccept: */*\r\nAccept-Language: en-us\r\nConnection: keep-alive\r\nAccept-Encoding: gzip, deflate\r\nUser-Agent: Security/1314 CFNetwork/976 Darwin/18.2.0\r\n\r\n",
            "http": {
                "hostname": "whatismyip.akamai.com",
                "http_method": "GET",
                "http_user_agent": "Security/1314 CFNetwork/976 Darwin/18.2.0",
                "length": 12,
                "protocol": "HTTP/1.1",
                "redirect": "",
                "http_refer": "",
                "status": 200,
                "url": "/"
            }
        }
Bluetooth Alerts
Lists bluetooth alerts generated in requested time span.
HTTP Method	POST
URL	/v1/events/btalerts
Headers	Accept: application/json
Content-Type: application/json
site_id	Array of site ids. Only entered if you want results for a particular site(s) (building, city, region)
Request expects a JSON request body with following parameters

starttime (required)	"2019-06-26T08:00:00Z"
endtime (required)	"2019-06-26T08:00:00Z"
severity (optional)	Possible values: "notice", "warning", "critical"
skip (optional)	Integer value for pagination. Default value: 0
limit (optional)	Integer value for pagination. Default value: 10. Max Value: 500
Example Request

curl -X POST \
  https://api.wootuno.wootcloud.com/v1/events/btalerts \
  -H 'Accept: application/json' \
  -H 'Authorization: Basic REDACTED' \
  -H 'Content-Type: application/json' \
  -H 'Host: api.wootuno.wootcloud.com' \
  -H 'content-length: 93' \
  -d '{
    "starttime": "2019-06-25T08:00:00Z",
    "endtime": "2019-06-27T08:00:00Z",
    "limit": 1
}'
Example Response

{
    "total": 24,
    "alerts": [
        {
            "id": "eyJpIjoiU05XT09UQVBQTlVTSjFjXzk3NDM1NTQ4OV8wMDAiLCJ0IjoiMjAxOS0wNi0yNlQyMzowMDo1MFoifQ==",
            "timestamp": "2019-06-26T23:00:50Z",
            "severity": "critical",
            "signature": "Bluetooth (BT) Device has a Blueborne (Information Leak) Vulnerability",
            "description": "",
            "inferred": {
                "device_id": "",
                "asset": "unmanaged",
                "managed": false,
                "category": "Audio/Video",
                "control": "",
                "host_name": "",
                "os": "",
                "os_version": "",
                "ownership": "",
                "total_risk": 0,
                "type": "Video Display and Loudspeaker",
                "username": "",
                "managed_info": {
                    "host_name": ""
                }
            }
        }
    ]
}


Anomaly Alerts
Lists anomaly alerts generated in requested time span.
HTTP Method	POST
URL	/v1/events/anomalies
Headers	Accept: application/json
Content-Type: application/json
site_id	Array of site ids. Only entered if you want results for a particular site(s) (building, city, region)
Request expects a JSON request body with following parameters

starttime (required)	"2019-06-26T08:00:00Z"
endtime (required)	"2019-06-26T08:00:00Z"
severity (optional)	Possible values: "info", "notice", "warning", "critical"
skip (optional)	Integer value for pagination. Default value: 0
limit (optional)	Integer value for pagination. Default value: 10. Max Value: 500
Example Request

curl -X POST \
  https://api.wootuno.wootcloud.com/v1/events/anomalies \
  -H 'Accept: application/json' \
  -H 'Authorization: Basic REDACTED' \
  -H 'Content-Type: application/json' \
  -H 'Host: api.wootuno.wootcloud.com' \
  -H 'content-length: 93' \
  -d '{
    "starttime": "2019-06-25T08:00:00Z",
    "endtime": "2019-06-27T08:00:00Z",
    "limit": 1
}'
Example Response

{
  "total": 26649,
  "alerts": [
      "id": "eyJpIjoibWxub2RlX3AwMDhfY2F0LGY4OjJkOjdjOjJmOjQzOjdjLHVua25vd24tcHJvdG9jb2wsMTU1Njc4NDAwMF8wMDAiLCJ0IjoiMjAxOS0wNS0wMlQwODowMDowMFoifQ==",
      "timestamp": "2019-05-02T08:00:00Z",
      "anomaly_type": "bytes_received",
      "signature": "60 (minutes) 'bytes_received'",
      "description": "Anomaly: 60 (minutes) 'bytes_received' (protocol=unknown-protocol) was significantly more than average during this time window (07:00-08:00 UTC) on a weekday according to group of similar devices ({'device.category': 'mobile_phone'})",
      "severity": "warning",
      "count": 1,
      "average": 0,
      "minimum": 0,
      "maximum": 0,
      "standard_deviation": 0,
      "anomaly_score": 1,
      "observed_value": 805,
      "deviation_from_norm": "8050.0",
      "units": "bytes",
      "address": "cc:cc:cc:cc:43:7c",
      "device_details": {
        "device_id": "5cccccccccd4b95ccccc0e96c84eff",
        "asset": "unmanaged",
        "managed": false,
        "category": "mobile_phone",
        "control": "user",
        "host_name": "iPhone",
        "os": "ios",
        "os_version": "",
        "ownership": "employee-owned",
        "total_risk": 0.008771929824570352,
        "type": "smart phone",
        "username": "",
        "managed_info": {
          "host_name": ""
        },
        "ip": "",
        "network": ""
}
