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
