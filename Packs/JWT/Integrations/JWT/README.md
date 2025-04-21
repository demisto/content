JSON Web Token (JWT) is a compact, URL-safe means of representing claims to be transferred between two parties. This Integration can be used to Generate New JWT Tokens, Encode and Decode Existing Ones.
This integration was integrated and tested with generic JWT authentication service.
## Configure JWT in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL | The authentication server URL | True |
| Secret Key | The secret key to sign the authentication token. | True |
| Issuer Claim | The “iss” \(issuer\) claim identifies the principal that issued the JWT. | False |
| Audience Claim | The “aud” \(audience\) claim identifies the recipients that the JWT is intended for. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### jwt-generate-access-token
***
Generates a JWT authorization token with an optional scope and queries the API for an access token and then returns the received API access token


#### Base Command

`jwt-generate-access-token`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| jti | The "jti" (JWT ID) claim provides a unique identifier for the JWT token. | Optional | 
| iss | The "iss" (issuer) claim identifies the principal that issued the JWT. | Optional | 
| aud | The "aud" (audience) claim identifies the recipients that the JWT is intended for. | Optional | 
| sub | The "sub" (subject) claim identifies the principal that is the subject of the JWT. | Optional | 
| scp | The "scp" (scope) claim is described in OAuth 2.0 Token Exchange as an array of strings, each of which represents an OAuth Scope granted for the issued security token. | Optional | 
| iat | The "iat" (issued at) claim identifies the time at which the JWT was issued. | Optional | 
| exp | The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. | Optional | 
| nbf | The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing. | Optional | 
| additionalClaims | Additional claims to include in the request. | Optional | 
| tokenTimeout | Token Timeout in Seconds. Default is 300. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JWT.Token.ID | String | The JWT Token ID | 
| JWT.Token.AccessToken | String | The JWT Access Token Value | 
| JWT.Token.AuthenticationToken | String | JWT Authentication Token | 


#### Command Example
```!jwt-generate-access-token iss="http://example.com" sub="3233-2344-4b52-2323-fc0bfb11e673" additionalClaims="{"parameter1":"23323-323-4854-893c-b59610423ad"}" tokenTimeout="300"```

#### Context Example
```json
{
    "JWT": {
        "Token": {
            "AccessToken": "***",
            "AuthenticationToken": "***",
            "ID": "009eb036-1e60-43e5-aad2-1187462db0be"
        }
    }
}
```

#### Human Readable Output

>### Results
>|AccessToken|AuthenticationToken|ID|
>|---|---|---|
>| eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MjIwNTA1ODMsImlhdCI6MTYyMjA1MDI4MywianRpIjoiMDA5ZWIwMzYtMWU2MC00M2U1LWFhZDItMTE4NzQ2MmRiMGJlIiwiaXNzIjoiaHR0cDovL2V4YW1wbGUuY29tIiwic3ViIjoiMzIzMy0yMzQ0LTRiNTItMjMyMy1mYzBiZmIxMWU2NzMiLCJwYXJhbWV0ZXIxIjoiMjMzMjMtMzIzLTQ4NTQtODkzYy1iNTk2MTA0MjNhZCJ9.13zCwNhvt8fCuyHBcmdbDSaXUIpDRI95Q5-m1EbPQmk", | 009eb036-1e60-43e5-aad2-1187462db0be |


### jwt-generate-authentication-payload
***
Generates a JWT authorization request payload by encoding the provided claims.


#### Base Command

`jwt-generate-authentication-payload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| jti | The "jti" (JWT ID) claim provides a unique identifier for the JWT token. | Optional | 
| iss | The "iss" (issuer) claim identifies the principal that issued the JWT. | Optional | 
| aud | The "aud" (audience) claim identifies the recipients that the JWT is intended for. | Optional | 
| sub | The "sub" (subject) claim identifies the principal that is the subject of the JWT. | Optional | 
| scp | The "scp" (scope) claim is described in OAuth 2.0 Token Exchange as an array of strings, each of which represents an OAuth Scope granted for the issued security token. | Optional | 
| iat | The "iat" (issued at) claim identifies the time at which the JWT was issued. | Optional | 
| exp | The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. . | Optional | 
| nbf | The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing. | Optional | 
| additionalClaims | Additional claims to include in the request. | Optional | 
| tokenTimeout | Token Timeout in Seconds. Default is 300. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JWT.Token.ID | String | The JWT Token ID | 
| JWT.Token.AuthenticationToken | String | The JWT Authentication Token Value | 


#### Command Example
```!jwt-generate-authentication-payload iss="http://example.com" sub="3233-2344-4b52-2323-fc0bfb11e673" additionalClaims=`{"parameter1":"23323-323-4854-893c-b59610423ad"}````

#### Context Example
```json
{
    "JWT": {
        "Token": {
            "AuthenticationToken": "***",
            "ID": "66175ceb-f910-4b32-8a53-739ecf37a95d"
        }
    }
}
```

#### Human Readable Output

>### Results
>|AuthenticationToken|ID|
>|---|---|
>| *** |


### jwt-decode-token
***
A command to decode JWT tokens


#### Base Command

`jwt-decode-token`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token | The token to decode. | Required | 
| secret | The secret to validate the token signature. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!jwt-decode-token token="************************************.*********************************************************************************************************************************************************************************************************************************************************************.******************************************"```

#### Context Example
```json
{
    "JWT": {
        "DecodedToken": {
            "exp": 1622050583,
            "iat": 1622050283,
            "iss": "http://example.com",
            "jti": "009eb036-1e60-43e5-aad2-1187462db0be",
            "parameter1": "23323-323-4854-893c-b59610423ad",
            "sub": "3233-2344-4b52-2323-fc0bfb11e673"
        }
    }
}
```

#### Human Readable Output

>### Results
>|exp|iat|iss|jti|parameter1|sub|
>|---|---|---|---|---|---|
>| 1622050583 | 1622050283 | http://example.com | 009eb036-1e60-43e5-aad2-1187462db0be | 23323-323-4854-893c-b59610423ad | 3233-2344-4b52-2323-fc0bfb11e673 |
