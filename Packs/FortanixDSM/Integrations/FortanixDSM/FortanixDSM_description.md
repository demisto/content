## Fortanix Data Security Manager

### Authentication
The integration supports the following auth methods:

#### User/password or Client Certificate Auth Method
These fields accept  the *Username*  and *Password* parameters for a user or App. These credentials may also be used for mutual-TLS using a client key and certificate. The may be signed by a Trusted CA if Fortanix DSM is configured accordingly.
#### API KEY Auth Method
An easy and quick way to test the integration is to specify the *Basic Authentication token* parameter from the Fortanix DSM App's API KEY.

### Playground Commands
The integration supports the following commands for execution:

#### fortanix-test
- Checks the connection with the Fortanix DSM server based on the instance settings.
- !fortanix-test

#### fortanix-list-secrets
- Lists all secrets from the Fortanix DSM App's member groups or a specified group, if any.
- !fortanix-list-secrets
- !fortanix-list-secrets group_id=aedc4bd0-2880-4191-8f38-043fce5ee97

#### fortanix-get-secret-metadata
- Get secret metadata based on its name or UUID, as specified.
- !fortanix-get-secret-metadata name="Test Secret"
- !fortanix-get-secret-metadata kid=09299af7-0d69-4091-9dc7-27d426667847

#### fortanix-fetch-secret
- Retrieve secret's confidential value based on a UUID.
- !fortanix-fetch-secret kid=4bd14880-522d-4c34-8560-617e0fb6485b

#### fortanix-new-secret
- Import a new secret along with its confidential value, into the Fortanix DSM App's default or a specified group, if any.
- !fortanix-new-secret value="Top Secret !3$8" name=metasec metadata="key1=value1, key2=meta2,key3=\"whats that\",key 4=nothin new" group_id=07f85883-adaf-4a6c-a040-ffed46dfd349

#### fortanix-rotate-secret
- Update an existing secret's confidential value by rotating out of it and obtaining a new UUID.
- !fortanix-rotate-secret value="Fib0nac!I !3$8" name=metasec metadata="key1=value01,key2=meta2a,key3=\"whats that\",key 4=nothin new" group_id=07f85883-adaf-4a6c-a040-ffed46dfd349

#### fortanix-delete-secret
- Delete an existing secret. This may be revocable if there is a Key Undo policy applied on the group.
- !fortanix-delete-secret kid=30d7286a-ad4c-4cb3-8bb1-0f9265e0adfc

#### fortanix-invoke-plugin
- Execute Lua code through a Fortanix Plugin running on Fortanix DSM using Confidential Computing. Requires the plugin UUID and an arbitrary user input, based on the plugin's functionality.
- !fortanix-invoke-plugin pid=3599796b-7b18-49c3-aad8-9758af24fbf9
- !fortanix-invoke-plugin pid=3599796b-7b18-49c3-aad8-9758af24fbf9 input="Hello World Oct 29"
- !fortanix-invoke-plugin pid=c6a5351e-d516-4099-b5c9-be00c6967a53 input=ewogICJjYV9rZXkiOiAiU1NIQ0EtUHJpdmF0ZS1LZXktRWQyNTUxOSIsCiAgInB1YmtleSI6ICJBQUFBRTJWalpITmhMWE5vWVRJdGJtbHpkSEF5TlRZQUFBQUlibWx6ZEhBeU5UWUFBQUJCQkt0R3dTeFhWdU4zbXFkaE9YNXozVjBNT243MkRJNWNQQThzSXBTemJSVjZnNTNRYW0yVzNNaW1JdlNaazkxL2x4aFNXRE82RmUxQXVqYy9VQ2VCc3lNPSIsCiAgImNlcnRfbGlmZXRpbWUiOiAzNjAwLAogICJ2YWxpZF9wcmluY2lwYWxzIjogInVidW50dSIsCiAgImNlcnRfdHlwZSI6ICJ1c2VyIiwKICAiY3JpdGljYWxfZXh0ZW5zaW9ucyI6IHt9LAogICJleHRlbnNpb25zIjogewogICAgInBlcm1pdC1wdHkiOiAiIgogIH0KfQo=
- !fortanix-invoke-plugin pid=3599796b-7b18-49c3-aad8-9758af24fbf9 input="{\"iv\":\"DaRIkBoCaAPqpGSczBeVGQ==\",\"kid\":\"3451bf0b-1728-4b9a-9859-f1c6bd0d8652\",\"op\":\"decrypt\",\"cipher\":\"ZmHxqmbgYGAtauvCnco7EA==\"}"

#### fortanix-encrypt
- Protect sensitive information or data using a Fortanix DSM key with default cryptographic parameters
- !fortanix-encrypt data="Hello World 123"

#### fortanix-decrypt
- Reveal sensitive information or data using a Fortanix DSM key with default cryptographic parameters
- !fortanix-decrypt cipher=eyJraWQiOiAiY2E5ZTJiMGYtNzFjNC00ZjNiLWJhYTYtNGM1YWY5YTM5N2YwIiwgImNpcGhlciI6ICJqcGxqVUk2S2tIb3drbHhhdG1MWXVBPT0iLCAiaXYiOiAidDFJczFWUTR3TlRFOThLZHR2aUlWZz09IiwgIm1vZGUiOiAiQ0JDIn0=
- !fortanix-decrypt cipher=u2KMcAUF1jsifJfh99uWqw== iv=r7HeHduHSZ1IrCC6s7MG0w==
- !fortanix-decrypt kid=ca9e2b0f-71c4-4f3b-baa6-4c5af9a397f0 cipher=u2KMcAUF1jsifJfh99uWqw== iv=r7HeHduHSZ1IrCC6s7MG0w==