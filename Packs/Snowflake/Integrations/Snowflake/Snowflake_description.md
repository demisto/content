## Integration Parameters

### Account
The name of the Snowflake account to connect to without the domain name: snowflakecomputing.com. For example, mycompany.snowflakecomputing.com, enter "mycompany". For more information, see the [Snowflake Computing documentation](https://docs.snowflake.net/manuals/user-guide/python-connector-api.html#label-account-format-info).

### Authenticator
(Optional) Use this parameter to log in to your Snowflake account using Okta. For the 'Username' parameter, enter your '<okta_login_name>'. For the 'Password' parameter, enter your '<okta_password>'. The value entered here should be 'https://<okta_account_name>.okta.com/' where all the values between the less than and greater than symbols are replaced with the actual information specific to your Okta account.

### Credentials
To use Key Pair authentication, follow these instructions:
1. Follow steps 1-4 in the instructions detailed in the [Snowflake Computing documentation](https://docs.snowflake.net/manuals/user-guide/python-connector-example.html#using-key-pair-authentication).
2. Follow the instructions under the section titled **Configure Cortex XSOAR Credentials** at this [link](https://support.demisto.com/hc/en-us/articles/115002567894).
3. Use the credentials you configured. Refer to the two images at the bottom of the section titled **Configure an External Credentials Vault**.