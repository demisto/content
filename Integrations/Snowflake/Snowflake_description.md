## Integration Parameters

### Account
The Snowflake account that you wish to connect to. Do not include the Snowflake
domain name (snowflakecomputing.com) as part of the parameter. For example, if
you typically connect to the Snowflake portal at 'examplecompany.snowflakecomputing.com'
then the account name you would enter here would be 'examplecompany'. For more
information regarding this parameter please visit this [link](https://docs.snowflake.net/manuals/user-guide/python-connector-api.html#label-account-format-info).

### Authentication
This parameter is optional and only intended if you wish to login to your Snowflake account via Okta. If you wish to use this method of connecting
to your Snowflake account then the 'Username' parameter should be your '<okta_login_name>',
'Password' should be your '<okta_password>' and the value entered here should
be 'https://<okta_account_name>.okta.com/' where all the values between the less
than and greater than symbols are replaced with the actual information specific
to your okta account.

### Credentials
If you would like to use Key Pair authentication to authenticate
to your Snowflake account you must do the following:
1. Follow steps 1-4 in the
instructions outlined [here](https://docs.snowflake.net/manuals/user-guide/python-connector-example.html#using-key-pair-authentication).
2. After carrying out the aforementioned steps follow the instructions under the
section titled **Configure Demisto Credentials** at this [link](https://support.demisto.com/hc/en-us/articles/115002567894).
3. Once you have done so, the two images at the bottom of the section titled **Configure
an External Credentials Vault** demonstrate how to utilize the credentials you setup
in the last step.

Happy Snowflaking!