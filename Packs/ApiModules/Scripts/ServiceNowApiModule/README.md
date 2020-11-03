The ServiceNow API handles the oauth2 authentication process and API requests. When developing a ServiceNow integration, follow these steps:
1. Import the API module to the integration.
2. Add the !servicenow-login command that will create a refresh token using the given credentials. The refresh token will be used to generate access tokens to the instance of the user.
3. (Optional) add the !servicenow-test command that will test the instance configuration. 

To use the common ServiceNow API logic, attach the `from ServiceNowApiModule import *  # noqa: E402` line of code in the following location to import it. After you import the module, the `ServiceNowClient` will be available for use.

```python
def main():
    ...


from ServiceNowApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

For examples, see the `ServiceNow_CMDB` integration.
