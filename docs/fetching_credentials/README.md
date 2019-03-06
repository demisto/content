# Fetching Credentials

As seen [here](https://support.demisto.com/hc/en-us/articles/115002567894), it is possible to integrate with 3rd party credentials 
vaults for Demisto to use when authenticating with integrations. This article provides an example of such integration.

## Requirements

In order to fetch credentials to the Demisto credentials store, the integration needs to be able to retrieve credential objects 
in the format of a username and password (key:value).

## Implementation

### isFetchCredentials Parameter
  
For this example we are going to look at the HasiCorp Vault integration. The first thing you need to do is add a boolean parameter with the name:
`isFetchCredentials`(You can give it a different display name). When this parameter is set to true, Demisto will fetch credentials from the integration.
It would look like something like this: ![image](https://user-images.githubusercontent.com/35098543/53886096-eae09600-4027-11e9-8c2d-a46078c3dcc4.png)
![image](https://user-images.githubusercontent.com/35098543/53886311-69d5ce80-4028-11e9-9755-08585fecff34.png)

### fetch-credentials Command

When Demisto tries to fetch credentials from the integrations, it will call a command called `fetch-credentials`.
This is where you should implement the credentials retrieving logic:
```python
if demisto.command() == 'fetch-credentials':
   fetch_credentials()
```

### Creating credentials objects

In the `fetch_credentials` function, you should retrieve the credentials from the vault and create new JSON objects in the format:
```json
{
  "user": "username",
  "password": "password",
  "name": "name"
}
```

In the end you should have a credentials list that contains the above objects.

When you're done creating the credentials objects, send them to the credentials store by using:
`demisto.credentials(credentials)`.

## Result
If everything went well you should be able to see the credentials in the Demisto credentials store:
![image](https://user-images.githubusercontent.com/35098543/53886981-f339d080-4029-11e9-9d27-a76b85d2d025.png)
Note that these credentials cannot be edited or deleted, they reflect what's in the vault. You can stop fetching credentials by unticking the 
`Fetch Credentials` checkbox in the integration settings.


## Troubleshooting
In case of an error during the process, you can debug your code by adding a test command that calls the `fetch_credentials` function.
Make sure you send a credentials list in the right format and as a valid JSON.






