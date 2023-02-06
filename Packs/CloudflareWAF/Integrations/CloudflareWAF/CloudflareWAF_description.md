# Authenticating
In order to connect to the Cloudflare WAF, please follow these steps:

- To get started creating an API Token, log into the [Cloudflare Dashboard](https://dash.cloudflare.com/) and go to `User Profile` -> `API Tokens` or simply [click here](https://dash.cloudflare.com/profile/api-tokens).
- From the API Token home screen select `Create Token`.
- If you are new to API Tokens or the Cloudflare API, Templates are the quickest way to get started.

## Customizing the Token
There are 3 required inputs to creating a Token:

1. The token name
2. The permissions granted to the token
3. The resources the token can affect

### Token Name
This can be anything text and should be informative of why or how the token is being used as a reference.

### ​​Token Permissions
Permissions are segmented into three categories based on resource:

1. Zone Permissions
2. Account Permissions
3. User Permissions

Each category contains Permission Groups related to those resources. A full list of the Permission Groups can be found here.

After selecting a Permission Group, you can choose what level of access to grant the token. Most groups offer Edit or Read options. Edit is full CRUDL (create, read, update, delete, list) access, while Read is just the read permission and list where appropriate.

### Token Resources

The resources selected will be the only ones that the token will be able to perform the authorized actions against.

## Generating the Token
Once successfully generated, the token secret is only shown once. Make sure to copy the secret to a secure place.

# Find zone and account IDs
Once you [set up a new account](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/account-setup/) and [add your domain](https://support.cloudflare.com/hc/articles/201720164#2YulMb5YJTVnMxgAgNWdS2) to Cloudflare, you may need access to your zone and account IDs for API operations.
To find your zone and account IDs:

1. Log into the [Cloudflare dashboard](https://dash.cloudflare.com/login) and select your account and domain.
2. On the Overview page (the landing page for your domain), find the API section.
3. The API section contains your Zone ID and Account ID. To copy these values for API commands or other tasks, click Click to copy.