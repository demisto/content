# Cloudflare WAF Authentication Methods

Cloudflare WAF supports two different authentication methods for API access:

1.  API Token Authentication (Recommended)
    - Uses a Bearer Token to authenticate requests.
    - This method is more secure as it allows granting limited permissions based on specific use cases.
    - Requires defining permissions and resources for the token.


2.  Global API Key Authentication
    - Uses an email address and a Global API Key to authenticate requests.
    - This method provides full account access and should be handled with caution.

Each method has its own setup process and security implications. Below, you will find details on how to obtain and use each authentication method.
note: *Any user role can create user based API tokens and the permissions they can assign to a token is any subset of their existing user permissions*

Note: When both an API token and a global API key/email are provided, the API token will take priority.

# Authenticating Using API Token (Recommended)

## How to create an API Token

1. Log into the  [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. Go to `User Profile` -> `API Tokens` or simply [click here](https://dash.cloudflare.com/profile/api-tokens).
3. Click **Create Token**.
4. Use Templates for a quick setup or define a custom token.

## Customizing the API Token

When creating an API token, you must define:

- Token Name – A descriptive name for reference.
- Permissions – Defines what actions the token can perform
- Resources – Specifies which accounts/zones the token can access.

## Token Permissions

Permissions are categorized based on resources:

- Zone Permissions
- Account Permissions
- User Permissions

Each category contains specific Permission Groups that define what the token can do. You can set:

- Edit (Full CRUDL access)
- Read (Limited access for viewing and listing)

## Token Resources

The resources selected will be the only ones that the token can interact with.

## Generating and Storing the Token

Once generated, the API token secret is only shown once.
Ensure you copy and store it securely.

## Finding Zone and Account IDs

After [setting up a new account](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/account-setup/) and [adding your domain](https://support.cloudflare.com/hc/articles/201720164#2YulMb5YJTVnMxgAgNWdS2), you may need access to your Zone ID and Account ID for API requests.

How to find your Zone and Account IDs

1. Log into the [Cloudflare dashboard](https://dash.cloudflare.com/login).
2. Select your account and domain.
3. On the Overview page, locate the API section.
4. The API section displays your Zone ID and Account ID. Click **Copy** to use them in API requests.


# Authenticating Using Global API Key

## Where to find your Auth API key

1. Log into the  [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. Go to `User Profile` -> `API Tokens` or simply [click here](https://dash.cloudflare.com/profile/api-tokens).
3. Click **API Keys** -> **Global API Key** -> **View**.
4. Copy the API key and store it securely.

## Token Permissions

- The Global API Key provides full account access and cannot be restricted to specific permissions like an API Token.
- For better security, it is recommended to use API Tokens instead of the Global API Key whenever possible.


## Token Resources

The Global API Key provides full access to all resources within your Cloudflare account. Unlike API Tokens, the Global API Key cannot be restricted to specific resources or permissions. It grants full administrative privileges over all zones, accounts, and services linked to the account.

## Finding Zone and Account IDs

After [setting up a new account](https://developers.cloudflare.com/fundamentals/get-started/basic-tasks/account-setup/) and [adding your domain](https://support.cloudflare.com/hc/articles/201720164#2YulMb5YJTVnMxgAgNWdS2), you may need access to your Zone ID and Account ID for API requests.

How to find your Zone and Account IDs

1. Log into the [Cloudflare dashboard](https://dash.cloudflare.com/login).
2. Select your account and domain.
3. On the Overview page, locate the API section.
4. The API section displays your Zone ID and Account ID. Click **Copy** to use them in API requests.