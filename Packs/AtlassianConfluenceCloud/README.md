# Atlassian Confluence Cloud

Atlassian Confluence Cloud is a collaborative workspace developed by Atlassian, designed to help teams create, organize, and share content seamlessly in the cloud. It enables users to build dynamic pages for project documentation, meeting notes, and knowledge bases, all in real time.

<~XSIAM>

## What does this pack contain?

- Rest API Log collection for audit events
- Parsing rules
- Modeling rules for audit events

## Configuration on Server Side

### Create an API token with scopes

1. Log in to your Atlassian account and navigate to [API Tokens](https://id.atlassian.com/manage-profile/security/api-tokens).
2. Select **Create API token** with scopes.
3. Give your API token a name that describes its purpose.
4. Select an expiration date for the API token. (*Token expiration is 1 to 365 days*.)
5. Select the **app** you’d like the API token to access.
6. Select the **scopes** to determine what the API token can do in Jira or Confluence.
    - *select **Confluence***.
7. Select **Create**
8. Select **Copy to clipboard**, then paste the token in your Cortex XSIAM integration.

For more inofrmation use the following guide [here](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/).

## Configuration in Cortex XSIAM

### Configure the Atlassian Confluence Cloud integration instance settings in Cortex XSIAM  

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Site Name (e.g., https://${site-name}.atlassian.net) | Site name of the Confluence cloud the user wants to connect to. | True |
| Email | The Atlassian account email. | True |
| API Token | Your API token generated in the **Create an API token with scopes** section. | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Events Fetch Interval |  | False |
| Max number of events per fetch |  | False |
| Fetch Events |  | False |

</~XSIAM>
