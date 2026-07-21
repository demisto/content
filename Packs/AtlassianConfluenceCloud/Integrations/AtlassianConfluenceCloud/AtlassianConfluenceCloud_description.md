## Atlassian Confluence Cloud Integration Help

Register for an account on [Confluence Cloud](https://www.atlassian.com/software/confluence?&aceid=&adposition=&adgroup=101907929911&campaign=9612158811&creative=425988944117&device=c&keyword=confluence%20cloud&matchtype=e&network=g&placement=&ds_kids=p52349416713&ds_e=GOOGLE&ds_eid=700000001542923&ds_e1=GOOGLE&gclid=CjwKCAjwmeiIBhA6EiwA-uaeFbxU-wiqFNoxltPxNhqPoCIBuKQsopVLzAlxJkcuf_UfWL81Jp2lJhoCZycQAvD_BwE&gclsrc=aw.ds) using your work email address.

This integration supports two authentication methods:

### Option 1: Basic Authentication (Email + API Token)

#### Create an API token
- Log in to the [Confluence Cloud](https://id.atlassian.com/manage/api-tokens) account.
- Click the "Create API Token" button.
- Enter a label for the token and click the "Create" button.

### Option 2: OAuth 2.0 Authentication

OAuth 2.0 provides a more secure authentication method using the Atlassian Developer Console.

#### Prerequisites
1. Access to the [Atlassian Developer Console](https://developer.atlassian.com/console/myapps/)
2. Admin access to your Confluence Cloud instance

#### Create an OAuth 2.0 App
1. Go to the [Atlassian Developer Console](https://developer.atlassian.com/console/myapps/)
2. Click "Create" and select "OAuth 2.0 integration"
3. Enter a name for your app and click "Create"
4. Navigate to "Permissions" and add the required Confluence API scopes. The integration uses the Confluence REST API v2 and requires the following granular scopes:
   - `read:audit-log:confluence` — **Required for event fetching** (audit log access)
   - `read:content:confluence`, `write:content:confluence`, `delete:content:confluence` — Read, write, and delete content
   - `read:content-details:confluence` — Read content details
   - `read:page:confluence`, `write:page:confluence`, `delete:page:confluence` — Read, write, and delete pages
   - `read:blogpost:confluence`, `write:blogpost:confluence`, `delete:blogpost:confluence` — Read, write, and delete blog posts
   - `read:custom-content:confluence`, `write:custom-content:confluence`, `delete:custom-content:confluence` — Manage custom content
   - `read:comment:confluence`, `write:comment:confluence` — Read and write footer comments
   - `write:template:confluence` — Manage templates
   - `read:space:confluence`, `write:space:confluence`, `delete:space:confluence` — Read, write, and delete spaces
   - `read:space-details:confluence` — Read space details
   - `read:group:confluence` — Read group information
   - `offline_access` — Enables refresh token for unattended access
5. Navigate to "Authorization" and configure the callback URL
6. Navigate to "Settings" to find your Client ID and Client Secret

#### Find Your Cloud ID
Your Cloud ID can be found by:
1. Navigate to your Confluence instance (e.g., https://your-site.atlassian.net)
2. Go to `https://your-site.atlassian.net/_edge/tenant_info`
3. The `cloudId` field contains your Cloud ID

#### Configure the Integration
1. Select "oauth" as the Authentication Type
2. Enter your Client ID
3. Enter your Client Secret
4. Enter your Cloud ID

> **Note:** If you are upgrading from a previous version, the new Confluence REST API v2 commands (pages, blog posts, footer comments, and spaces) require additional granular OAuth scopes. After adding the scopes listed above to your OAuth 2.0 app in the Atlassian Developer Console, you must re-authenticate by running `!confluence-cloud-oauth-start` and `!confluence-cloud-oauth-complete` again so the access token is reissued with the new permissions.