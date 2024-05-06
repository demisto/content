## Redmine Integration

- Redmine is a flexible project management web application. Written using the Ruby on Rails framework, it is cross-platform and cross-database.
- Redmine is open source and released under the terms of the GNU General Public License v2 (GPL).

## Authentication:

1. Navigate to your server URL to access your account.
2. Enter your username and password.
3. Go to "My Account" located at the top right corner of the page.
4. Click **API access key** and select **Show** to reveal your API key.
5. Input the API key into the Redmine integration authentication window.

## General notes

- Your API key determines your role in Redmine. 
- If you have insufficient permissions when using commands such as "update" or "create," certain fields may remain unchanged due to insufficient privileges. In such cases, while the command itself will not fail, those particular fields will not be updated.
- If you would like to display data related only to a project with ID x-. Fill it in the Redmine integration authentication window.
         