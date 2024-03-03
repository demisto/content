## Redmine Integration
- Redmine is a flexible project management web application. Written using the Ruby on Rails framework, it is cross-platform and cross-database.
- Redmine is open source and released under the terms of the GNU General Public License v2 (GPL).

## Authentication:
1. Use your server URL to enter to your account. 
2. Enter your username and password.
3. Navigate to "My Account" at the top right corner of the page.
4. Click on the API access key -> Show - this is your API key.
5. Fill it in the Redmine integration authentication window.
6. If you would like to display data related only to a project with id x- Fill it in the Redmine integration authentication window.
 
## General instructions
1. When searching for a specific ID (like issue_id etc...) make sure this object ID exists, otherwise you wil get an error code [404]- NOT FOUND or [422]- Unprocessable Entity

2. When adding a file to an issue- first upload it to the XSOAR War Room, then search for the id in the three dots in the top right, the add this entry_id to the request as file_entry_id=the entry id you created

3. To create a custom field go to server URL with admin privilege -> Administration (top left) -> Custom fields -> New custom field

### Your API key carries all your privileges, so keep it secure and don’t share it with anyone.
         