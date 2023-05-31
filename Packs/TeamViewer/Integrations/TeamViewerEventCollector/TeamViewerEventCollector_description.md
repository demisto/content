## TeamViewer
Use this integration to collect events automatically from TeamViewer.
You can also use the ***teamviewer-get-events*** command to manually collect events.

TeamViewer event collector collects the following event types:
* AuditEvents 
* CompanyAdministration
* GroupManagement
* UserProfile
* Session
* CustomModules
* Policy

### Script Token
To use the TeamViewer collector, you would need to create a script token.
Notice that A Tensor license is required.

1. Log in to the Management Console: https://login.teamviewer.com/
2. Click on your user in the upper right corner and select **Edit profile**.
3. Select **Apps**.
4. Select **Create script token**.
5. Tick all the permissions you need for your token (User access token scope: Event logging - is needed ).
6. Select **Create**.
7. The token has now been added to the Apps and Scripts list. To get your token, click on the newly created token. The token will be displayed under the token name.

[For more information, click here](https://community.teamviewer.com/English/kb/articles/109647-use-the-teamviewer-api).


