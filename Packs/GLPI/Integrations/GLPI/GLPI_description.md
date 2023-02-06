# Instance configuration

In order to use GLPI on Cortex XSOAR, you need to generate an API and user keys.


**API Activation**

1 - Login to your GLPI application, go to the Setup / General / API page.
2 - Make sure the API and "Enable login with external token" options are enabled.


**Generate keys**

Generate the **Application Token** :

1 - On the Setup / General / API page, click on the "Add API client" button.
2 - Ensure to set the Active field to yes and click the regenerate checkbox.
3 - Once created, you can copy the Application token from the item page. 

Generate the **User Token**

1 - Visit your profile preference page.
2 - On the remote access keys section, click regenerate next to API token.
3 - Once saved you can copy the User Token and paste it in the instance configuration page.

Ensure the API user's timezone is set to **UTC** 