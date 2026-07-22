1. **Create a Service Account**  
Follow the instructions [here](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount) in the "Creating a Service Account" section.
---
2. **Delegate Domain Wide Authority and Authorize API Access**  
If you wish the Service Account to have authorized access to all Google Cloud Platform resources on behalf of all users for the associated G Suite domain then follow the instructions [here](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#delegatingauthority) to Delegate Domain Wide Authority.
---
3. **Enable Access to the Google Resource Manager API**   
In Google Cloud Platform console Dashboard page for the project in which you created the Service Account scroll to the Getting Started section and click on "Explore and enable APIs". Alternatively you can click the Navigation Menu button in the top left and in the navigation menu click the "APIs & Services" button. Towards the top of the page click the button that says "+ ENABLE APIS AND SERVICES". Search "google resource manager" in the search bar and enable the API.
---
4. **Grant Permissions**  
In order for the Service Account to carry out certain Google Resource Manager API commands, it is required that you grant the Service Account roles with the necessary permissions. To give the Service Account Organization-wide permissions, navigate to your organization's page. You can do this by clicking the Navigation Menu in the top left of the page, hover over "IAM & admin" and click "Identity & Organization" in the resulting popout menu. It will direct you to a page that will tell you that the page is not viewable for projects and ask you to select an organization. Select your organization. Select "IAM" from the menu on the left. Click the "ADD" button towards the top of the page and add your Service Account by entering the Client Email associated with the Service Account. To grant your Service Account the ability to create new project assign your Service Account the roles of Owner and Project Creator. To grant your Service Account the ability to update projects, assign your Service Account the addional roles of Editor and Project Mover.
---
5. **Setup Integration Instance**  
All the integration parameters to set up an instance are in the Service Account Credentials File that was downloaded to your machine in step 1 when you created a Service Account. Copy each value to its matching integration parameter without its surrounding quotes.