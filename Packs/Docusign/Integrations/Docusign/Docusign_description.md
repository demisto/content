# Configure DocuSign new application

Follow the steps below to create and configure a DocuSign application for use with this integration:

#### 1. **Access DocuSign Developer Portal**

* Open the DocuSign web UI and log in.
* Navigate to **Account**.
* From the left sidebar, click **Apps and Keys**.

#### 2. **Create a New Application**

* Click **Add App**.
* Provide a name for your application.
* Copy the **Integration Key**.

#### 3. **Setting Integration Type**

* Select the App integration type required for your workflow.

#### 4. **Configure Application Settings**

* Under **User Application**, select **Yes**.
* Under **Authentication Method for your App**, leave the default option, **Authorization Code Grant**.

#### 5. **Generate a Secret Key**

* Click **Add Secret Key** and generate a new secret key.

#### 6. **Generate RSA Key Pair**

* Under **Service Integration** Click **Generate RSA**.
* Copy the **Private Key**. (The public key is not used by the integration)

#### 7. **Set Redirect URI**

* Navigate to **Additional Settings**.
* Set the **Redirect URI** to `https://localhost`.

#### 8. **Save the Application**

* Click **Save** to finalize your application configuration.

#### 9. **Retrieve Organization ID**

* Navigate to the **Organization** tab from the left sidebar.
* Copy the **Organization ID** from the URL.

#### 10. Configure and Test

* Configure and save the instance.
* To use the Docusign integration and allow access to Docusign events, an administrator has to approve our app using an admin consent flow by running the ***!docusign-generate-consent-url*** command.
* Run the command ***!docusign-auth-test*** to test the full authentication flow and API connectivity.


# Prerequisites

The Docusign app needs to be configured as follows:

| **Data element** | **Description** |
|------------------|-----------------|
| You have defined an [integration key](https://developers.docusign.com/platform/configure-app/#integration-key). | An integration key identifies your integration and links to its configuration values. [Create an integration key.](https://developers.docusign.com/platform/configure-app/#how-to-get-an-integration-key) |
| You have defined a [redirect URI](https://developers.docusign.com/platform/configure-app/#redirect-uri) for your integration key. | The redirect URI is the URL to which Docusign redirects the browser after authentication. [Set a redirect URI.](https://developers.docusign.com/platform/configure-app/#how-to-set-a-redirect-uri) |
| Your application has an [RSA key pair](https://developers.docusign.com/platform/configure-app/#rsa-key-pair). | [Add the RSA key pair.](https://developers.docusign.com/platform/configure-app/#add-the-rsa-key-pair)<br>Note: You can define a maximum of 5 RSA key pairs. If you have already defined 5 key pairs, you must delete one of them before creating a new one. |
