## Generate an API Key
To use Ivanti Heat, you need to generate an API key from the Ivanti tenant:
1. From the Configuration console, click **Configure > Security Controls > API Keys**.
2. Select the relevant group created for the REST API from the **Key Groups** section.
3. Click **Add API Key**. The application displays the New API Key page.
4. Enter values for the following fields.
- ***Reference ID*** - This field is auto-generated. This ID is the REST API Key you need to use for endpoint authorization.

- ***Activated*** - Select or clear the check box to activate and deactivate the key.

- ***Description*** - Enter a description for the key.

- ***On Behalf Of*** - Select the name of the user creating the key.

- ***In Role*** - Select a role for the user that you're creating the API key for
By default, the REST API Key created is applicable for the logged-in tenant. However, you can add additional IP addresses to this key. To do so, click **Add New IP** and enter the IP address and click **Ok**.

6. Click **Save Key**. The generated REST API Key is saved with the details you entered.

7. Click **Back** to return to the API Keys page.
