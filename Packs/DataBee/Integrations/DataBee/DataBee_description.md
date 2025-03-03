## Authentication Methods for DataBee

DataBee integration supports two primary methods of authentication: via an API Token or through the use of a username and password. Below are the detailed steps for each method.

### Obtaining a DataBee API Token

To authenticate using an API Token, follow these steps:

1. **Log in** to your DataBee account.
2. Navigate to the **API Documentation** by clicking the documentation icon (question mark button), located to the left of the settings button.
3. In the API Documentation page, click the text that reads *"API Token** at the top of the page. Your API Token will be automatically copied to your clipboard.

### Authenticating with an API Token

Once you have your API Token, you can use it to authenticate in the following way:

1. Create a Cortex  **XSOAR credential** and paste your API Token into the credential's password field.
2. To apply your Cortex XSOAR credential, click **"Switch to credentials"** in the instance settings.

### Authenticating with a Username and Password

If you prefer to use a username and password for authentication, you have two options:

1. **Using Cortex XSOAR credentials:**
   - Create a Cortex **XSOAR credential**, entering your username and password into the respective fields.
   - Apply your Cortex XSOAR credential by clicking **"Switch to credentials"** in the instance settings.
2. **Using instance text fields:**
   - Enter your DataBee username in the **username text field**.
   - Enter your DataBee password in the **password text field**.


## Findings additional context output
Use the additional findings context outputs field to add additional context data to retrieve from the API.
**Be aware that requesting extensive context data may impact your server's performance.**
