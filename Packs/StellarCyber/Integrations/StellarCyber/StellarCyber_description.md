## Stellar Cyber Help

### Required Privileges to Make API Calls

To perform API calls, you must have:

- Root scope
- Super Admin privileges (must be the default profile template)

We recommend creating a Stellar Cyber user dedicated to API calls. That way you can easily track changes made through API calls under System | Administration | Users | Activity Log.

### Necessary Information to Make API Calls

Calls to the Stellar Cyber API typically require a subset of the following information:

- Username
- API Key

Generate an API key as follows:

- Navigate to the System | Administration | Users page.
- Locate the user account to perform the API call and click the Edit () button in its row. Remember that the user performing the call must have Root scope and Super Admin privileges.
- Locate the API Access item in the dialog box that appears and click the Generate New Token button.
- Copy and paste the token into a text file to store it temporarily.