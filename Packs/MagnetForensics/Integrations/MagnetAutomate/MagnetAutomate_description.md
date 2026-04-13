# Magnet Automate

## Setup Instructions

### Prerequisites
To configure this integration, you will need:
1.  A valid Magnet Automate instance.
2.  An API key generated from the Magnet Automate interface.
3.  The server URL of your Magnet Automate instance.

### Obtain the API Key
1.  Log in to your Magnet Automate interface.
2.  Navigate to the **Settings** or **API Management** section (refer to your Magnet Automate version documentation for the exact location).
3.  Generate a new API Key and copy it for use in the XSOAR integration configuration.

### Server URL Format
The Server URL must be provided in the following format:
`https://{hostName}:{port}`
Example: `https://automate.example.com:5000`

## Usage Notes
### Custom Fields
Magnet Automate allows for the definition of custom fields for cases. To ensure successful case creation, it is recommended to use the `ma-forensics-custom-fields-list` command. This command retrieves a list of all available custom fields and their requirements, which can then be mapped to the case creation arguments in XSOAR.
