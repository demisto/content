# Group-IB Threat Intelligence

This section provides step-by-step instructions for configuring the Group-IB Threat Intelligence & Attribution integration instance in Cortex XSOAR.

## Prerequisites

1. **Access Group-IB TI Web Interface**
   - Open the Group-IB Threat Intelligence platform at [https://tap.group-ib.com](https://tap.group-ib.com)

2. **Generate API Credentials**
   - In the web interface, click your name in the upper right corner
   - Select **Profile** → **Security and Access** tab
   - Click **Personal token** and follow the instructions to generate your API token
   - **Note**: The API token serves as your password for authentication

## Configuration Steps

1. **Configure Connection Settings**
   - **GIB TI URL**: Enter your Group-IB TI web interface URL (default: `https://tap.group-ib.com/api/v2/`)
   - **Username**: Enter the email address you use to log into the web interface
   - **Password**: Enter your API token (Personal token) generated in step 2

2. **Configure Collection Parameters**

   **Important - Limit Parameter**:
   - The **Limit (items per request)** parameter specifies the number of records fetched per API request
   - This limit applies to **all collections** configured in the integration instance
   - For optimal performance, consult the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) for recommended limit values per collection
   - **Best practice**: Create separate integration instances for different collections or groups of collections with similar optimal limit values
   - **Example**: If "Number of requests per collection" is set to 2 and the limit is 500, the integration will fetch up to 1000 records per collection per fetch cycle (2 requests × 500 records each)

   **Collection-Specific Filters** (apply only to `compromised/account_group`):

   The following filters control data collection behavior for the `compromised/account_group` collection:

   - **Include combolist type in data**: When enabled, includes combolist data from the compromised/account_group collection
   - **Include unique type in data**: When enabled, includes unique data from the compromised/account_group collection
   - **Enable filter "Probable Corporate Access"**: When enabled, applies the "Probable Corporate Access" filter to the compromised/account_group collection

     **Filter Logic**:
     - If **both** `Include unique type in data` and `Include combolist type in data` are **disabled**: No filtering is applied, and both types of data are collected
     - If **only** `Include unique type in data` is **enabled**: Only unique records are collected. **Note**: The "Probable Corporate Access" filter is enabled by default when using unique type, so you don't need to enable it separately
     - If **only** `Include combolist type in data` is **enabled**: Only combolist records are collected
     - If **both** `Include unique type in data` and `Include combolist type in data` are **enabled**: Both types of data are collected

     **Important Note on "Probable Corporate Access" Filter**:
     - The "Probable Corporate Access" filter is **enabled by default** when `Include unique type in data` is enabled, as it is included in unique data types
     - If you are collecting **only combolist** data (without unique), you can enable `Enable filter "Probable Corporate Access"` to include probable corporate access records in the combolist data collection

     **Best Practice**:
     - For optimal organization and performance, consider running **two separate integration instances**:
       - **Instance 1**: Configure to collect unique data (with "Probable Corporate Access" enabled by default)
       - **Instance 2**: Configure to collect combolist data, with or without the "Probable Corporate Access" filter, depending on your requirements

   **Note**: These filters have no effect on other collections

   **Other Configuration Options**:
   - **Collections to fetch**: Select the collections you want to fetch incidents from
   - **Incidents first fetch**: Specify the date range for initial data fetch (default: "3 days")
   - **Number of requests per collection**: Number of API requests per collection in each fetch iteration (default: 3)
   - **Hunting Rules**: Enable to collect data using hunting rules (required for certain collections like `osi/git_repository`, `osi/public_leak`, and `compromised/breached`)

3. **Configure Classifier and Mapper**
   - Set up the classifier and mapper using the Group-IB Threat Intelligence & Attribution classifier and mapper, or configure your own custom classifier and mapper as needed

4. **Configure Pre-Processing Rules**
   - Navigate to **Settings** → **Integrations** → **Pre-Processing Rules**
   - Create a new pre-processing rule with the following configuration:
     - **Conditions**:
       - `gibid Is not empty (General)`
       - `Type Doesn't equal(String) GIB Data Breach`
     - **Action**: Run a script
     - **Script**: Select one of the following:
       - `GIBIncidentUpdate`: Recreates closed incidents if they receive updates; otherwise updates existing incidents
       - `GIBIncidentUpdateIncludingClosed`: Updates incidents only (does not recreate closed incidents)

5. **Network Configuration**
   - **Important**: Contact Group-IB support to add your Cortex XSOAR server's IP address to the allow list
   - If you are using a proxy, provide the public IP address of the proxy server instead

## Additional Resources

For detailed information about collections, their structure, available fields, and recommended date ranges, refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).
