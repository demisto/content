# Group-IB Threat Intelligence Feed

This section provides step-by-step instructions for configuring the Group-IB Threat Intelligence Feed integration instance in Cortex XSOAR.

## Prerequisites

1. **Access Group-IB Threat Intelligence (TI) Web Interface**
   - Open the Group-IB TI platform at [https://tap.group-ib.com](https://tap.group-ib.com)

2. **Generate API Credentials**
   - In the web interface, click your name in the upper right corner
   - Select **Profile** → **Security and Access** tab
   - Click **Personal token** and follow the instructions to generate your API token
   - **Note**: The API token serves as your password for authentication

3. **Network Configuration**
   - **Important**: Contact Group-IB support to add your Cortex XSOAR server's IP address to the allow list
   - If you are using a proxy, provide the public IP address of the proxy server instead
   - Make sure you have added Group-IB [API IPs/URLs](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FInitial%20Steps%2FInitial%20Steps) to you FW/Proxy rules.

## Configuration Steps

1. **Configure Connection Settings**
   - **GIB TI URL**: Enter your Group-IB TI web interface URL (default: `https://tap.group-ib.com/api/v2/`)
   - **Username**: Enter the email address you use to log into the web interface
   - **Password**: Enter your API token (Personal token) generated in step 2
   - **Trust any certificate (not secure)**: Whether to allow connections without verifying SSL certificates validity
   - **Use system proxy settings**: Whether to use XSOAR system proxy settings to connect to the API

2. **Configure Collection Parameters**

   - **Fetches indicators**: Enable to fetch indicators from the feed (default: enabled)
   - **Indicator collections**: Select the collections you want to fetch indicators from. Read more about collections [here](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details)
   - **Indicators first fetch**: Specify the date range for initial data fetch (default: "3 days")
   - **Number of requests per collection**: Number of API requests per collection in each fetch iteration (default: 2). Each request picks up to 100 (limit) objects with different amount of indicators. If you face runtime errors, lower the value.
   - **Limit (items per request)**: Specifies the number of records fetched per API request (default: 100)
     - This limit applies to **all collections** configured in the integration instance
     - For optimal performance, check the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) for recommended limit values per collection
   - **Best practice**: Create separate integration instances for different collections or groups of collections with similar optimal limit values
   - **Example**: If "Number of requests per collection" is set to 2 and the limit is 100, the integration will fetch up to 200 records per collection per fetch cycle (2 requests × 100 records each)

   **Configure Feed Behavior Settings**:
   - **Indicator Reputation**: Dropdown (default: "Suspicious") - "Indicators from this integration instance will be marked with this reputation" (options: Unknown, Benign, Suspicious, Malicious). As example, recomended to use Malicious to IOC common and Suspicious for Suspicious IP collections
   - **Source Reliability**: Select the reliability rating for the source (**required**, default: A - Completely reliable). Options: A - Completely reliable, B - Usually reliable, C - Fairly reliable, D - Not usually reliable, E - Unreliable, F - Reliability cannot be judged
   - **Feed Fetch Interval**: Configure how often to fetch indicators (hours and minutes, default: 1 minute)
   - **Bypass exclusion list**: When enabled, bypasses the exclusion list for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system.
   - **Tags**: Enter tags for indicators if needed
   - **Traffic Light Protocol Color**: Select the Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. Options: RED, AMBER, GREEN, WHITE (AMBER by default)
   - **Indicator Expiration Method**: Configure how indicators expire. Options: Time Interval, Never Expire, When removed from the feed

3. **Configure Classifier and Mapper**
   - Set up the classifier and mapper using the 'Group-IB Threat Intelligence' classifier and mapper, or configure your own custom classifier and mapper as needed

## Additional Resources

For detailed information about collections, their structure, available fields, and recommended date ranges, refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).