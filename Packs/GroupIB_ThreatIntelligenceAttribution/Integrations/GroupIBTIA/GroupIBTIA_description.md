# Group-IB Threat Intelligence

This section provides step-by-step instructions for configuring the Group-IB Threat Intelligence integration instance in Cortex XSOAR.

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

2. **Configure Collection Parameters**

   - **Collections to fetch**: Select the collections you want to fetch incidents from. See the [Collections Overview documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Overview%2FCollections%20Overview).
   - **Incidents first fetch**: Specify the date range for initial data fetch (default: "3 days")
   - **Number of requests per collection**: Number of API requests per collection in each fetch iteration (default: 3)
   - **Limit (items per request)**: Specifies the number of records fetched per API request
     - This limit applies to **all collections** configured in the integration instance
     - For optimal performance, check the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations) for recommended limit values per collection
   - **Best practice**: Create separate integration instances for different collections or groups of collections with similar optimal limit values
   - **Example**: If "Number of requests per collection" is set to 2 and the limit is 500, the integration will fetch up to 1000 records per collection per fetch cycle (2 requests × 500 records each)
   - **Hunting Rules**: Enable to collect data using hunting rules
   - **Enable reputation commands**: Optional multi-select list of reputation commands to enable for this integration instance (supported: ip, domain, file). **Default: none enabled** (fail-safe). Only selected commands perform enrichment and return DBotScore.

   **Collection-Specific Filters** (apply only to `compromised/account_group`). The following three filters control data collection behavior for the `compromised/account_group` collection:
   - **Note**: These filters have no effect on other collections
   - **Include unique type in data**: Filter to include unique data from the compromised/account_group collection
   - **Include combolist type in data**: Filter to include combolist data from the compromised/account_group collection
   - **Enable filter "Probable Corporate Access"**: Filter to limit data collection to only corporate accounts
   - **Filter Logic** (applies to unique and combolist filters):
     - If **both** `Include unique type in data` and `Include combolist type in data` are **disabled**: No filtering is applied, and both types of data are collected
     - If **only** `Include unique type in data` is **enabled**: Only unique records are collected
     - If **only** `Include combolist type in data` is **enabled**: Only combolist records are collected
     - If **both** `Include unique type in data` and `Include combolist type in data` are **enabled**: Both types of data are collected
     - When both unique and combolist filters are **not enabled** (no checkboxes selected): Both unique and combolist data types are collected by default (as stated above). In this state, you can enable `Enable filter "Probable Corporate Access"` to limit the entire feed (both unique and combolist data) to only corporate accounts. You can also combine the corporate access filter with unique or combolist filters, if needed. For example, if you are collecting **only combolist** data (without unique), you can enable `Enable filter "Probable Corporate Access"` to limit the combolist collection to only corporate accounts
   - **Best Practice**: For optimal organization and performance, consider running **two separate integration instances**:
       - **Instance 1**: Enable `Include unique type in data` only
       - **Instance 2**: Enable `Include combolist type in data` only
       - **Instance 3** (optional): Enable 'Probable Corporate Access' - if you need to focus on your company employees compromises only

3. **Configure Classifier and Mapper**
   - Set up the classifier and mapper using the 'Group-IB Threat Intelligence' classifier and mapper, or configure your own custom classifier and mapper as needed

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

## Reputation Commands (ip / domain / file)

This integration implements the standard Cortex XSOAR reputation commands:

- `ip`
- `domain`
- `file`

### Required: use a dedicated instance for reputation

We recommend using a **dedicated** integration instance for reputation commands, such as **Group-IB Threat Intelligence (Partner Contribution)**.

### Enabling reputation commands

Reputation commands are **disabled by default** to avoid unexpected auto-enrichment side effects.
To enable them, configure the integration instance parameter **Enable reputation commands** and select the command types you want to allow (`ip`, `domain`, `file`).

### Source Reliability and override behavior

The integration supports **two reliability modes** for reputation commands:

- **Instance override mode (fixed reliability)**:
  - Controlled by the instance parameter **Source Reliability**.
  - When **Ignore Source Reliability override** is **disabled** (unchecked), the integration will attach the configured **Source Reliability** value to **every reputation response**, regardless of indicator-specific findings.

- **Integration-calculated reliability mode (dynamic reliability)**:
  - Enabled by the instance parameter **Ignore Source Reliability override**.
  - When **Ignore Source Reliability override** is **enabled** (checked), the integration ignores the instance **Source Reliability** value and calculates reliability per indicator based on the collections that returned matches (see rules below).

### Score (DBotScore) calculation rules

Score and reliability are calculated independently.

#### `file` score rules

- **BAD**: at least one match in `ioc/common`
- **UNKNOWN (NONE)**: no matches

Note: For `file` reputation, the integration evaluates **only** the `ioc/common` collection for score.

#### `domain` score rules

The integration uses a **3-year recency window** and the following date fields:

- `ioc/common.dateLastSeen`
- `hi/open_threats.detected`
- `attacks/deface.date`

Rules (evaluated top-to-bottom):

- **BAD**: `ioc/common` match with `dateLastSeen` within the last 3 years
- **SUSPICIOUS**: `hi/open_threats` or `attacks/deface` match with a date within the last 3 years
- **SUSPICIOUS**: `ioc/common` has records but `dateLastSeen` is missing or older than 3 years
- **UNKNOWN (NONE)**: no findings (no matches in `ioc/common`, `hi/open_threats`, `attacks/deface`)

#### `ip` score rules

The integration maps the numeric Group-IB `riskScore` (0..100) to DBotScore:

- **GOOD**: 0..49
- **SUSPICIOUS**: 50..84
- **BAD**: 85..100
- **UNKNOWN (NONE)**: score is missing or out of range

### Reliability calculation rules (only when Ignore Source Reliability override is enabled)

When the integration-calculated reliability mode is enabled, reliability is computed as follows:

#### `file` reliability rules

- **A - Completely reliable**: at least one match in `ioc/common`
- **None**: no matches

#### `domain` and `ip` reliability rules

Reliability is derived from which collections returned matches:

- **A - Completely reliable**:
  - any match in `apt/threat` or `apt/threat_actor`, or
  - any match in `ioc/common`

- **B - Usually reliable**:
  - any match in `attacks/deface`, or
  - any match in `hi/open_threats`

Final selection logic:

- If there is at least one **A - Completely reliable** source → reliability is **A - Completely reliable**
- Else if there is at least one **B - Usually reliable** source → reliability is **B - Usually reliable**
- Else → reliability is **None**

## Additional Resources

For detailed information about collections, their structure, available fields, and recommended date ranges, refer to the [Collections Overview](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Overview%2FCollections%20Overview).