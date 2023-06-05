Use the Tenable.sc integration to get a real-time, continuous assessment of your security posture so you can find and fix vulnerabilities faster.
All data in Tenable.sc is managed using group level permissions. If you have several groups, data (scans, scan results, assets, etc.) can be viewable but not manageable. Users with Security Manager role  can manage everything. These permissions come into play when multiple groups are in use.
It is important to know what data is manageable for the user in order to work with the integration.

## Use cases:

    * Create and run scans.
    * Launch and manage scan results and the found vulnerabilities.
    * Create and view assets.
    * View policies, repositories, credentials, users and more system information.
    * View alerts received in real-time.

**Added support for secret & access keys authentication method.** 

- Added support for secret & access keys authentication method (API Key Authentication) which can be generated from the Tenable SC UI while logged into the desired account.
- Secret & access keys needs to be generated twice, once for secman and once for admin.
- First, you need to enable API Key Authentication:

## [Steps to follow:](https://docs.tenable.com/security-center/Content/EnableAPIKeys.htm)

      1. Log in to Tenable Security Center via the user interface.
      2. Go to **System** > **Configuration**.
      3. Click the **Security** tile.
      4. In the Authentication Settings section, click **Allow API Keys** to enable the toggle.
      5. Click **Submit**.

- Second, you need to generate the API Key: 

## [Steps to follow:](https://docs.tenable.com/security-center/Content/GenerateAPIKey.htm)

      1. Log in to Tenable Security Center via the user interface.
      2. Go to **Users** > **Users**.
      3. Right-click the row for the user for which you want to generate an API key.
        -or-
        Select the checkbox for the user for which you want to generate an API key.
      4. Click **API Keys** > **Generate API Key**.
      5. Click **Generate**.
      6. The API Key window appears, displaying the access key and secret key for the user. Save the API keys in a safe location.
