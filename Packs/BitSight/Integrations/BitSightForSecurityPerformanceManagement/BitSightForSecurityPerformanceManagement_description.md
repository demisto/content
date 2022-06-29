### Getting Started with BitSight for Security Performance Management

To get started with the integration, contact BitSight support so that your BitSight portal can be enabled to share findings with Cortext XSOAR.

API Key: BitSight customers can generate an API token to enable communication between BitSight and Cortex XSOAR. Steps for generating an API token:

1) Login to BitSight SPM at https://service.bitsighttech.com/app/spm/.
2) Click on the gear icon in top-right side.
3) In the dropdown menu, click on "Account".
4) In the "User Preferences" tab, there will be a section "API Token" to generate a new API Token.
5) Click on "Generate New Token" and use that token to authenticate the BitSight integration in XSOAR.

Company's GUID: Each company monitored by BitSight is identified by a unique identifier (Global Unique Identifier, or GUID). In addition, each subsidiary company associated with a parent company also has a GUID and is organized in a hierarchical tree structure.

You can specify the GUID for a parent or subsidiary company in your company tree. Any issues related to that company and its child companies in the tree structure will be retrieved. You can easily find the GUID for your parent organization by executing the following command:


"bitsight-companies-guid-get"

First fetch time in days: When running for the first time, the integration will take input from this parameter and retrieve incidents for the given number of days.

Findings Minimum Severity: This parameter helps to filter the record based on minimum severity entered here. You can choose one of the severity listed.

Findings Minimum Asset Category: This parameter helps to filter the record based on the minimum asset category entered here. You can choose one of the asset categories listed.

Findings Grade: This parameter helps to filter the record based on Grade. You can choose multiple grades listed.

Risk Vector: Parameter helps to filter the record based on Risk Vector. By default, 'All' will be selected, if you need only particular values you can unselect 'All' and select the required values listed.

Note: Please be sure to click on 'Reset the "last run" timestamp', when changing the values of parameters 'First fetch time in days', 'Findings Minimum Severity', 'Findings Minimum Asset Category', 'Findings Grade' or 'Risk Vector' after fetching has started to avoid dropping of findings.
