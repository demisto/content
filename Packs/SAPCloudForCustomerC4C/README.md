## What does this pack do?

The SAP Cloud for Customer (C4C) integration facilitates the collection of audit events directly from your SAP C4C instance. It enables security teams to monitor user activities and system changes by fetching relevant event data for analysis and incident response.

#### This includes

- Efficient Pagination: Supports client-side pagination with $top and $skip parameters to handle large datasets efficiently (up to 1,000 records per page).
- Customizable Fetch Limit: Allows setting a maximum number of audit events to fetch per run (defaulting to 10,000).

### Timezone Configuration

Before configuring this integration, you **must** ensure that the timezone for the user configured in your SAP C4C instance matches the UTC format. Failure to do so may result in errors when fetching events due to timestamp mismatches.

To configure the timezone for your technical user in SAP C4C, follow these steps:

1. Log in to your SAP C4C system with an administrator account.
2. Navigate to **Application and User Management** -> **Business Users**.
3. Find and select the technical user that will be used for this integration.
4. Go to the **Details** section for the selected user.
5. Under the **General** tab, locate the **Time Zone** field.
6. Set the time zone to a UTC format (e.g., "UTC", "UTC+01:00", "UTC-05:00").
7. Save your changes.

For a detailed explanation and visual guide, please refer to the following SAP Community blog post: [Technical User Date Time Format Settings Change in C4C](https://community.sap.com/t5/crm-and-cx-blog-posts-by-members/technical-user-date-time-format-settings-change-in-c4c/ba-p/13581365).
