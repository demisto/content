This integration provides the ability to import **Palo Alto Networks - Prisma Cloud Compute** alerts into Cortex XSOAR.

**Important**: Before you can use the Prisma Cloud Compute integration in Cortex XSOAR, there are several configuration steps required on the Prisma Cloud Compute console.

## Configure Prisma Cloud Compute to send alerts to Cortex XSOAR by creating an alert profile.

1. Log in to your Prisma Cloud Compute console.
2. Navigate to **Manage > Alerts**.
3. Click **Add Profile** to create a new alert profile.
4. On the left, select **Demisto** from the provider list.
5. On the right, select the alert triggers. Alert triggers specify which alerts are sent to Cortex XSOAR.
6. Click **Save** to save the alert profile.
7. Make sure you configure the user role to be at least `auditor`, otherwise you will not be able to fetch the alerts.
