### Proofpoint CASB
This pack includes parsing and modeling rules for Proofpoint CASB logs sent via HTTP Event Collector.

### Supported Timestamp Formats:
Timestamp is extracted from the occurredAt field with the following format - yyyy-mm-ddTHH:MM:SS.SSSZ

### Collect Events from Proofpoint CASB (XSIAM)

**On XSIAM side:**

1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source**.
2. From the Type dropdown list, select **Custom Integrations**.
3. Click **Custom - HTTP based Collector**.
4. Click **Connect**.
5. Set the following values:
   - Name as `Proofpoint CASB`
   - Compression as `uncompressed`
   - Log Format as `JSON`
   - Vendor as `proofpoint`
   - Product as `casb`
6. Creating a new HTTP Log Collector will allow you to generate a unique token. Save it since it will be used later.
7. Click the 3 dots next to the newly created instance and copy the **API Url**. It will also be used later.

**On Proofpoint CASB side:**

 [Link to Proofpoint webhook docs](https://docs.public.analyze.proofpoint.com/admin/notification_policies_webhooks.htm)

<u>Guidelines:</u>
1. Navigate to **Integrations** >  **Notification Policies**. Click **New Notification**.
2. Select **For Rules** > **Create**.
3. Name the new policy as "Forward events to XSIAM".
4. Click **Add** in the Webhooks area.
5. From the dropdown, select **Generic Template**.
6. In the **URL** field paste the **API Url** from the last section.
7. In the **Method** field select **POST**.
8. In the **Headers** field do the following:
    a. Click **Add Row**.
    b. Add the value **Authorization** to the **Name** field of the first row. 
    c. In the **Value** field paste the unique token you created in the last section.
    d. Add the value **Content-Type** to the **Name** field of the second row. 
    e. In the **Value** field add the value **application/json**.
9. In the **Data** section use the given default format.
10. Click **Save**.