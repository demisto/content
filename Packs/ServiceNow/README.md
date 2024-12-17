Cortex XSOAR interfaces with ServiceNow to help streamline security-related service management and IT operations. 

The data in ServiceNow tickets can be mirrored to Cortex XSOAR so that you can track the status and information in the task. 
You can also provide comments or attachments in Cortex XSOAR which will appear in ServiceNow. 


# What does this pack do?

- View, create, update, or delete a ServiceNow ticket directly from Cortex XSOAR and enrich it with Cortex XSOAR data.
- View, create, update, and delete records from any ServiceNow table.
- Query ServiceNow data with the ServiceNow query syntax.
- Enables users to fetch Events from ServiceNow platform into Cortex XSIAM.
- Log Normalization - XDM mapping for key event types

<~XSOAR>
As part of this pack, you will also get two out-of-the-box layouts so that you can visualize ServiceNow ticket information in Cortex XSOAR.


The Create ServiceNow Ticket playbook provides an example for how to use the Mirror ServiceNow Ticket playbook to mirror data and the ServiceNow Ticket State Polling sub-playbook to track when the ticket closes.
</~XSOAR>

<~XSIAM>

### Supported Event Types:

* Audit
* Syslog Transactions


### Configure ServiceNow Event Collector on XSIAM Tenant

1. Go to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for ServiceNow Event Collector
3. Click **Add instance**.
4. Insert the ServiceNow URL.
5. Insert your credentials (user name and password).
6. Scroll down to the **Collect** section.
7. Mark **Fetch Events** and select the desire event types to fetch (Audit and Syslog Transactions)


### For more information on ServiceNow platform

- [Visit ServiceNow website](https://www.servicenow.com/docs/)
- [Visit ServiceNow Transaction documentations](https://www.servicenow.com/docs/bundle/utah-platform-security/page/administer/time/reference/r_TransactionLogs.html)

</~XSIAM>