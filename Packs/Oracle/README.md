This pack includes XSIAM content.

## Collect Events from Vendor

In order to use the collector, you will need to perform the following steps:
 - [Configure the Broker VM](#broker-vm)
 - [Activate the Database Collector](#database-collector) 

### Broker VM
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/broker-vm/set-up-broker-vm/configure-your-broker-vm).\
You can configure the specific vendor and product for this instance.
1. Navigate to **Settings** -> **Configuration** -> **Data Broker** -> **Broker VMs**. 
2. Right-click the broker VM and select **Database Collector** -> **Activate**.
3. When configuring the Database Collector, set:
   - vendor as oracle
   - product as db

### Database Collector
You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/broker-vm/set-up-broker-vm/activate-the-database-collector#id1d9fc182-8324-4299-8cdd-10c0eeaa4afa).\
When configuring the `Database Connection` the `SQL Query` should look as follows:

```
SELECT to_char(EVENT_TIMESTAMP,'YYYY/MM/DD HH:MM:SS.mi') as DB_TIMESTAMP, UNIFIED_AUDIT_TRAIL.*
FROM UNIFIED_AUDIT_TRAIL
WHERE to_char(EVENT_TIMESTAMP,'YYYY/MM/DD HH:MM:SS.mi') > ?
ORDER BY  DB_TIMESTAMP DESC;
```
